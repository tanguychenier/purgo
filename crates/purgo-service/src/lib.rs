use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use purgo_domain::{Artifact, DisarmFile, DisarmReport, DisarmRequest, DomainError};

pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

pub const HEADER_FORMAT: HeaderName = HeaderName::from_static("x-purgo-format");

pub const HEADER_REMOVED_COUNT: HeaderName = HeaderName::from_static("x-purgo-removed-count");

pub const HEADER_ORIGINAL_SIZE: HeaderName = HeaderName::from_static("x-purgo-original-size");

pub const HEADER_SANITIZED_SIZE: HeaderName = HeaderName::from_static("x-purgo-sanitized-size");

pub const HEADER_MODIFIED: HeaderName = HeaderName::from_static("x-purgo-modified");

#[derive(Clone)]
pub struct AppState {
    disarm: Arc<dyn DisarmFile + Send + Sync>,
}

impl AppState {
    #[must_use]
    pub fn new(disarm: Arc<dyn DisarmFile + Send + Sync>) -> Self {
        Self { disarm }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/disarm",
            post(disarm).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn disarm(State(state): State<AppState>, body: Bytes) -> Response {
    let request = DisarmRequest::strict(Artifact::new(body.to_vec()));

    match state.disarm.execute(request) {
        Ok(receipt) => report_headers(&receipt.report, receipt.clean.into_bytes()),

        Err(err) => (status_for(&err), err.to_string()).into_response(),
    }
}

fn report_headers(report: &DisarmReport, clean: Vec<u8>) -> Response {
    let mut response = (StatusCode::OK, clean).into_response();
    let headers = response.headers_mut();
    headers.insert(HEADER_FORMAT, header_value(report.format.as_str()));
    headers.insert(
        HEADER_REMOVED_COUNT,
        header_value(&report.removed_count().to_string()),
    );
    headers.insert(
        HEADER_ORIGINAL_SIZE,
        header_value(&report.original_size.to_string()),
    );
    headers.insert(
        HEADER_SANITIZED_SIZE,
        header_value(&report.sanitized_size.to_string()),
    );
    headers.insert(
        HEADER_MODIFIED,
        header_value(if report.is_modified() {
            "true"
        } else {
            "false"
        }),
    );
    response
}

fn header_value(raw: &str) -> HeaderValue {
    HeaderValue::from_str(raw).unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[must_use]
pub fn status_for(err: &DomainError) -> StatusCode {
    match err {
        DomainError::UnsupportedFormat(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        DomainError::MalformedInput { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        DomainError::PolicyViolation(_) => StatusCode::UNPROCESSABLE_ENTITY,
        DomainError::SigningFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,

        _ => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purgo_domain::{
        CleanArtifact, DisarmReceipt, DisarmReport, FileFormat, RemovedItem, ThreatClass,
    };

    struct StubUseCase(Result<DisarmReceipt, DomainError>);
    impl DisarmFile for StubUseCase {
        fn execute(&self, _request: DisarmRequest) -> Result<DisarmReceipt, DomainError> {
            self.0.clone()
        }
    }

    fn receipt() -> DisarmReceipt {
        DisarmReceipt {
            clean: CleanArtifact::new(FileFormat::Jpeg, b"clean-bytes".to_vec()),
            report: DisarmReport {
                format: FileFormat::Jpeg,
                original_size: 42,
                sanitized_size: 11,
                removed: vec![RemovedItem::new(
                    "segment APP1",
                    ThreatClass::Metadata,
                    "EXIF",
                    20,
                )],
            },
        }
    }

    #[test]
    fn success_response_carries_clean_bytes_and_report_headers() {
        let response = report_headers(&receipt().report, b"clean-bytes".to_vec());
        assert_eq!(response.status(), StatusCode::OK);
        let h = response.headers();
        assert_eq!(h.get(HEADER_FORMAT).unwrap(), "jpeg");
        assert_eq!(h.get(HEADER_REMOVED_COUNT).unwrap(), "1");
        assert_eq!(h.get(HEADER_ORIGINAL_SIZE).unwrap(), "42");
        assert_eq!(h.get(HEADER_SANITIZED_SIZE).unwrap(), "11");
        assert_eq!(h.get(HEADER_MODIFIED).unwrap(), "true");
    }

    #[test]
    fn status_mapping_is_fail_closed() {
        assert_eq!(
            status_for(&DomainError::UnsupportedFormat(FileFormat::Unknown)),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status_for(&DomainError::MalformedInput {
                format: FileFormat::Jpeg,
                reason: "x".into(),
            }),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status_for(&DomainError::PolicyViolation("x".into())),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status_for(&DomainError::SigningFailed("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn state_only_depends_on_the_port() {
        let _state = AppState::new(Arc::new(StubUseCase(Ok(receipt()))));
    }
}
