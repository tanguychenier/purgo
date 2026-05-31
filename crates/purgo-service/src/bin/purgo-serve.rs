use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use purgo_adapters::{
    JpegDisarmer, MagicFormatDetector, OoxmlDisarmer, PdfDisarmer, PngDisarmer, ZipDisarmer,
};
use purgo_application::DisarmService;
use purgo_domain::{DisarmFile, Disarmer, FormatDetector};
use purgo_service::{router, AppState};

const BIND_ENV: &str = "PURGO_BIND";

const DEFAULT_BIND: &str = "127.0.0.1:9090";

#[tokio::main]
async fn main() -> ExitCode {
    match serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purgo-serve: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> Result<(), String> {
    let addr = bind_address()?;
    let app = router(AppState::new(build_service()));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind {addr}: {e}"))?;
    eprintln!("purgo-serve: listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

fn bind_address() -> Result<SocketAddr, String> {
    let raw = std::env::var(BIND_ENV).unwrap_or_else(|_| DEFAULT_BIND.to_string());
    raw.parse()
        .map_err(|e| format!("invalid {BIND_ENV}={raw:?}: {e}"))
}

fn build_service() -> Arc<dyn DisarmFile + Send + Sync> {
    let detector: Arc<dyn FormatDetector> = Arc::new(MagicFormatDetector::new());
    let disarmers: Vec<Arc<dyn Disarmer>> = vec![
        Arc::new(JpegDisarmer::new()),
        Arc::new(PngDisarmer::new()),
        Arc::new(PdfDisarmer::new()),
        Arc::new(OoxmlDisarmer::new()),
        Arc::new(ZipDisarmer::new()),
    ];
    Arc::new(DisarmService::new(detector, disarmers))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("purgo-serve: shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bind_is_loopback_9090() {
        let addr: SocketAddr = DEFAULT_BIND.parse().unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 9090);
    }

    #[test]
    fn build_service_yields_a_usable_use_case() {
        let _: Arc<dyn DisarmFile + Send + Sync> = build_service();
    }
}
