use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use purgo_adapters::{
    JpegDisarmer, MagicFormatDetector, OoxmlDisarmer, PdfDisarmer, PngDisarmer, ZipDisarmer,
};
use purgo_application::DisarmService;
use purgo_domain::{DisarmFile, Disarmer, FormatDetector};
use purgo_service::{
    router, AppState, HEADER_FORMAT, HEADER_MODIFIED, HEADER_ORIGINAL_SIZE, HEADER_REMOVED_COUNT,
    HEADER_SANITIZED_SIZE, MAX_BODY_BYTES,
};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn app() -> axum::Router {
    let detector: Arc<dyn FormatDetector> = Arc::new(MagicFormatDetector::new());
    let disarmers: Vec<Arc<dyn Disarmer>> = vec![
        Arc::new(JpegDisarmer::new()),
        Arc::new(PngDisarmer::new()),
        Arc::new(PdfDisarmer::new()),
        Arc::new(OoxmlDisarmer::new()),
        Arc::new(ZipDisarmer::new()),
    ];
    let use_case: Arc<dyn DisarmFile + Send + Sync> =
        Arc::new(DisarmService::new(detector, disarmers));
    router(AppState::new(use_case))
}

fn sample_jpeg_with_exif() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    let payload = b"Exif\x00\x00HIDDEN-METADATA";
    v.extend_from_slice(&[0xFF, 0xE1]);
    v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x12, 0x34]);
    v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0xAA, 0xBB, 0xFF, 0xD9]);
    v
}

#[tokio::test]
async fn health_returns_200() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn disarm_strips_exif_and_reports_in_headers() {
    let input = sample_jpeg_with_exif();
    assert!(contains(&input, b"HIDDEN-METADATA"), "fixture sanity");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disarm")
                .body(Body::from(input.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers().clone();
    assert_eq!(headers.get(HEADER_FORMAT).unwrap(), "jpeg");
    assert_eq!(
        headers.get(HEADER_REMOVED_COUNT).unwrap(),
        "1",
        "the single APP1/EXIF segment must be reported as removed"
    );
    assert_eq!(headers.get(HEADER_MODIFIED).unwrap(), "true");
    assert_eq!(
        headers.get(HEADER_ORIGINAL_SIZE).unwrap(),
        input.len().to_string().as_str()
    );
    assert!(headers.contains_key(HEADER_SANITIZED_SIZE));

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[0..2], &[0xFF, 0xD8], "SOI preserved");
    assert_eq!(&body[body.len() - 2..], &[0xFF, 0xD9], "EOI preserved");
    assert!(
        !contains(&body, b"HIDDEN-METADATA"),
        "EXIF must be gone from the response body"
    );
    assert_eq!(
        headers.get(HEADER_SANITIZED_SIZE).unwrap(),
        body.len().to_string().as_str(),
        "sanitized-size header must match the body length"
    );
}

#[tokio::test]
async fn disarm_rejects_unsupported_input_fail_closed() {
    let garbage = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disarm")
                .body(Body::from(garbage.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !contains(&body, &garbage),
        "rejected input must not be returned in the response body"
    );
}

#[tokio::test]
async fn disarm_rejects_malformed_jpeg_fail_closed() {
    let malformed = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00];
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disarm")
                .body(Body::from(malformed))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn disarm_rejects_oversized_body_with_413() {
    let oversized = vec![0u8; MAX_BODY_BYTES + 1];
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disarm")
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

fn sample_pdf_with_active_content() -> Vec<u8> {
    use lopdf::{dictionary, Document, Object, Stream};

    let mut doc = Document::with_version("1.5");
    let content_id = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf (PurgoHttpPdfBody) Tj ET".to_vec(),
    ));
    let pages_id = doc.new_object_id();
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        }),
    );
    let js_id = doc.add_object(dictionary! {
        "Type" => "Action", "S" => "JavaScript", "JS" => "app.alert('pwn');",
    });
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog", "Pages" => pages_id, "OpenAction" => js_id,
    });
    doc.trailer.set("Root", catalog_id);
    let mut buf = Vec::new();
    doc.save_to(&mut buf).expect("fixture pdf must serialise");
    buf
}

#[tokio::test]
async fn disarm_pdf_strips_javascript_over_http() {
    let input = sample_pdf_with_active_content();
    assert!(contains(&input, b"app.alert"), "fixture sanity");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disarm")
                .body(Body::from(input))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(headers.get(HEADER_FORMAT).unwrap(), "pdf");
    assert_eq!(headers.get(HEADER_MODIFIED).unwrap(), "true");

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.starts_with(b"%PDF-"), "body is a rebuilt PDF");
    assert!(contains(&body, b"PurgoHttpPdfBody"), "page text preserved");
    assert!(!contains(&body, b"OpenAction"), "OpenAction stripped");
    assert!(!contains(&body, b"app.alert"), "JavaScript stripped");
}

fn sample_docx_with_macro() -> Vec<u8> {
    use std::io::{Cursor, Write as _};
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut part = |name: &str, data: &[u8]| {
        zip.start_file(name, opts).unwrap();
        zip.write_all(data).unwrap();
    };
    part(
        "[Content_Types].xml",
        br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
    );
    part(
        "_rels/.rels",
        br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#,
    );
    part(
        "word/document.xml",
        b"<w:document>PurgoHttpDocxBody</w:document>",
    );
    part("word/vbaProject.bin", b"HTTP-MACRO-EVIL-CODE");
    part(
        "word/_rels/document.xml.rels",
        br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>"#,
    );
    zip.finish().unwrap().into_inner()
}

#[tokio::test]
async fn disarm_docx_strips_macro_over_http() {
    let input = sample_docx_with_macro();

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disarm")
                .body(Body::from(input))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(headers.get(HEADER_FORMAT).unwrap(), "ooxml");
    assert_eq!(headers.get(HEADER_MODIFIED).unwrap(), "true");

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.starts_with(&[0x50, 0x4B]), "body is a ZIP package");
    let mut rebuilt = zip::ZipArchive::new(std::io::Cursor::new(body.to_vec()))
        .expect("response body is a valid ZIP");
    let names: Vec<String> = (0..rebuilt.len())
        .map(|i| rebuilt.by_index(i).unwrap().name().to_owned())
        .collect();
    assert!(
        names.iter().any(|n| n == "word/document.xml"),
        "the document part survives, got {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("vbaProject")),
        "the VBA macro project must be removed, got {names:?}"
    );
}

#[tokio::test]
async fn disarm_rejects_bare_zip_fail_closed() {
    use std::io::Write as _;
    use zip::{write::SimpleFileOptions, ZipWriter};

    let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("notes.txt", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"BARE-ZIP-PAYLOAD").unwrap();
    let bare_zip = zip.finish().unwrap().into_inner();

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disarm")
                .body(Body::from(bare_zip))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !contains(&body, b"BARE-ZIP-PAYLOAD"),
        "a refused bare ZIP must not be echoed back to the caller"
    );
}
