use std::sync::Arc;

use purgo_adapters::{JpegDisarmer, MagicFormatDetector, PngDisarmer};
use purgo_application::DisarmService;
use purgo_domain::{
    Artifact, DisarmFile, DisarmRequest, Disarmer, DomainError, FileFormat, FormatDetector,
};

fn service() -> DisarmService {
    let detector: Arc<dyn FormatDetector> = Arc::new(MagicFormatDetector::new());
    let disarmers: Vec<Arc<dyn Disarmer>> =
        vec![Arc::new(JpegDisarmer::new()), Arc::new(PngDisarmer::new())];
    DisarmService::new(detector, disarmers)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn png_with_text_chunk() -> Vec<u8> {
    fn push_chunk(v: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(kind);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0, 0, 0, 0]);
    }
    let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    push_chunk(&mut v, b"IHDR", &[0, 0, 0, 0]);
    push_chunk(&mut v, b"tEXt", b"Comment\x00secret");
    push_chunk(&mut v, b"IDAT", &[1, 2, 3]);
    push_chunk(&mut v, b"IEND", &[]);
    v
}

#[test]
fn detects_png_and_strips_text_chunk_end_to_end() {
    let receipt = service()
        .execute(DisarmRequest::strict(Artifact::new(png_with_text_chunk())))
        .expect("png supported");

    assert_eq!(receipt.clean.format(), FileFormat::Png);
    assert_eq!(receipt.report.removed_count(), 1);
    assert!(!contains(receipt.clean.bytes(), b"secret"));
    assert!(contains(receipt.clean.bytes(), b"IDAT"));
}

#[test]
fn unknown_format_is_rejected_end_to_end() {
    let err = service()
        .execute(DisarmRequest::strict(Artifact::new(
            b"not a known file".to_vec(),
        )))
        .unwrap_err();
    assert_eq!(err, DomainError::UnsupportedFormat(FileFormat::Unknown));
}
