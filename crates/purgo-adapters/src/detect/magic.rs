use std::io::Cursor;

use purgo_domain::{Artifact, FileFormat, FormatDetector};
use zip::ZipArchive;

#[derive(Debug, Default, Clone, Copy)]
pub struct MagicFormatDetector;

impl MagicFormatDetector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

const OOXML_MARKER: &str = "[Content_Types].xml";

fn is_ooxml(bytes: &[u8]) -> bool {
    match ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive.file_names().any(|name| name == OOXML_MARKER),
        Err(_) => false,
    }
}

impl FormatDetector for MagicFormatDetector {
    fn detect(&self, artifact: &Artifact) -> FileFormat {
        let bytes = artifact.bytes();
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            FileFormat::Jpeg
        } else if bytes.starts_with(&PNG_SIGNATURE) {
            FileFormat::Png
        } else if bytes.starts_with(b"%PDF-") {
            FileFormat::Pdf
        } else if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            if is_ooxml(bytes) {
                FileFormat::Ooxml
            } else {
                FileFormat::Zip
            }
        } else {
            FileFormat::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn detect(bytes: &[u8]) -> FileFormat {
        MagicFormatDetector::new().detect(&Artifact::new(bytes.to_vec()))
    }

    fn zip_with(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in parts {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn recognises_known_signatures() {
        assert_eq!(detect(&[0xFF, 0xD8, 0xFF, 0xE0]), FileFormat::Jpeg);
        assert_eq!(
            detect(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00]),
            FileFormat::Png
        );
        assert_eq!(detect(b"%PDF-1.7\n"), FileFormat::Pdf);
    }

    #[test]
    fn plain_zip_without_content_types_is_zip() {
        let bytes = zip_with(&[("hello.txt", b"hi")]);
        assert_eq!(detect(&bytes), FileFormat::Zip);
    }

    #[test]
    fn zip_with_content_types_is_ooxml() {
        let bytes = zip_with(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", b"<w:document/>"),
        ]);
        assert_eq!(detect(&bytes), FileFormat::Ooxml);
    }

    #[test]
    fn truncated_zip_signature_is_plain_zip_not_ooxml() {
        assert_eq!(detect(&[0x50, 0x4B, 0x03, 0x04, 0x14]), FileFormat::Zip);
    }

    #[test]
    fn unknown_when_no_signature_matches() {
        assert_eq!(detect(b"just some text"), FileFormat::Unknown);
        assert_eq!(detect(&[]), FileFormat::Unknown);
    }
}
