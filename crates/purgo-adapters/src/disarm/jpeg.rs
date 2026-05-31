use purgo_domain::{
    Artifact, DisarmOutput, Disarmer, DomainError, FileFormat, Policy, RemovedItem, ThreatClass,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct JpegDisarmer;

impl JpegDisarmer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOS: u8 = 0xDA;
const TEM: u8 = 0x01;
const APP0: u8 = 0xE0;
const APP15: u8 = 0xEF;
const COM: u8 = 0xFE;

fn malformed(reason: impl Into<String>) -> DomainError {
    DomainError::MalformedInput {
        format: FileFormat::Jpeg,
        reason: reason.into(),
    }
}

fn is_standalone(marker: u8) -> bool {
    matches!(marker, 0xD0..=0xD7 | SOI | EOI | TEM)
}

fn scan_data_end(data: &[u8], from: usize) -> usize {
    let mut k = from;
    while k < data.len() {
        if data[k] != 0xFF {
            k += 1;
            continue;
        }

        let mut m = k;
        while m < data.len() && data[m] == 0xFF {
            m += 1;
        }
        if m >= data.len() {
            return k;
        }
        let next = data[m];

        if next == 0x00 || (0xD0..=0xD7).contains(&next) {
            k = m + 1;
            continue;
        }

        return k;
    }
    data.len()
}

impl Disarmer for JpegDisarmer {
    fn format(&self) -> FileFormat {
        FileFormat::Jpeg
    }

    fn disarm(&self, artifact: &Artifact, policy: &Policy) -> Result<DisarmOutput, DomainError> {
        let data = artifact.bytes();
        if data.len() < 2 || data[0] != 0xFF || data[1] != SOI {
            return Err(malformed("missing SOI marker"));
        }

        let mut out: Vec<u8> = Vec::with_capacity(data.len());
        let mut removed: Vec<RemovedItem> = Vec::new();
        out.extend_from_slice(&[0xFF, SOI]);

        let mut i = 2usize;
        let mut seen_scan = false;
        loop {
            if i >= data.len() {
                if seen_scan {
                    break;
                }
                return Err(malformed("truncated before start of scan"));
            }
            if data[i] != 0xFF {
                return Err(malformed("expected a marker"));
            }

            let mut j = i;
            while j < data.len() && data[j] == 0xFF {
                j += 1;
            }
            if j >= data.len() {
                return Err(malformed("dangling marker prefix"));
            }
            let marker = data[j];
            let after_marker = j + 1;

            if marker == EOI {
                out.push(0xFF);
                out.push(EOI);
                break;
            }
            if marker == SOS {
                if after_marker + 2 > data.len() {
                    return Err(malformed("truncated scan header length"));
                }
                let len = u16::from_be_bytes([data[after_marker], data[after_marker + 1]]) as usize;
                if len < 2 {
                    return Err(malformed("invalid scan header length"));
                }
                let header_end = after_marker + len;
                if header_end > data.len() {
                    return Err(malformed("scan header runs past end of file"));
                }
                let data_end = scan_data_end(data, header_end);
                out.push(0xFF);
                out.push(SOS);
                out.extend_from_slice(&data[after_marker..data_end]);
                i = data_end;
                seen_scan = true;
                continue;
            }
            if is_standalone(marker) {
                out.push(0xFF);
                out.push(marker);
                i = after_marker;
                continue;
            }

            if after_marker + 2 > data.len() {
                return Err(malformed("truncated segment length"));
            }
            let len = u16::from_be_bytes([data[after_marker], data[after_marker + 1]]) as usize;
            if len < 2 {
                return Err(malformed("invalid segment length"));
            }
            let seg_end = after_marker + len;
            if seg_end > data.len() {
                return Err(malformed("segment runs past end of file"));
            }

            let is_app = (APP0..=APP15).contains(&marker);
            let is_com = marker == COM;
            let keep_this_app = marker == APP0 && policy.keep_jfif;
            let drop_it = policy.strip_metadata && (is_com || (is_app && !keep_this_app));

            if drop_it {
                let (location, detail) = if is_com {
                    ("segment COM".to_string(), "comment segment".to_string())
                } else {
                    let n = marker - APP0;
                    (
                        format!("segment APP{n}"),
                        format!("application segment APP{n} (EXIF/XMP/ICC/thumbnail)"),
                    )
                };

                removed.push(RemovedItem::new(
                    location,
                    ThreatClass::Metadata,
                    detail,
                    len + 2,
                ));
            } else {
                out.push(0xFF);
                out.push(marker);
                out.extend_from_slice(&data[after_marker..seg_end]);
            }
            i = seg_end;
        }

        Ok(DisarmOutput::new(out, removed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: Vec<u8>, policy: Policy) -> Result<DisarmOutput, DomainError> {
        JpegDisarmer::new().disarm(&Artifact::new(bytes), &policy)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn sample() -> Vec<u8> {
        let mut v = vec![0xFF, SOI];

        let exif = b"EXIFDATA";
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(exif);

        let jfif = b"JFIF\x00";
        v.extend_from_slice(&[0xFF, APP0]);
        v.extend_from_slice(&((jfif.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(jfif);

        v.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x12, 0x34]);

        v.extend_from_slice(&[0xFF, SOS, 0x00, 0x02, 0xAA, 0xBB, 0xFF, EOI]);
        v
    }

    #[test]
    fn strips_app1_keeps_jfif_and_image_data() {
        let out = run(sample(), Policy::strict()).unwrap();
        assert!(!contains(&out.bytes, b"EXIFDATA"), "EXIF must be gone");
        assert!(contains(&out.bytes, b"JFIF"), "JFIF (APP0) must be kept");
        assert!(contains(&out.bytes, &[0x12, 0x34]), "DQT must be kept");
        assert_eq!(&out.bytes[out.bytes.len() - 2..], &[0xFF, EOI]);

        assert_eq!(out.removed.len(), 1);
        assert_eq!(out.removed[0].class, ThreatClass::Metadata);
        assert!(out.removed[0].location.contains("APP1"));

        assert_eq!(out.removed[0].bytes_removed, 12);
    }

    #[test]
    fn rejects_input_without_soi() {
        let err = run(vec![0x00, 0x01, 0x02], Policy::strict()).unwrap_err();
        assert!(matches!(err, DomainError::MalformedInput { .. }));
    }

    #[test]
    fn truncates_payload_appended_after_eoi() {
        let mut v = sample();
        v.extend_from_slice(b"APPENDED-EVIL-PAYLOAD");
        let out = run(v, Policy::strict()).unwrap();

        assert!(
            !contains(&out.bytes, b"APPENDED-EVIL-PAYLOAD"),
            "bytes after EOI must be dropped, not copied through"
        );
        assert_eq!(
            &out.bytes[out.bytes.len() - 2..],
            &[0xFF, EOI],
            "output must end exactly at EOI"
        );
    }

    fn progressive_with_interleaved_app1() -> Vec<u8> {
        let mut v = vec![0xFF, SOI];

        v.extend_from_slice(&[0xFF, SOS, 0x00, 0x02]);
        v.extend_from_slice(&[0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD0, 0x33]);

        let exif = b"Exif\x00\x00BETWEEN-SCANS-SECRET";
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(exif);

        v.extend_from_slice(&[0xFF, SOS, 0x00, 0x02, 0x44, 0x55]);
        v.extend_from_slice(&[0xFF, EOI]);
        v
    }

    #[test]
    fn strips_app1_interleaved_between_progressive_scans() {
        let out = run(progressive_with_interleaved_app1(), Policy::strict()).unwrap();

        assert!(
            !contains(&out.bytes, b"BETWEEN-SCANS-SECRET"),
            "an APPn segment between scans must still be stripped"
        );

        assert!(contains(
            &out.bytes,
            &[0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD0, 0x33]
        ));
        assert!(contains(&out.bytes, &[0x44, 0x55]));
        assert_eq!(&out.bytes[out.bytes.len() - 2..], &[0xFF, EOI]);

        assert_eq!(out.removed.len(), 1);
        assert!(out.removed[0].location.contains("APP1"));
    }
}
