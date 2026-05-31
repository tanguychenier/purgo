use alloc::string::String;
use alloc::vec::Vec;

use crate::FilterError;

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

const KEEP: [&[u8; 4]; 9] = [
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"pHYs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PngOptions {
    pub strip_metadata: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedChunk {
    pub name: String,

    pub bytes_removed: usize,
}

pub fn disarm_png(
    data: &[u8],
    options: PngOptions,
) -> Result<(Vec<u8>, Vec<RemovedChunk>), FilterError> {
    if !data.starts_with(&SIGNATURE) {
        return Err(FilterError::Malformed("missing PNG signature"));
    }

    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    out.extend_from_slice(&SIGNATURE);
    let mut removed: Vec<RemovedChunk> = Vec::new();

    let mut i = SIGNATURE.len();
    loop {
        if i == data.len() {
            break;
        }

        if i + 8 > data.len() {
            return Err(FilterError::Malformed("truncated chunk header"));
        }
        let length = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let type_start = i + 4;
        let kind = &data[type_start..type_start + 4];

        let crc_end = type_start
            .checked_add(4)
            .and_then(|n| n.checked_add(length))
            .and_then(|n| n.checked_add(4));
        let crc_end = match crc_end {
            Some(end) if end <= data.len() => end,
            _ => return Err(FilterError::Malformed("chunk runs past end of file")),
        };
        let whole = &data[i..crc_end];
        let is_iend = kind == b"IEND";

        let keep = !options.strip_metadata || KEEP.iter().any(|allowed| kind == allowed.as_slice());
        if keep {
            out.extend_from_slice(whole);
        } else {
            removed.push(RemovedChunk {
                name: String::from_utf8_lossy(kind).into_owned(),
                bytes_removed: whole.len(),
            });
        }

        i = crc_end;
        if is_iend {
            break;
        }
    }

    Ok((out, removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_chunk(v: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(kind);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0, 0, 0, 0]);
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn sample() -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        push_chunk(&mut v, b"IHDR", &[0, 0, 0, 0]);
        push_chunk(&mut v, b"tEXt", b"Comment\x00secret-payload");
        push_chunk(&mut v, b"IDAT", &[1, 2, 3]);
        push_chunk(&mut v, b"IEND", &[]);
        v
    }

    #[test]
    fn drops_text_chunk_and_keeps_critical_chunks() {
        let (bytes, removed) = disarm_png(
            &sample(),
            PngOptions {
                strip_metadata: true,
            },
        )
        .unwrap();
        assert!(!contains(&bytes, b"secret-payload"));
        assert!(contains(&bytes, b"IHDR"));
        assert!(contains(&bytes, b"IDAT"));
        assert!(contains(&bytes, b"IEND"));
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "tEXt");
    }

    #[test]
    fn keeps_everything_when_not_stripping() {
        let (_, removed) = disarm_png(
            &sample(),
            PngOptions {
                strip_metadata: false,
            },
        )
        .unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn rejects_input_without_signature() {
        let err = disarm_png(
            &[0u8; 8],
            PngOptions {
                strip_metadata: true,
            },
        )
        .unwrap_err();
        assert_eq!(err, FilterError::Malformed("missing PNG signature"));
    }

    #[test]
    fn rejects_truncated_chunk_header() {
        let mut v = SIGNATURE.to_vec();
        v.extend_from_slice(&[0, 0, 0]);
        let err = disarm_png(
            &v,
            PngOptions {
                strip_metadata: true,
            },
        )
        .unwrap_err();
        assert_eq!(err, FilterError::Malformed("truncated chunk header"));
    }

    #[test]
    fn rejects_chunk_length_past_end() {
        let mut v = SIGNATURE.to_vec();

        v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        v.extend_from_slice(b"tEXt");
        let err = disarm_png(
            &v,
            PngOptions {
                strip_metadata: true,
            },
        )
        .unwrap_err();
        assert_eq!(err, FilterError::Malformed("chunk runs past end of file"));
    }
}
