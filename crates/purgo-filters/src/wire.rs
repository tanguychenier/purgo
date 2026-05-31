use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{FilterError, RemovedChunk};

const STATUS_OK: u8 = 0;

const STATUS_MALFORMED: u8 = 1;

pub const FORMAT_PNG: u32 = 0;

pub const FLAG_STRIP_METADATA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedResult {
    Ok {
        bytes: Vec<u8>,

        removed: Vec<RemovedChunk>,
    },

    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Truncated,

    LengthOutOfRange,

    UnknownStatus(u8),

    InvalidUtf8,
}

#[must_use]
pub fn encode_result(result: &Result<(Vec<u8>, Vec<RemovedChunk>), FilterError>) -> Vec<u8> {
    let mut buf = Vec::new();
    match result {
        Ok((bytes, removed)) => {
            buf.push(STATUS_OK);
            put_bytes(&mut buf, bytes);
            put_u32(&mut buf, removed.len() as u32);
            for chunk in removed {
                put_bytes(&mut buf, chunk.name.as_bytes());
                put_u32(&mut buf, chunk.bytes_removed as u32);
            }
        }
        Err(FilterError::Malformed(reason)) => {
            buf.push(STATUS_MALFORMED);
            put_bytes(&mut buf, reason.as_bytes());
        }
    }
    buf
}

pub fn decode_result(buf: &[u8]) -> Result<DecodedResult, WireError> {
    let mut r = Reader::new(buf);
    let status = r.u8()?;
    match status {
        STATUS_OK => {
            let bytes = r.bytes()?.to_vec();
            let count = r.u32()? as usize;
            let mut removed = Vec::with_capacity(count.min(buf.len()));
            for _ in 0..count {
                let name = r.string()?;
                let bytes_removed = r.u32()? as usize;
                removed.push(RemovedChunk {
                    name,
                    bytes_removed,
                });
            }
            Ok(DecodedResult::Ok { bytes, removed })
        }
        STATUS_MALFORMED => Ok(DecodedResult::Malformed(r.string()?)),
        other => Err(WireError::UnknownStatus(other)),
    }
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::LengthOutOfRange)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, WireError> {
        let slice = self.bytes()?;
        core::str::from_utf8(slice)
            .map(ToString::to_string)
            .map_err(|_| WireError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trips_ok_result() {
        let removed = vec![
            RemovedChunk {
                name: "tEXt".to_string(),
                bytes_removed: 42,
            },
            RemovedChunk {
                name: "eXIf".to_string(),
                bytes_removed: 7,
            },
        ];
        let original = Ok((vec![1u8, 2, 3, 4], removed.clone()));
        let buf = encode_result(&original);
        let decoded = decode_result(&buf).unwrap();
        assert_eq!(
            decoded,
            DecodedResult::Ok {
                bytes: vec![1, 2, 3, 4],
                removed,
            }
        );
    }

    #[test]
    fn round_trips_malformed_result() {
        let original = Err(FilterError::Malformed("missing PNG signature"));
        let buf = encode_result(&original);
        let decoded = decode_result(&buf).unwrap();
        assert_eq!(
            decoded,
            DecodedResult::Malformed("missing PNG signature".to_string())
        );
    }

    #[test]
    fn rejects_truncated_buffer_without_panicking() {
        let full = encode_result(&Ok((vec![9u8; 10], vec![])));

        for cut in 0..full.len() {
            let err = decode_result(&full[..cut]);
            assert!(err.is_err() || cut == full.len());
        }
    }

    #[test]
    fn rejects_unknown_status() {
        let err = decode_result(&[0xFF]).unwrap_err();
        assert_eq!(err, WireError::UnknownStatus(0xFF));
    }
}
