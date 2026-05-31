use std::cell::RefCell;
use std::collections::BTreeMap;

use purgo_filters::wire::{encode_result, FLAG_STRIP_METADATA, FORMAT_PNG};
use purgo_filters::{disarm_png, FilterError, PngOptions};

thread_local! {
    static BUFFERS: RefCell<BTreeMap<u32, Vec<u8>>> = const { RefCell::new(BTreeMap::new()) };
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn alloc(len: u32) -> u32 {
    let mut buffer = vec![0u8; len as usize];
    let ptr = buffer.as_mut_ptr() as u32;
    BUFFERS.with(|buffers| {
        buffers.borrow_mut().insert(ptr, buffer);
    });
    ptr
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn dealloc(ptr: u32, _len: u32) {
    BUFFERS.with(|buffers| {
        buffers.borrow_mut().remove(&ptr);
    });
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn disarm(ptr: u32, len: u32, format: u32, options: u32) -> u64 {
    let input = BUFFERS.with(|buffers| {
        buffers
            .borrow()
            .get(&ptr)
            .map(|buf| buf[..(len as usize).min(buf.len())].to_vec())
    });

    let result = match input {
        Some(input) => run(format, &input, options),

        None => Err(FilterError::Malformed("unknown input buffer")),
    };

    let encoded = encode_result(&result);
    let result_len = encoded.len() as u32;
    let result_ptr = alloc(result_len);
    BUFFERS.with(|buffers| {
        if let Some(slot) = buffers.borrow_mut().get_mut(&result_ptr) {
            slot.copy_from_slice(&encoded);
        }
    });
    (u64::from(result_ptr) << 32) | u64::from(result_len)
}

fn run(
    format: u32,
    input: &[u8],
    options: u32,
) -> Result<(Vec<u8>, Vec<purgo_filters::RemovedChunk>), FilterError> {
    match format {
        FORMAT_PNG => disarm_png(
            input,
            PngOptions {
                strip_metadata: options & FLAG_STRIP_METADATA != 0,
            },
        ),
        _ => Err(FilterError::Malformed("unsupported sandbox format")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purgo_filters::wire::{decode_result, DecodedResult};

    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    fn png_with_text() -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        let mut push = |kind: &[u8; 4], data: &[u8]| {
            v.extend_from_slice(&(data.len() as u32).to_be_bytes());
            v.extend_from_slice(kind);
            v.extend_from_slice(data);
            v.extend_from_slice(&[0, 0, 0, 0]);
        };
        push(b"IHDR", &[0, 0, 0, 0]);
        push(b"tEXt", b"secret");
        push(b"IEND", &[]);
        v
    }

    #[test]
    fn abi_round_trip_strips_text_chunk() {
        let input = png_with_text();
        let ptr = alloc(input.len() as u32);
        BUFFERS.with(|b| {
            b.borrow_mut()
                .get_mut(&ptr)
                .unwrap()
                .copy_from_slice(&input);
        });

        let packed = disarm(ptr, input.len() as u32, FORMAT_PNG, FLAG_STRIP_METADATA);
        let res_ptr = (packed >> 32) as u32;
        let res_len = (packed & 0xFFFF_FFFF) as usize;

        let encoded = BUFFERS.with(|b| b.borrow().get(&res_ptr).unwrap()[..res_len].to_vec());
        match decode_result(&encoded).unwrap() {
            DecodedResult::Ok { bytes, removed } => {
                assert!(bytes.starts_with(&SIGNATURE));
                assert_eq!(removed.len(), 1);
                assert_eq!(removed[0].name, "tEXt");
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        dealloc(ptr, input.len() as u32);
        dealloc(res_ptr, res_len as u32);
    }

    #[test]
    fn unknown_format_is_fail_closed() {
        let ptr = alloc(4);
        let packed = disarm(ptr, 4, 0xDEAD, 0);
        let res_ptr = (packed >> 32) as u32;
        let res_len = (packed & 0xFFFF_FFFF) as usize;
        let encoded = BUFFERS.with(|b| b.borrow().get(&res_ptr).unwrap()[..res_len].to_vec());
        assert!(matches!(
            decode_result(&encoded).unwrap(),
            DecodedResult::Malformed(_)
        ));
    }
}
