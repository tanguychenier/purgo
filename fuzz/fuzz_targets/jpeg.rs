#![no_main]







use libfuzzer_sys::fuzz_target;
use purgo_adapters::JpegDisarmer;
use purgo_domain::{Artifact, Disarmer, DomainError, Policy};

fuzz_target!(|data: &[u8]| {
    let artifact = Artifact::new(data.to_vec());
    match JpegDisarmer::new().disarm(&artifact, &Policy::strict()) {

        Ok(_) | Err(DomainError::MalformedInput { .. }) => {}


        Err(other) => panic!("unexpected non-malformed error from JpegDisarmer: {other:?}"),
    }
});
