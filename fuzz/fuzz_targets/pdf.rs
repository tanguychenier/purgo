#![no_main]








use libfuzzer_sys::fuzz_target;
use purgo_adapters::PdfDisarmer;
use purgo_domain::{Artifact, Disarmer, DomainError, Policy};

fuzz_target!(|data: &[u8]| {
    let artifact = Artifact::new(data.to_vec());
    match PdfDisarmer::new().disarm(&artifact, &Policy::strict()) {

        Ok(_) | Err(DomainError::MalformedInput { .. }) => {}


        Err(other) => panic!("unexpected non-malformed error from PdfDisarmer: {other:?}"),
    }
});
