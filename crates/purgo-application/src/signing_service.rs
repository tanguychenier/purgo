use std::sync::Arc;

use purgo_domain::{DisarmAndSign, DisarmFile, DisarmRequest, DomainError, SignedReceipt, Signer};

pub struct SigningDisarmService {
    disarm: Arc<dyn DisarmFile + Send + Sync>,
    signer: Arc<dyn Signer>,
}

impl SigningDisarmService {
    #[must_use]
    pub fn new(disarm: Arc<dyn DisarmFile + Send + Sync>, signer: Arc<dyn Signer>) -> Self {
        Self { disarm, signer }
    }
}

impl DisarmAndSign for SigningDisarmService {
    fn execute_signed(&self, request: DisarmRequest) -> Result<SignedReceipt, DomainError> {
        let receipt = self.disarm.execute(request)?;

        let signature = self.signer.sign(receipt.clean.bytes())?;
        let public_key = self.signer.public_key();
        Ok(SignedReceipt {
            receipt,
            signature,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purgo_domain::{
        Artifact, CleanArtifact, DisarmReceipt, DisarmReport, FileFormat, PublicKey, Signature,
    };

    struct StubDisarm(Result<DisarmReceipt, DomainError>);
    impl DisarmFile for StubDisarm {
        fn execute(&self, _request: DisarmRequest) -> Result<DisarmReceipt, DomainError> {
            self.0.clone()
        }
    }

    struct StubSigner {
        signature: Vec<u8>,
        public_key: Vec<u8>,
    }
    impl Signer for StubSigner {
        fn sign(&self, bytes: &[u8]) -> Result<Signature, DomainError> {
            assert_eq!(bytes, b"clean-bytes");
            Ok(Signature::new(self.signature.clone()))
        }
        fn public_key(&self) -> PublicKey {
            PublicKey::new(self.public_key.clone())
        }
    }

    fn receipt() -> DisarmReceipt {
        DisarmReceipt {
            clean: CleanArtifact::new(FileFormat::Png, b"clean-bytes".to_vec()),
            report: DisarmReport {
                format: FileFormat::Png,
                original_size: 20,
                sanitized_size: 11,
                removed: vec![],
            },
        }
    }

    fn request() -> DisarmRequest {
        DisarmRequest::strict(Artifact::new(b"dirty".to_vec()))
    }

    #[test]
    fn signs_the_clean_bytes_and_exposes_the_public_key() {
        let svc = SigningDisarmService::new(
            Arc::new(StubDisarm(Ok(receipt()))),
            Arc::new(StubSigner {
                signature: vec![1, 2, 3],
                public_key: vec![9, 9],
            }),
        );

        let signed = svc
            .execute_signed(request())
            .expect("disarm + sign succeeds");
        assert_eq!(signed.receipt.clean.bytes(), b"clean-bytes");
        assert_eq!(signed.signature.bytes(), &[1, 2, 3]);
        assert_eq!(signed.public_key.bytes(), &[9, 9]);
    }

    #[test]
    fn does_not_sign_when_disarming_fails() {
        struct NeverSigner;
        impl Signer for NeverSigner {
            fn sign(&self, _bytes: &[u8]) -> Result<Signature, DomainError> {
                panic!("must not sign when disarming failed");
            }
            fn public_key(&self) -> PublicKey {
                panic!("must not expose a key when disarming failed");
            }
        }

        let svc = SigningDisarmService::new(
            Arc::new(StubDisarm(Err(DomainError::UnsupportedFormat(
                FileFormat::Unknown,
            )))),
            Arc::new(NeverSigner),
        );

        let err = svc.execute_signed(request()).unwrap_err();
        assert_eq!(err, DomainError::UnsupportedFormat(FileFormat::Unknown));
    }

    #[test]
    fn propagates_a_signing_failure() {
        struct FailingSigner;
        impl Signer for FailingSigner {
            fn sign(&self, _bytes: &[u8]) -> Result<Signature, DomainError> {
                Err(DomainError::SigningFailed("bad key".into()))
            }
            fn public_key(&self) -> PublicKey {
                PublicKey::new(vec![])
            }
        }

        let svc =
            SigningDisarmService::new(Arc::new(StubDisarm(Ok(receipt()))), Arc::new(FailingSigner));

        let err = svc.execute_signed(request()).unwrap_err();
        assert!(matches!(err, DomainError::SigningFailed(_)));
    }
}
