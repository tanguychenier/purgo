use std::fmt;
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use purgo_domain::{DomainError, PublicKey, Signature, Signer};
use rand_core::OsRng;

pub struct Ed25519Signer {
    key: SigningKey,
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("verifying_key", &self.verifying_key())
            .field("key", &"<redacted>")
            .finish()
    }
}

fn signing_failed(reason: impl Into<String>) -> DomainError {
    DomainError::SigningFailed(reason.into())
}

impl Ed25519Signer {
    pub const SEED_LEN: usize = SECRET_KEY_LENGTH;

    #[must_use]
    pub fn from_seed(seed: [u8; Self::SEED_LEN]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_seed_file(path: &Path) -> Result<Self, DomainError> {
        let raw = std::fs::read(path)
            .map_err(|e| signing_failed(format!("cannot read key file {}: {e}", path.display())))?;
        let seed: [u8; Self::SEED_LEN] = raw.as_slice().try_into().map_err(|_| {
            signing_failed(format!(
                "key file {} must be exactly {} bytes, got {}",
                path.display(),
                Self::SEED_LEN,
                raw.len()
            ))
        })?;
        Ok(Self::from_seed(seed))
    }

    #[must_use]
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    #[must_use]
    pub fn seed(&self) -> [u8; Self::SEED_LEN] {
        self.key.to_bytes()
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, bytes: &[u8]) -> Result<Signature, DomainError> {
        Ok(Signature::new(self.key.sign(bytes).to_bytes().to_vec()))
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::new(self.verifying_key().to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature as DalekSignature, Verifier};

    fn verify(public_key: &PublicKey, signature: &Signature, message: &[u8]) -> bool {
        let Ok(vk_bytes): Result<[u8; 32], _> = public_key.bytes().try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = signature.bytes().try_into() else {
            return false;
        };
        vk.verify(message, &DalekSignature::from_bytes(&sig_bytes))
            .is_ok()
    }

    #[test]
    fn signs_and_the_signature_verifies() {
        let signer = Ed25519Signer::generate();
        let message = b"clean-output-bytes";

        let sig = signer.sign(message).unwrap();
        assert_eq!(sig.bytes().len(), 64, "ed25519 signatures are 64 bytes");
        assert!(verify(&signer.public_key(), &sig, message));
    }

    #[test]
    fn a_signature_over_modified_bytes_fails_verification() {
        let signer = Ed25519Signer::generate();
        let sig = signer.sign(b"the original message").unwrap();

        assert!(
            !verify(&signer.public_key(), &sig, b"the TAMPERED message"),
            "verification must reject tampered bytes"
        );
    }

    #[test]
    fn a_seed_yields_a_deterministic_key_and_signature() {
        let seed = [7u8; Ed25519Signer::SEED_LEN];
        let a = Ed25519Signer::from_seed(seed);
        let b = Ed25519Signer::from_seed(seed);

        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.sign(b"x").unwrap(), b.sign(b"x").unwrap());
    }

    #[test]
    fn generate_then_reload_seed_reproduces_the_same_signer() {
        let signer = Ed25519Signer::generate();
        let reloaded = Ed25519Signer::from_seed(signer.seed());
        assert_eq!(signer.public_key(), reloaded.public_key());
    }

    #[test]
    fn rejects_a_key_file_of_the_wrong_length() {
        let dir = std::env::temp_dir().join(format!("purgo-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("short.key");
        std::fs::write(&path, [0u8; 8]).unwrap();

        let err = Ed25519Signer::from_seed_file(&path).unwrap_err();
        assert!(matches!(err, DomainError::SigningFailed(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loads_a_valid_seed_file_and_signs() {
        let dir = std::env::temp_dir().join(format!("purgo-key-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seed.key");
        std::fs::write(&path, [3u8; Ed25519Signer::SEED_LEN]).unwrap();

        let signer = Ed25519Signer::from_seed_file(&path).unwrap();
        let sig = signer.sign(b"payload").unwrap();
        assert!(verify(&signer.public_key(), &sig, b"payload"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
