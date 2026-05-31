use crate::error::DomainError;
use crate::model::artifact::Artifact;
use crate::model::format::FileFormat;
use crate::model::policy::Policy;
use crate::model::report::RemovedItem;
use crate::model::signature::{PublicKey, Signature};

pub trait FormatDetector: Send + Sync {
    fn detect(&self, artifact: &Artifact) -> FileFormat;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisarmOutput {
    pub bytes: Vec<u8>,

    pub removed: Vec<RemovedItem>,
}

impl DisarmOutput {
    #[must_use]
    pub fn new(bytes: Vec<u8>, removed: Vec<RemovedItem>) -> Self {
        Self { bytes, removed }
    }
}

pub trait Disarmer: Send + Sync {
    fn format(&self) -> FileFormat;

    fn disarm(&self, artifact: &Artifact, policy: &Policy) -> Result<DisarmOutput, DomainError>;
}

pub trait Sandbox: Send + Sync {
    fn run_disarm(
        &self,
        format: FileFormat,
        input: &[u8],
        policy: &Policy,
    ) -> Result<DisarmOutput, DomainError>;
}

pub trait Signer: Send + Sync {
    fn sign(&self, bytes: &[u8]) -> Result<Signature, DomainError>;

    fn public_key(&self) -> PublicKey;
}
