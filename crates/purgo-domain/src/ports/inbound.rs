use crate::error::DomainError;
use crate::model::artifact::Artifact;
use crate::model::policy::Policy;
use crate::model::report::{DisarmReceipt, SignedReceipt};

#[derive(Debug, Clone)]
pub struct DisarmRequest {
    pub artifact: Artifact,

    pub policy: Policy,
}

impl DisarmRequest {
    #[must_use]
    pub fn new(artifact: Artifact, policy: Policy) -> Self {
        Self { artifact, policy }
    }

    #[must_use]
    pub fn strict(artifact: Artifact) -> Self {
        Self {
            artifact,
            policy: Policy::default(),
        }
    }
}

pub trait DisarmFile {
    fn execute(&self, request: DisarmRequest) -> Result<DisarmReceipt, DomainError>;
}

pub trait DisarmAndSign {
    fn execute_signed(&self, request: DisarmRequest) -> Result<SignedReceipt, DomainError>;
}
