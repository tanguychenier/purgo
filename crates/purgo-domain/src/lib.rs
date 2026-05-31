pub mod error;
pub mod model;
pub mod ports;

pub use error::DomainError;
pub use model::{
    artifact::{Artifact, CleanArtifact},
    format::FileFormat,
    policy::Policy,
    report::{DisarmReceipt, DisarmReport, RemovedItem, SignedReceipt, ThreatClass},
    signature::{PublicKey, Signature},
};
pub use ports::{
    inbound::{DisarmAndSign, DisarmFile, DisarmRequest},
    outbound::{DisarmOutput, Disarmer, FormatDetector, Sandbox, Signer},
};
