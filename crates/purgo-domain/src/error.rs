use crate::model::format::FileFormat;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainError {
    UnsupportedFormat(FileFormat),

    MalformedInput { format: FileFormat, reason: String },

    PolicyViolation(String),

    SigningFailed(String),

    SandboxFailure(String),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat(format) => write!(f, "unsupported format: {format}"),
            Self::MalformedInput { format, reason } => {
                write!(f, "malformed {format} input: {reason}")
            }
            Self::PolicyViolation(reason) => write!(f, "policy violation: {reason}"),
            Self::SigningFailed(reason) => write!(f, "signing failed: {reason}"),
            Self::SandboxFailure(reason) => write!(f, "sandbox failure: {reason}"),
        }
    }
}

impl std::error::Error for DomainError {}
