use crate::model::artifact::CleanArtifact;
use crate::model::format::FileFormat;
use crate::model::signature::{PublicKey, Signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThreatClass {
    ActiveContent,

    Metadata,

    EmbeddedFile,

    ExternalReference,
}

impl ThreatClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveContent => "active-content",
            Self::Metadata => "metadata",
            Self::EmbeddedFile => "embedded-file",
            Self::ExternalReference => "external-reference",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedItem {
    pub location: String,

    pub class: ThreatClass,

    pub detail: String,

    pub bytes_removed: usize,
}

impl RemovedItem {
    #[must_use]
    pub fn new(
        location: impl Into<String>,
        class: ThreatClass,
        detail: impl Into<String>,
        bytes_removed: usize,
    ) -> Self {
        Self {
            location: location.into(),
            class,
            detail: detail.into(),
            bytes_removed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisarmReport {
    pub format: FileFormat,

    pub original_size: usize,

    pub sanitized_size: usize,

    pub removed: Vec<RemovedItem>,
}

impl DisarmReport {
    #[must_use]
    pub fn is_modified(&self) -> bool {
        !self.removed.is_empty() || self.original_size != self.sanitized_size
    }

    #[must_use]
    pub fn removed_count(&self) -> usize {
        self.removed.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisarmReceipt {
    pub clean: CleanArtifact,

    pub report: DisarmReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReceipt {
    pub receipt: DisarmReceipt,

    pub signature: Signature,

    pub public_key: PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_when_items_removed_even_if_size_equal() {
        let report = DisarmReport {
            format: FileFormat::Png,
            original_size: 100,
            sanitized_size: 100,
            removed: vec![RemovedItem::new(
                "chunk tEXt",
                ThreatClass::Metadata,
                "text",
                10,
            )],
        };
        assert!(report.is_modified());
        assert_eq!(report.removed_count(), 1);
    }

    #[test]
    fn unmodified_when_empty_and_same_size() {
        let report = DisarmReport {
            format: FileFormat::Png,
            original_size: 50,
            sanitized_size: 50,
            removed: vec![],
        };
        assert!(!report.is_modified());
    }
}
