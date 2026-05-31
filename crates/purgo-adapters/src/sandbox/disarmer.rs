use std::sync::Arc;

use purgo_domain::{Artifact, DisarmOutput, Disarmer, DomainError, FileFormat, Policy, Sandbox};

pub struct SandboxDisarmer {
    format: FileFormat,
    sandbox: Arc<dyn Sandbox>,
}

impl SandboxDisarmer {
    #[must_use]
    pub fn new(format: FileFormat, sandbox: Arc<dyn Sandbox>) -> Self {
        Self { format, sandbox }
    }
}

impl Disarmer for SandboxDisarmer {
    fn format(&self) -> FileFormat {
        self.format
    }

    fn disarm(&self, artifact: &Artifact, policy: &Policy) -> Result<DisarmOutput, DomainError> {
        self.sandbox
            .run_disarm(self.format, artifact.bytes(), policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purgo_domain::RemovedItem;
    use purgo_domain::ThreatClass;

    struct StubSandbox;

    impl Sandbox for StubSandbox {
        fn run_disarm(
            &self,
            format: FileFormat,
            input: &[u8],
            policy: &Policy,
        ) -> Result<DisarmOutput, DomainError> {
            assert_eq!(format, FileFormat::Png);
            assert!(policy.strip_metadata);
            Ok(DisarmOutput::new(
                input.to_vec(),
                vec![RemovedItem::new(
                    "chunk tEXt",
                    ThreatClass::Metadata,
                    "text",
                    12,
                )],
            ))
        }
    }

    #[test]
    fn delegates_to_the_sandbox_with_its_format() {
        let disarmer = SandboxDisarmer::new(FileFormat::Png, Arc::new(StubSandbox));
        assert_eq!(disarmer.format(), FileFormat::Png);
        let out = disarmer
            .disarm(&Artifact::new(b"png-bytes".to_vec()), &Policy::strict())
            .unwrap();
        assert_eq!(out.bytes, b"png-bytes");
        assert_eq!(out.removed.len(), 1);
    }
}
