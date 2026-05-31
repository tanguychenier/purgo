use std::sync::Arc;

use purgo_domain::{
    CleanArtifact, DisarmFile, DisarmReceipt, DisarmReport, DisarmRequest, Disarmer, DomainError,
    FileFormat, FormatDetector,
};

pub struct DisarmService {
    detector: Arc<dyn FormatDetector>,
    disarmers: Vec<Arc<dyn Disarmer>>,
}

impl DisarmService {
    #[must_use]
    pub fn new(detector: Arc<dyn FormatDetector>, disarmers: Vec<Arc<dyn Disarmer>>) -> Self {
        for (i, a) in disarmers.iter().enumerate() {
            for b in &disarmers[i + 1..] {
                assert!(
                    a.format() != b.format(),
                    "two disarmers registered for {}",
                    a.format()
                );
            }
        }
        Self {
            detector,
            disarmers,
        }
    }

    fn select(&self, format: FileFormat) -> Option<&Arc<dyn Disarmer>> {
        self.disarmers.iter().find(|d| d.format() == format)
    }
}

impl DisarmFile for DisarmService {
    fn execute(&self, request: DisarmRequest) -> Result<DisarmReceipt, DomainError> {
        let DisarmRequest { artifact, policy } = request;
        let format = self.detector.detect(&artifact);
        let disarmer = self
            .select(format)
            .ok_or(DomainError::UnsupportedFormat(format))?;

        let original_size = artifact.len();
        let output = disarmer.disarm(&artifact, &policy)?;

        let report = DisarmReport {
            format,
            original_size,
            sanitized_size: output.bytes.len(),
            removed: output.removed,
        };
        Ok(DisarmReceipt {
            clean: CleanArtifact::new(format, output.bytes),
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purgo_domain::{Artifact, DisarmOutput, Policy, RemovedItem, ThreatClass};

    struct FixedDetector(FileFormat);
    impl FormatDetector for FixedDetector {
        fn detect(&self, _artifact: &Artifact) -> FileFormat {
            self.0
        }
    }

    struct StubDisarmer {
        format: FileFormat,
        removed: Vec<RemovedItem>,
        output: Vec<u8>,
    }
    impl Disarmer for StubDisarmer {
        fn format(&self) -> FileFormat {
            self.format
        }
        fn disarm(
            &self,
            _artifact: &Artifact,
            _policy: &Policy,
        ) -> Result<DisarmOutput, DomainError> {
            Ok(DisarmOutput::new(self.output.clone(), self.removed.clone()))
        }
    }

    fn service_with(detected: FileFormat, disarmer: StubDisarmer) -> DisarmService {
        DisarmService::new(Arc::new(FixedDetector(detected)), vec![Arc::new(disarmer)])
    }

    #[test]
    fn routes_to_the_disarmer_matching_the_detected_format() {
        let svc = service_with(
            FileFormat::Png,
            StubDisarmer {
                format: FileFormat::Png,
                removed: vec![RemovedItem::new(
                    "chunk tEXt",
                    ThreatClass::Metadata,
                    "text chunk",
                    12,
                )],
                output: b"clean".to_vec(),
            },
        );

        let receipt = svc
            .execute(DisarmRequest::strict(Artifact::new(
                b"original-bytes".to_vec(),
            )))
            .expect("png is supported");

        assert_eq!(receipt.clean.format(), FileFormat::Png);
        assert_eq!(receipt.clean.bytes(), b"clean");
        assert_eq!(receipt.report.original_size, "original-bytes".len());
        assert_eq!(receipt.report.sanitized_size, "clean".len());
        assert_eq!(receipt.report.removed_count(), 1);
        assert!(receipt.report.is_modified());
    }

    #[test]
    fn rejects_a_format_with_no_registered_disarmer() {
        let svc = service_with(
            FileFormat::Unknown,
            StubDisarmer {
                format: FileFormat::Png,
                removed: vec![],
                output: vec![],
            },
        );

        let err = svc
            .execute(DisarmRequest::strict(Artifact::new(vec![0u8; 4])))
            .unwrap_err();

        assert_eq!(err, DomainError::UnsupportedFormat(FileFormat::Unknown));
    }

    #[test]
    #[should_panic(expected = "two disarmers registered")]
    fn refuses_duplicate_disarmers_for_one_format() {
        let make = || {
            Arc::new(StubDisarmer {
                format: FileFormat::Jpeg,
                removed: vec![],
                output: vec![],
            }) as Arc<dyn Disarmer>
        };
        let _ = DisarmService::new(
            Arc::new(FixedDetector(FileFormat::Jpeg)),
            vec![make(), make()],
        );
    }
}
