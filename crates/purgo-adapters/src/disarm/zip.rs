use purgo_domain::{Artifact, DisarmOutput, Disarmer, DomainError, FileFormat, Policy};

#[derive(Debug, Default, Clone, Copy)]
pub struct ZipDisarmer;

impl ZipDisarmer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Disarmer for ZipDisarmer {
    fn format(&self) -> FileFormat {
        FileFormat::Zip
    }

    fn disarm(&self, _artifact: &Artifact, _policy: &Policy) -> Result<DisarmOutput, DomainError> {
        Err(DomainError::PolicyViolation(
            "bare ZIP archives are not disarmable: a generic ZIP can nest \
             arbitrary, non-rebuildable content. Only recognised office \
             documents (OOXML: .docx/.xlsx/.pptx) are accepted."
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_registered_for_the_zip_format() {
        assert_eq!(ZipDisarmer::new().format(), FileFormat::Zip);
    }

    #[test]
    fn rejects_a_bare_zip_fail_closed() {
        let bytes = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x01, 0x02];
        let err = ZipDisarmer::new()
            .disarm(&Artifact::new(bytes), &Policy::strict())
            .unwrap_err();
        assert!(
            matches!(err, DomainError::PolicyViolation(_)),
            "a bare ZIP must be rejected fail-closed, got {err:?}"
        );
    }

    #[test]
    fn never_returns_output_for_any_input() {
        let err = ZipDisarmer::new()
            .disarm(&Artifact::new(Vec::new()), &Policy::strict())
            .unwrap_err();
        assert!(matches!(err, DomainError::PolicyViolation(_)));
    }
}
