use purgo_domain::{
    Artifact, DisarmOutput, Disarmer, DomainError, FileFormat, Policy, RemovedItem, ThreatClass,
};
use purgo_filters::{disarm_png, FilterError, PngOptions, RemovedChunk};

#[derive(Debug, Default, Clone, Copy)]
pub struct PngDisarmer;

impl PngDisarmer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

pub(crate) fn png_malformed(reason: &str) -> DomainError {
    DomainError::MalformedInput {
        format: FileFormat::Png,
        reason: reason.to_owned(),
    }
}

fn to_domain_error(err: FilterError) -> DomainError {
    match err {
        FilterError::Malformed(reason) => png_malformed(reason),
    }
}

pub(crate) fn png_removed_item(chunk: &RemovedChunk) -> RemovedItem {
    RemovedItem::new(
        format!("chunk {}", chunk.name),
        ThreatClass::Metadata,
        format!("ancillary PNG chunk '{}'", chunk.name),
        chunk.bytes_removed,
    )
}

impl Disarmer for PngDisarmer {
    fn format(&self) -> FileFormat {
        FileFormat::Png
    }

    fn disarm(&self, artifact: &Artifact, policy: &Policy) -> Result<DisarmOutput, DomainError> {
        let options = PngOptions {
            strip_metadata: policy.strip_metadata,
        };
        let (bytes, removed) = disarm_png(artifact.bytes(), options).map_err(to_domain_error)?;
        let removed = removed.iter().map(png_removed_item).collect();
        Ok(DisarmOutput::new(bytes, removed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    fn push_chunk(v: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(kind);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0, 0, 0, 0]);
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn sample() -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        push_chunk(&mut v, b"IHDR", &[0, 0, 0, 0]);
        push_chunk(&mut v, b"tEXt", b"Comment\x00secret-payload");
        push_chunk(&mut v, b"IDAT", &[1, 2, 3]);
        push_chunk(&mut v, b"IEND", &[]);
        v
    }

    #[test]
    fn drops_text_chunk_and_keeps_critical_chunks() {
        let out = PngDisarmer::new()
            .disarm(&Artifact::new(sample()), &Policy::strict())
            .unwrap();
        assert!(!contains(&out.bytes, b"secret-payload"));
        assert!(contains(&out.bytes, b"IHDR"));
        assert!(contains(&out.bytes, b"IDAT"));
        assert!(contains(&out.bytes, b"IEND"));
        assert_eq!(out.removed.len(), 1);
        assert!(out.removed[0].location.contains("tEXt"));
    }

    #[test]
    fn rejects_input_without_signature() {
        let err = PngDisarmer::new()
            .disarm(&Artifact::new(vec![0u8; 8]), &Policy::strict())
            .unwrap_err();
        assert!(matches!(err, DomainError::MalformedInput { .. }));
    }
}
