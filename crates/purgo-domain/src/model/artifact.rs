use crate::model::format::FileFormat;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    name: Option<String>,
    bytes: Vec<u8>,
}

impl Artifact {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { name: None, bytes }
    }

    #[must_use]
    pub fn named(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: Some(name.into()),
            bytes,
        }
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanArtifact {
    format: FileFormat,
    bytes: Vec<u8>,
}

impl CleanArtifact {
    #[must_use]
    pub fn new(format: FileFormat, bytes: Vec<u8>) -> Self {
        Self { format, bytes }
    }

    #[must_use]
    pub fn format(&self) -> FileFormat {
        self.format
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_name_and_length() {
        let a = Artifact::named("photo.jpg", vec![1, 2, 3]);
        assert_eq!(a.name(), Some("photo.jpg"));
        assert_eq!(a.len(), 3);
        assert!(!a.is_empty());
        assert!(Artifact::new(vec![]).is_empty());
    }
}
