use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileFormat {
    Jpeg,

    Png,

    Pdf,

    Zip,

    Ooxml,

    Unknown,
}

impl FileFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
            Self::Png => "png",
            Self::Pdf => "pdf",
            Self::Zip => "zip",
            Self::Ooxml => "ooxml",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for FileFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_as_str() {
        assert_eq!(FileFormat::Jpeg.to_string(), "jpeg");
        assert_eq!(FileFormat::Ooxml.as_str(), "ooxml");
        assert_eq!(FileFormat::Unknown.as_str(), "unknown");
    }
}
