#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub strip_metadata: bool,

    pub keep_jfif: bool,
}

impl Policy {
    #[must_use]
    pub fn strict() -> Self {
        Self {
            strip_metadata: true,
            keep_jfif: true,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::strict()
    }
}
