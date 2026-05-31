#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl Signature {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
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
    fn signature_round_trips_its_bytes() {
        let sig = Signature::new(vec![1, 2, 3]);
        assert_eq!(sig.bytes(), &[1, 2, 3]);
        assert_eq!(sig.into_bytes(), vec![1, 2, 3]);
    }

    #[test]
    fn public_key_round_trips_its_bytes() {
        let key = PublicKey::new(vec![9, 8, 7]);
        assert_eq!(key.bytes(), &[9, 8, 7]);
        assert_eq!(key.into_bytes(), vec![9, 8, 7]);
    }
}
