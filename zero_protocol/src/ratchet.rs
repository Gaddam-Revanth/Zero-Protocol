use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RatchetError {
    #[error("KDF Error")]
    KdfError,
}

/// Symmetric Ratchet for Forward Secrecy
pub struct SymmetricRatchet {
    chain_key: [u8; 32],
}

impl SymmetricRatchet {
    pub fn new(root_key: &[u8; 32]) -> Self {
        Self {
            chain_key: *root_key,
        }
    }

    /// Advance ratchet and return message key
    pub fn step(&mut self) -> Result<[u8; 32], RatchetError> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);
        let mut output = [0u8; 64];
        hkdf.expand(b"ZeroRatchetStep", &mut output)
            .map_err(|_| RatchetError::KdfError)?;

        let message_key: [u8; 32] = output[0..32].try_into().unwrap();
        self.chain_key = output[32..64].try_into().unwrap();
        Ok(message_key)
    }

    pub fn get_chain_state(&self) -> [u8; 32] {
        self.chain_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_advancement() {
        let root_key = [0x55u8; 32];
        let mut ratchet = SymmetricRatchet::new(&root_key);
        let key1 = ratchet.step().unwrap();
        let key2 = ratchet.step().unwrap();
        assert_ne!(key1, key2);
        assert_ne!(key1, root_key);
    }

    #[test]
    fn test_ratchet_determinism() {
        let root_key = [0xAAu8; 32];
        let mut a = SymmetricRatchet::new(&root_key);
        let mut b = SymmetricRatchet::new(&root_key);
        assert_eq!(a.step().unwrap(), b.step().unwrap());
    }
}
