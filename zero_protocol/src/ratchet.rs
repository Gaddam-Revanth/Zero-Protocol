use hkdf::Hkdf;
use hmac::{Hmac, Mac}; // Standard HMAC
use sha2::Sha256;
use thiserror::Error;

// Define errors for the ratchet
#[derive(Error, Debug)]
pub enum RatchetError {
    #[error("KDF Error")]
    KdfError,
}

/// A Symmetric Ratchet for Forward Secrecy.
///
/// Ensures that every message uses a unique key.
/// Ideally, the chain key is updated so that future keys cannot derive past keys.
pub struct SymmetricRatchet {
    chain_key: [u8; 32],
}

impl SymmetricRatchet {
    /// Initialize with a shared secret (e.g., from ECDH key exchange)
    pub fn new(root_key: &[u8; 32]) -> Self {
        Self {
            chain_key: *root_key,
        }
    }

    /// Advances the ratchet one step.
    /// Returns the Message Key for the *current* step, and updates the internal Chain Key.
    ///
    /// Output: [u8; 32] (Message Key)
    pub fn step(&mut self) -> Result<[u8; 32], RatchetError> {
        // Concept:
        // Input: Chain Key (CK)
        // Output: Message Key (MK) = KDF(CK, "1")
        // New Chain Key (CK') = KDF(CK, "2")

        // We use HKDF-SHA256 for KDF.

        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);

        let mut output_key_material = [0u8; 64]; // Make space for 2x 32-byte keys
        // Info tag to act as domain separation
        let info = b"ZeroRatchetStep";

        hkdf.expand(info, &mut output_key_material)
            .map_err(|_| RatchetError::KdfError)?;

        // Split: First 32 bytes -> Message Key, Last 32 bytes -> Next Chain Key
        let message_key: [u8; 32] = output_key_material[0..32].try_into().unwrap();
        let next_chain_key: [u8; 32] = output_key_material[32..64].try_into().unwrap();

        // Update state (Ratchet forward)
        self.chain_key = next_chain_key;

        Ok(message_key)
    }

    /// Get the current chain key (For debug/persistence, handle with care!)
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

        // Step 1
        let msg_key_1 = ratchet.step().unwrap();

        // Step 2
        let msg_key_2 = ratchet.step().unwrap();

        // Keys must be different
        assert_ne!(msg_key_1, msg_key_2);

        // Keys must not match root key
        assert_ne!(msg_key_1, root_key);
        assert_ne!(msg_key_2, root_key);
    }

    #[test]
    fn test_ratchet_determinism() {
        let root_key = [0xAAu8; 32];

        let mut ratchet_a = SymmetricRatchet::new(&root_key);
        let mut ratchet_b = SymmetricRatchet::new(&root_key);

        assert_eq!(ratchet_a.step().unwrap(), ratchet_b.step().unwrap());
        assert_eq!(ratchet_a.step().unwrap(), ratchet_b.step().unwrap());
    }
}
