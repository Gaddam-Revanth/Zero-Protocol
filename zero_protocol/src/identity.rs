use crate::crypto;
use libp2p::kad::{Quorum, Record};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Invalid address format")]
    InvalidAddress,
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto::CryptoError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("DHT error: {0}")]
    DhtError(String),
}

/// Represents a Zero Protocol Address
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZeroAddress {
    /// The primary identity (Public Key)
    pub public_key: [u8; 32],
    /// Optional human-readable alias (e.g., "revanth@zero.mail")
    pub alias: Option<String>,
    /// Optional ENS name (e.g., "revanth.eth")
    pub ens: Option<String>,
}

impl ZeroAddress {
    /// Create a new address from a public key
    pub fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            alias: None,
            ens: None,
        }
    }

    /// Format as standard string: "ed25519:<hex_key>"
    pub fn to_string(&self) -> String {
        format!("ed25519:{}", hex::encode(self.public_key))
    }

    /// Parse from string: "ed25519:<hex_key>"
    pub fn from_string(s: &str) -> Result<Self, IdentityError> {
        if !s.starts_with("ed25519:") {
            return Err(IdentityError::InvalidAddress);
        }
        let hex_part = &s[8..];
        let bytes = hex::decode(hex_part).map_err(|_| IdentityError::InvalidAddress)?;
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidAddress);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self::new(key))
    }
}

/// Derive the DHT key for an alias
/// Key = SHA256("alias:" + alias_string)
pub fn derive_alias_key(alias: &str) -> libp2p::kad::RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(b"alias:");
    hasher.update(alias.as_bytes());
    let result = hasher.finalize();
    libp2p::kad::RecordKey::new(&result)
}

/// Register an alias in the DHT
/// This maps "alias:revanth" -> "ed25519:public_key"
pub fn register_alias(
    swarm: &mut libp2p::Swarm<crate::p2p::ZeroBehaviour>,
    alias: &str,
    public_key: &[u8; 32],
) -> Result<libp2p::kad::QueryId, IdentityError> {
    let key = derive_alias_key(alias);
    let value = public_key.to_vec(); // Store raw public key bytes

    let record = Record {
        key,
        value,
        publisher: None,
        expires: None, // In production, set an expiry!
    };

    swarm
        .behaviour_mut()
        .kademlia
        .put_record(record, Quorum::One)
        .map_err(|e| IdentityError::DhtError(e.to_string()))
}

/// Resolve an alias from the DHT
/// This looks up "alias:revanth" -> returns public_key
pub fn resolve_alias(
    swarm: &mut libp2p::Swarm<crate::p2p::ZeroBehaviour>,
    alias: &str,
) -> libp2p::kad::QueryId {
    let key = derive_alias_key(alias);
    swarm.behaviour_mut().kademlia.get_record(key)
}
