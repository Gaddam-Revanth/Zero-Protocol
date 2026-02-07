use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_DIFFICULTY: u32 = 2; // MVP: 2 bytes (16 bits) of zeros. Real world needs more.

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PoWMessage {
    pub nonce: u64,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

impl PoWMessage {
    pub fn new(payload: Vec<u8>, difficulty: u32) -> Self {
        let mut msg = Self {
            nonce: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload,
        };
        msg.mine(difficulty);
        msg
    }

    pub fn mine(&mut self, difficulty: u32) {
        loop {
            if self.verify(difficulty) {
                break;
            }
            self.nonce += 1;
        }
    }

    pub fn verify(&self, difficulty: u32) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.payload);
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        let result = hasher.finalize();

        if difficulty as usize > result.len() {
            return false;
        }

        result[0..difficulty as usize].iter().all(|&x| x == 0)
    }
}
