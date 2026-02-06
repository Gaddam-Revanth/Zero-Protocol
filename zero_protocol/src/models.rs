use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserIdentity {
    pub id: String,         // UUID or Public Key Hash
    pub public_key: String, // Hex encoded
    pub username: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Email {
    pub id: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub subject: String, // Encrypted? Logic handled by crypto, but model holds string/bytes
    pub body: String,    // Encrypted content (Base64 usually if simple string field, or Vec<u8>)
    pub timestamp: i64,
    pub is_read: bool,
    pub folder: String, // Inbox, Sent, etc.
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub address: String, // zero protocol address / email
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedPacket {
    pub iv: String,      // Hex
    pub content: String, // Hex or Base64
    pub mac: Option<String>,
}
