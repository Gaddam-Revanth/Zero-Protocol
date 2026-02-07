use crate::crypto;
use crate::models::{Email, UserIdentity};
use rusqlite::{Connection, Result, params};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DbError(#[from] rusqlite::Error),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto::CryptoError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                username TEXT NOT NULL,
                created_at INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS emails (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipients TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                timestamp INTEGER,
                is_read BOOLEAN,
                folder TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                public_key TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Storage { conn })
    }

    pub fn save_user(&self, user: &UserIdentity) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO users (id, public_key, username, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![user.id, user.public_key, user.username, user.created_at],
        )?;
        Ok(())
    }

    pub fn get_user(&self) -> Result<Option<UserIdentity>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, public_key, username, created_at FROM users LIMIT 1")?;
        let mut rows = stmt.query([])?;

        if let Some(row) = rows.next()? {
            Ok(Some(UserIdentity {
                id: row.get(0)?,
                public_key: row.get(1)?,
                username: row.get(2)?,
                created_at: row.get(3)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn save_email(&self, email: &Email) -> Result<(), StorageError> {
        let recipients_json = serde_json::to_string(&email.recipients)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO emails (id, sender, recipients, subject, body, timestamp, is_read, folder) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                email.id,
                email.sender,
                recipients_json,
                email.subject,
                email.body,
                email.timestamp,
                email.is_read,
                email.folder
            ],
        )?;
        Ok(())
    }

    pub fn get_emails_by_folder(&self, folder: &str) -> Result<Vec<Email>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, recipients, subject, body, timestamp, is_read, folder FROM emails WHERE folder = ?1 ORDER BY timestamp DESC"
        )?;
        let rows = stmt.query_map([folder], |row| {
            let recipients_str: String = row.get(2)?;
            let recipients: Vec<String> = serde_json::from_str(&recipients_str).unwrap_or_default();
            Ok(Email {
                id: row.get(0)?,
                sender: row.get(1)?,
                recipients,
                subject: row.get(3)?,
                body: row.get(4)?,
                timestamp: row.get(5)?,
                is_read: row.get(6)?,
                folder: row.get(7)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_user_operations() {
        let storage = Storage::open(":memory:").unwrap();
        let user = UserIdentity {
            id: "user_123".to_string(),
            public_key: "pub_key_hex".to_string(),
            username: "testuser".to_string(),
            created_at: 1234567890,
        };
        storage.save_user(&user).unwrap();
        let fetched = storage.get_user().unwrap().unwrap();
        assert_eq!(fetched.id, user.id);
    }

    #[test]
    fn test_storage_email_operations() {
        let storage = Storage::open(":memory:").unwrap();
        let email = Email {
            id: "msg_1".to_string(),
            sender: "alice@example.com".to_string(),
            recipients: vec!["bob@example.com".to_string()],
            subject: "Super Secret".to_string(),
            body: "EncryptedBody".to_string(),
            timestamp: 100,
            is_read: false,
            folder: "inbox".to_string(),
        };
        storage.save_email(&email).unwrap();
        let emails = storage.get_emails_by_folder("inbox").unwrap();
        assert_eq!(emails.len(), 1);
    }
}
