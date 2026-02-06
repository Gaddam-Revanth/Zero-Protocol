use crate::models::Email;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("JMAP error: {0}")]
    JmapError(String),
}

pub struct JmapClient {
    client: Client,
    base_url: String,
    auth_token: String,
    session: Option<JmapSession>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JmapSession {
    pub username: Option<String>,
    pub accounts: serde_json::Value,
    #[serde(rename = "primaryAccounts")]
    pub primary_accounts: Option<serde_json::Value>,
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "downloadUrl")]
    pub download_url: String,
    #[serde(rename = "uploadUrl")]
    pub upload_url: String,
}

#[derive(Serialize)]
struct JmapRequest {
    using: Vec<String>,
    #[serde(rename = "methodCalls")]
    method_calls: Vec<(String, serde_json::Value, String)>,
}

#[derive(Deserialize)]
struct JmapResponse {
    #[serde(rename = "methodResponses")]
    method_responses: Vec<(String, serde_json::Value, String)>,
}

impl JmapClient {
    pub fn new(base_url: String, auth_token: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            auth_token,
            session: None,
        }
    }

    pub async fn authenticate(&mut self) -> Result<(), NetworkError> {
        let url = format!("{}/.well-known/jmap", self.base_url);
        let session: JmapSession = self
            .client
            .get(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await?
            .json()
            .await?;

        self.session = Some(session);
        Ok(())
    }

    pub fn get_api_url(&self) -> Result<String, NetworkError> {
        self.session
            .as_ref()
            .map(|s| s.api_url.clone())
            .ok_or(NetworkError::JmapError("Not authenticated".to_string()))
    }

    // Placeholder for implementation
    pub async fn get_emails(&self, ids: Vec<String>) -> Result<Vec<Email>, NetworkError> {
        let account_id = self.get_primary_account_id()?;
        let api_url = self.get_api_url()?;

        let request = JmapRequest {
            using: vec![
                "urn:ietf:params:jmap:core".to_string(),
                "urn:ietf:params:jmap:mail".to_string(),
            ],
            method_calls: vec![(
                "Email/get".to_string(),
                serde_json::json!({
                    "accountId": account_id,
                    "ids": ids,
                    "properties": ["id", "sender", "recipients", "subject", "body", "sentAt", "isRead", "mailboxIds"]
                }),
                "0".to_string(),
            )],
        };

        let response: JmapResponse = self
            .client
            .post(&api_url)
            .bearer_auth(&self.auth_token)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        // Extract "list" from response
        for (method_name, data, _client_id) in response.method_responses {
            if method_name == "Email/get" {
                if let Some(list) = data.get("list").and_then(|l| l.as_array()) {
                    let mut emails = Vec::new();
                    for item in list {
                        // TODO: Map JMAP Email object to our Email struct
                        // This requires mapping fields and handling encryption if body is encrypted blob
                        // For now, we return empty or attempt valid parsing
                        // let email: Email = serde_json::from_value(item.clone())?;
                        // emails.push(email);
                    }
                    return Ok(emails);
                }
            }
        }

        Ok(Vec::new())
    }

    fn get_primary_account_id(&self) -> Result<String, NetworkError> {
        self.session
            .as_ref()
            .and_then(|s| s.primary_accounts.as_ref())
            .and_then(|p| p.get("urn:ietf:params:jmap:mail"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(NetworkError::JmapError(
                "No primary mail account found".to_string(),
            ))
    }

    pub async fn send_email(&self, email: &Email) -> Result<(), NetworkError> {
        let account_id = self.get_primary_account_id()?;
        let api_url = self.get_api_url()?;

        // Encryption Bridge (Placeholder)
        // In a real scenario, we would:
        // 1. Fetch recipient's public key (e.g. from Contacts or Directory).
        // 2. crypto::encrypt_ecies(&recipient_key, email.body.as_bytes())
        // 3. Send encrypted blob.
        // For now, we send generic JMAP structure.

        let request = JmapRequest {
            using: vec![
                "urn:ietf:params:jmap:core".to_string(),
                "urn:ietf:params:jmap:mail".to_string(),
            ],
            method_calls: vec![(
                "Email/set".to_string(),
                serde_json::json!({
                    "accountId": account_id,
                    "create": {
                        "tempid-1": {
                            "from": [{"email": email.sender}],
                            "to": email.recipients.iter().map(|r| serde_json::json!({"email": r})).collect::<Vec<_>>(),
                            "subject": email.subject, // Should be encrypted
                            "bodyValues": {
                                "body-part-1": {
                                    "value": email.body, // Should be encrypted
                                    "charset": "utf-8"
                                }
                            },
                            "textBody": [{"partId": "body-part-1", "type": "text/plain"}]
                        }
                    }
                }),
                "0".to_string(),
            )],
        };

        let _response: JmapResponse = self
            .client
            .post(&api_url)
            .bearer_auth(&self.auth_token)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        Ok(())
    }
}
