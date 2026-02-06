use base64::{Engine as _, engine::general_purpose};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zero_protocol::crypto;
use zero_protocol::models::{Email, UserIdentity};
use zero_protocol::storage::Storage;

// --- Mock Network Relay ---
// Simulates a central server or P2P relay that holds encrypted messages
#[derive(Clone)]
struct MockRelay {
    // Map recipient_username -> List of Encrypted Emails
    inboxes: Arc<Mutex<HashMap<String, Vec<Email>>>>,
}

impl MockRelay {
    fn new() -> Self {
        Self {
            inboxes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn push_email(&self, recipient: &str, email: Email) {
        let mut inboxes = self.inboxes.lock().unwrap();
        inboxes
            .entry(recipient.to_string())
            .or_default()
            .push(email);
    }

    fn fetch_emails(&self, recipient: &str) -> Vec<Email> {
        let mut inboxes = self.inboxes.lock().unwrap();
        if let Some(inbox) = inboxes.get_mut(recipient) {
            // Move emails out (like POP3/JMAP fetch + delete) or just copy
            let emails = inbox.clone();
            inbox.clear();
            emails
        } else {
            Vec::new()
        }
    }
}

// --- Agent ---
// Simulates a user with their own device/storage
struct Agent {
    username: String,
    storage: Storage,
    keypair: k256::SecretKey,  // For ECIES simulation
    public_key_bytes: Vec<u8>, // To publish to directory
}

impl Agent {
    fn new(username: &str) -> Self {
        let mnemonic = crypto::generate_mnemonic().unwrap();
        let seed = crypto::derive_seed_from_mnemonic(&mnemonic, "").unwrap();

        // Use first 32 bytes of seed for ECIES (Simulation only)
        let secret_key = k256::SecretKey::from_slice(&seed[0..32]).unwrap();
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_sec1_bytes().to_vec();

        let user_identity = UserIdentity {
            id: format!("id_{}", username),
            username: username.to_string(),
            public_key: hex::encode(&public_key_bytes),
            created_at: 0,
        };

        // Each agent has a private local DB
        let storage = Storage::open(":memory:").unwrap();
        storage.save_user(&user_identity).unwrap();

        Self {
            username: username.to_string(),
            storage,
            keypair: secret_key,
            public_key_bytes: public_key_bytes.to_vec(),
        }
    }

    fn send_message(
        &self,
        recipient_username: &str,
        recipient_pub_key: &[u8],
        body: &str,
        relay: &MockRelay,
    ) {
        // 1. Encrypt Content for Recipient
        let encrypted_body = crypto::encrypt_ecies(recipient_pub_key, body.as_bytes()).unwrap();
        let body_b64 = general_purpose::STANDARD.encode(encrypted_body);

        // 2. Wrap in Email Struct
        let email = Email {
            id: format!("{}_{}", self.username, rand::random::<u32>()),
            sender: self.username.clone(),
            recipients: vec![recipient_username.to_string()],
            subject: "Simulation Msg".to_string(),
            body: body_b64,
            timestamp: 1000,
            is_read: false,
            folder: "inbox".to_string(),
        };

        // 3. Send to Relay
        relay.push_email(recipient_username, email.clone()); // Clone for local 'sent' copy if needed

        // 4. Save to Sent folder
        // self.storage.save_email(&email).unwrap(); // (Optional for sim)
    }

    fn check_inbox(&self, relay: &MockRelay) -> usize {
        let emails = relay.fetch_emails(&self.username);
        let count = emails.len();

        for email in emails {
            // Decrypt
            let encrypted_bytes = general_purpose::STANDARD.decode(&email.body).unwrap();
            let decrypted = crypto::decrypt_ecies(&self.keypair.to_bytes(), &encrypted_bytes);

            match decrypted {
                Ok(_) => {
                    // Save to local storage
                    self.storage.save_email(&email).unwrap();
                }
                Err(e) => println!(
                    "Agent {} failed to decrypt msg from {}: {:?}",
                    self.username, email.sender, e
                ),
            }
        }
        count
    }
}

#[tokio::test]
async fn test_multi_user_simulation() {
    let relay = MockRelay::new();
    let num_users = 5;
    let mut agents = Vec::new();

    // 1. Register Agents (Publication Phase)
    let mut directory: HashMap<String, Vec<u8>> = HashMap::new();

    for i in 0..num_users {
        let name = format!("user_{}", i);
        let agent = Agent::new(&name);
        directory.insert(name.clone(), agent.public_key_bytes.clone());
        agents.push(agent);
    }

    // 2. Simulation Loop
    // Each agent randomly sends a message to another agent
    let iterations = 20;

    for _ in 0..iterations {
        let sender = agents.choose(&mut rand::thread_rng()).unwrap();

        // Pick recipient != sender
        // Pick recipient != sender
        let recipients: Vec<&Agent> = agents
            .iter()
            .filter(|a| a.username != sender.username)
            .collect();
        let recipient = recipients.choose(&mut rand::thread_rng()).unwrap();

        let recipient_key = directory.get(&recipient.username).unwrap();

        // Action: Send
        sender.send_message(
            &recipient.username,
            recipient_key,
            &format!("Hello from {} to {}", sender.username, recipient.username),
            &relay,
        );
    }

    // 3. Process Inboxes
    let mut total_received = 0;
    for agent in &agents {
        let count = agent.check_inbox(&relay);
        total_received += count;
    }

    assert_eq!(
        total_received, iterations,
        "All sent messages should be received and decrypted"
    );
}
