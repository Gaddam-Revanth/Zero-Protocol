use zero_protocol::crypto;
use zero_protocol::models::{Email, UserIdentity};
use zero_protocol::storage::Storage;

#[test]
fn test_full_user_registration_flow() {
    // 1. Generate Mnemonic
    let mnemonic = crypto::generate_mnemonic().expect("Failed to generate mnemonic");

    // 2. Derive Seed & Keys
    let seed = crypto::derive_seed_from_mnemonic(&mnemonic, "").expect("Failed to derive seed");
    let signing_key = crypto::derive_signing_key(&seed);
    let public_key = signing_key.verifying_key();
    let pub_key_hex = hex::encode(public_key.as_bytes());

    // 3. Create Identity
    let user = UserIdentity {
        id: "user_test_flow".to_string(),
        public_key: pub_key_hex.clone(),
        username: "integration_user".to_string(),
        created_at: 1000,
    };

    // 4. Save to Storage
    let storage = Storage::open(":memory:").expect("Failed to open DB");
    storage.save_user(&user).expect("Failed to save user");

    // 5. Verify Retrieval
    let retrieved = storage.get_user().expect("Failed to get user").unwrap();
    assert_eq!(retrieved.username, "integration_user");
    assert_eq!(retrieved.public_key, pub_key_hex);
}

#[test]
fn test_end_to_end_email_encryption_flow() {
    // Scenario: Alice sends email to Bob

    // 1. Setup Alice
    let alice_mnemonic = crypto::generate_mnemonic().unwrap();
    let alice_seed = crypto::derive_seed_from_mnemonic(&alice_mnemonic, "").unwrap();
    let alice_key = crypto::derive_signing_key(&alice_seed); // (In real ECIES, needs diff key type, but using ed25519 seed for sim)

    // 2. Setup Bob
    let bob_mnemonic = crypto::generate_mnemonic().unwrap();
    let bob_seed = crypto::derive_seed_from_mnemonic(&bob_mnemonic, "").unwrap();
    let bob_secret = k256::SecretKey::from_slice(&bob_seed[0..32]).expect("Invalid key");
    let bob_public = bob_secret.public_key();
    let bob_public_bytes = bob_public.to_sec1_bytes();

    // 3. Alice composes email
    let original_body = "Meet me at Zero Point at dawn.";

    // 4. Alice encrypts for Bob
    let encrypted_body = crypto::encrypt_ecies(&bob_public_bytes, original_body.as_bytes())
        .expect("Encryption failed");

    // 5. Create Email Object
    let email = Email {
        id: "msg_flow_1".to_string(),
        sender: "alice@zero.net".to_string(),
        recipients: vec!["bob@zero.net".to_string()],
        subject: "Secret Mission".to_string(),
        body: base64::encode(&encrypted_body), // Store as base64 string
        timestamp: 2000,
        is_read: false,
        folder: "inbox".to_string(),
    };

    // 6. Bob receives (Simulating storage load)
    let storage = Storage::open(":memory:").unwrap();
    storage.save_email(&email).unwrap();

    let bob_inbox = storage.get_emails_by_folder("inbox").unwrap();
    let received_msg = &bob_inbox[0];

    // 7. Bob decrypts
    let encrypted_bytes = base64::decode(&received_msg.body).unwrap();
    let decrypted_body =
        crypto::decrypt_ecies(&bob_secret.to_bytes(), &encrypted_bytes).expect("Decryption failed");

    assert_eq!(std::str::from_utf8(&decrypted_body).unwrap(), original_body);
}

#[test]
fn test_password_security_flow() {
    let password = "CorrectHorseBatteryStaple";
    let hash = crypto::hash_password(password).expect("Hashing failed");

    // Positive case
    assert!(crypto::verify_password(password, &hash).unwrap());

    // Negative cases
    assert!(!crypto::verify_password("wrong", &hash).unwrap());
    assert!(!crypto::verify_password("", &hash).unwrap());
    assert!(!crypto::verify_password("CorrectHorseBatteryStapl", &hash).unwrap());
}
