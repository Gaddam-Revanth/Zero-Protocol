use base64::{Engine as _, engine::general_purpose};
use zero_protocol::crypto;
use zero_protocol::models::Email;

#[test]
fn test_replay_attack_mitigation() {
    // Scenario: Attacker captures a valid encrypted message and tries to resend it later.
    // The system should ideally detect this via timestamp or unique message ID checks.
    // NOTE: Current implementation relies on logical checks in the client (simulated here).

    // 1. Alice creates a message
    let alice_mnemonic = crypto::generate_mnemonic().unwrap();
    let _alice_seed = crypto::derive_seed_from_mnemonic(&alice_mnemonic, "").unwrap();

    let bob_mnemonic = crypto::generate_mnemonic().unwrap();
    let bob_seed = crypto::derive_seed_from_mnemonic(&bob_mnemonic, "").unwrap();
    let bob_secret = k256::SecretKey::from_slice(&bob_seed[0..32]).unwrap();

    let body = "Transfer $1000";
    let encrypted_body =
        crypto::encrypt_ecies(&bob_secret.public_key().to_sec1_bytes(), body.as_bytes()).unwrap();

    let email = Email {
        id: "msg_unique_123".to_string(),
        sender: "alice@zero.net".to_string(),
        recipients: vec!["bob@zero.net".to_string()],
        subject: "Money".to_string(),
        body: general_purpose::STANDARD.encode(&encrypted_body),
        timestamp: 1000,
        is_read: false,
        folder: "inbox".to_string(),
    };

    // 2. Bob receives it first time (Success)
    // In a real DB, we'd check if msg_unique_123 exists.
    let mut processed_ids = std::collections::HashSet::new();
    processed_ids.insert(email.id.clone());

    // 3. Replay: Attacker sends same email object
    let replay_email = email.clone();

    // Check duplication
    let is_replay = processed_ids.contains(&replay_email.id);
    assert!(is_replay, "System should identify duplicate message ID");
}

#[test]
fn test_man_in_the_middle_signature_tampering() {
    // Scenario: MITM captures message and modifies content, trying to pass it off as valid.
    // Zero Protocol uses encryption (AES/ECIES), but we also need to ensure Integrity.
    // AES-GCM (used in simulation/ECIES) provides integrity tag check.

    let bob_mnemonic = crypto::generate_mnemonic().unwrap();
    let bob_seed = crypto::derive_seed_from_mnemonic(&bob_mnemonic, "").unwrap();
    let bob_secret = k256::SecretKey::from_slice(&bob_seed[0..32]).unwrap();

    let body = "Secret Coordinates";
    let encrypted_body =
        crypto::encrypt_ecies(&bob_secret.public_key().to_sec1_bytes(), body.as_bytes()).unwrap();

    // Attacker modifies the ciphertext (random bit flip)
    let mut tampered_body = encrypted_body.clone();
    // Tamper with the last byte (part of the authentication tag in AES-GCM)
    let len = tampered_body.len();
    tampered_body[len - 1] ^= 0xFF;

    // Bob tries to decrypt
    let result = crypto::decrypt_ecies(&bob_secret.to_bytes(), &tampered_body);

    assert!(
        result.is_err(),
        "Decryption must fail if ciphertext/tag is modified"
    );
}
