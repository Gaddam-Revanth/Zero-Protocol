use zero_protocol::crypto;

#[test]
fn test_empty_input_encryption() {
    // Encrypting empty data should fail or return valid empty ciphertext depending on implementation
    // For AES-CBC with padding, it should return at least one block
    let key = [0u8; 32];
    let data = b"";
    let encrypted = crypto::encrypt_aes_256_cbc(data, &key).expect("Should handle empty data");

    assert!(
        encrypted.len() > 0,
        "Ciphertext should include padding even for empty input"
    );

    let decrypted =
        crypto::decrypt_aes_256_cbc(&encrypted, &key).expect("Should decrypt empty data");
    assert_eq!(decrypted, data);
}

#[test]
fn test_invalid_signature_verification() {
    let seed = [2u8; 32];
    let signing_key = crypto::derive_signing_key(&seed);
    let verifying_key = signing_key.verifying_key();

    let data = b"Vital Information";
    let signature = crypto::sign_data(&signing_key, data);

    // Corrupt signature
    let mut bad_sig = signature.clone();
    bad_sig[0] ^= 0xFF;

    assert!(crypto::verify_signature(verifying_key.as_bytes(), data, &bad_sig).is_err());
}
