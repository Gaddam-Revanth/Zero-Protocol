use proptest::prelude::*;
use zero_protocol::crypto;

proptest! {
    #[test]
    fn test_aes_roundtrip(key_bytes in prop::collection::vec(any::<u8>(), 32), data in prop::collection::vec(any::<u8>(), 0..1000)) {
        // Prepare fixed size key
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        // Encrypt
        let encrypted_res = crypto::encrypt_aes_256_cbc(&data, &key);
        // Encryption might fail only if something is critically wrong with the lib setup, but for valid inputs it should succeed
        // However, AES-CBC requires padding. Our wrapper handles it.

        prop_assert!(encrypted_res.is_ok(), "Encryption failed");
        let encrypted = encrypted_res.unwrap();

        // Ciphertext should not be equal to plaintext (unless empty, but even then padding adds bytes)
        // Actually, with padding, empty input -> 1 block output.
        prop_assert_ne!(&data, &encrypted);

        // Decrypt
        let decrypted_res = crypto::decrypt_aes_256_cbc(&encrypted, &key);
        prop_assert!(decrypted_res.is_ok(), "Decryption failed");
        let decrypted = decrypted_res.unwrap();

        // Check equality
        prop_assert_eq!(data, decrypted);
    }

}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5))]
    #[test]
    fn test_password_hashing_limited(password in "[a-zA-Z0-9~!@#$%^&*()_+]{8,32}") {
        let hash_res = crypto::hash_password(&password);
        prop_assert!(hash_res.is_ok());
        let hash = hash_res.unwrap();

        let verify_res = crypto::verify_password(&password, &hash);
        prop_assert!(verify_res.is_ok());
        prop_assert!(verify_res.unwrap());
    }
}
