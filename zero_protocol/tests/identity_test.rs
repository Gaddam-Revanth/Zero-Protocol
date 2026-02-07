use zero_protocol::identity::{derive_alias_key, ZeroAddress};

#[test]
fn test_address_format() {
    let pub_key = [0u8; 32];
    let addr = ZeroAddress::new(pub_key);

    // Test to_string
    let addr_str = addr.to_string();
    assert!(addr_str.starts_with("ed25519:"));
    assert_eq!(addr_str.len(), 8 + 64); // "ed25519:" + 64 hex chars

    // Test from_string
    let parsed = ZeroAddress::from_string(&addr_str).expect("Failed to parse address");
    assert_eq!(parsed, addr);
}

#[test]
fn test_invalid_address_format() {
    assert!(ZeroAddress::from_string("invalid:123").is_err());
    assert!(ZeroAddress::from_string("ed25519:short").is_err());
}

#[test]
fn test_alias_key_derivation() {
    let key1 = derive_alias_key("revanth");
    let key2 = derive_alias_key("revanth");
    let key3 = derive_alias_key("alice");

    assert_eq!(key1.to_vec(), key2.to_vec());
    assert_ne!(key1.to_vec(), key3.to_vec());
}
