use zero_protocol::pow::{DEFAULT_DIFFICULTY, PoWMessage};

#[test]
fn test_pow_mining_and_verification() {
    let payload = b"Hello Zero Protocol".to_vec();

    // 1. Mine a valid PoW Message
    println!("Mining PoW...");
    let start = std::time::Instant::now();
    let msg = PoWMessage::new(payload.clone(), DEFAULT_DIFFICULTY);
    println!("Mined in {:?}", start.elapsed());

    // 2. Verify it's valid
    assert!(msg.verify(DEFAULT_DIFFICULTY));
    assert_eq!(msg.payload, payload);

    // 3. Verify tampering fails
    let mut bad_msg = msg.clone();
    bad_msg.nonce += 1; // Change nonce
    assert!(!bad_msg.verify(DEFAULT_DIFFICULTY));

    let mut bad_payload_msg = msg.clone();
    bad_payload_msg.payload = b"Hacked".to_vec();
    assert!(!bad_payload_msg.verify(DEFAULT_DIFFICULTY));
}
