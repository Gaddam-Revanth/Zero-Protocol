use aes::cipher::{self, BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7}; // Explicit imports + generic
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use k256::{
    EncodedPoint, PublicKey, SecretKey, ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint,
};
use pbkdf2::pbkdf2_hmac;
use rand::{Rng, RngCore};
use sha2::Sha256;
use thiserror::Error;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Key generation error: {0}")]
    KeyGenError(String),
    #[error("Password hashing error: {0}")]
    PasswordHashError(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    #[error("Invalid key")]
    InvalidKey,
}

/// Generates a new 12-word BIP39 mnemonic.
pub fn generate_mnemonic() -> Result<String, CryptoError> {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    Ok(mnemonic.phrase().to_string())
}

/// Derives a 32-byte seed from a mnemonic (and optional passphrase).
pub fn derive_seed_from_mnemonic(phrase: &str, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
        .map_err(|_| CryptoError::InvalidMnemonic)?;
    let seed = Seed::new(&mnemonic, passphrase);
    Ok(seed.as_bytes().to_vec())
}

/// Derives an Ed25519 signing key from a seed.
pub fn derive_signing_key(seed: &[u8]) -> SigningKey {
    let mut key_bytes = [0u8; 32];
    if seed.len() >= 32 {
        key_bytes.copy_from_slice(&seed[0..32]);
    } else {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(seed);
        key_bytes = hasher.finalize().into();
    }
    SigningKey::from_bytes(&key_bytes)
}

/// AES-256-CBC Encryption
pub fn encrypt_aes_256_cbc(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::EncryptionError);
    }
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let mut encryptor = Aes256CbcEnc::new(key.into(), &iv.into());
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(data);

    let mut result = Vec::with_capacity(iv.len() + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// AES-256-CBC Decryption
pub fn decrypt_aes_256_cbc(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 || encrypted_data.len() < 16 {
        return Err(CryptoError::DecryptionError);
    }
    let (iv, ciphertext) = encrypted_data.split_at(16);
    let mut decryptor = Aes256CbcDec::new(key.into(), iv.into());

    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| CryptoError::DecryptionError)
}

pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::PasswordHashError(e.to_string()))?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| CryptoError::PasswordHashError(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn derive_key_pbkdf2(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, &mut key);
    key
}

/// ECIES Encryption (Pure Rust Implementation)
pub fn encrypt_ecies(recipient_pub_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let recipient_pub =
        PublicKey::from_sec1_bytes(recipient_pub_bytes).map_err(|_| CryptoError::InvalidKey)?;

    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(&[], &mut key)
        .map_err(|_| CryptoError::EncryptionError)?;

    let cipher = Aes256Gcm::new(&key.into());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let encrypted = cipher
        .encrypt(&nonce.into(), data)
        .map_err(|_| CryptoError::EncryptionError)?;

    let ephemeral_pub_bytes = ephemeral_pub.to_encoded_point(true);
    let mut result = Vec::with_capacity(33 + 12 + encrypted.len());
    result.extend_from_slice(ephemeral_pub_bytes.as_bytes());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);

    Ok(result)
}

pub fn decrypt_ecies(recipient_secret_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 33 + 12 {
        return Err(CryptoError::DecryptionError);
    }

    let (ephemeral_pub_bytes, rest) = data.split_at(33);
    let (nonce, ciphertext) = rest.split_at(12);

    let recipient_secret =
        SecretKey::from_slice(recipient_secret_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let ephemeral_pub =
        PublicKey::from_sec1_bytes(ephemeral_pub_bytes).map_err(|_| CryptoError::InvalidKey)?;

    let shared_secret = k256::ecdh::diffie_hellman(
        recipient_secret.to_nonzero_scalar(),
        ephemeral_pub.as_affine(),
    );

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(&[], &mut key)
        .map_err(|_| CryptoError::DecryptionError)?;

    let cipher = Aes256Gcm::new(&key.into());
    let decrypted = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| CryptoError::DecryptionError)?;

    Ok(decrypted)
}
