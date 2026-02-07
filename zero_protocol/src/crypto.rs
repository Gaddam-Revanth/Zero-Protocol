use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use k256::{PublicKey, SecretKey, ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
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
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Generate a 12-word BIP39 mnemonic
pub fn generate_mnemonic() -> Result<String, CryptoError> {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    Ok(mnemonic.phrase().to_string())
}

/// Derive 64-byte seed from mnemonic
pub fn derive_seed_from_mnemonic(phrase: &str, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
        .map_err(|_| CryptoError::InvalidMnemonic)?;
    let seed = Seed::new(&mnemonic, passphrase);
    Ok(seed.as_bytes().to_vec())
}

/// Derive Ed25519 signing key from seed
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

/// Sign data with Ed25519
pub fn sign_data(key: &SigningKey, data: &[u8]) -> Vec<u8> {
    key.sign(data).to_vec()
}

/// Verify Ed25519 signature
pub fn verify_signature(
    public_key_bytes: &[u8],
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let public_key = VerifyingKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?,
    )
    .map_err(|_| CryptoError::InvalidKey)?;

    let signature = Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?,
    );

    public_key
        .verify(data, &signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// AES-256-CBC encryption
pub fn encrypt_aes_256_cbc(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::EncryptionError);
    }
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let encryptor = Aes256CbcEnc::new(key.into(), &iv.into());
    let len = data.len();
    let buffer_len = len + 16;
    let mut buffer = vec![0u8; buffer_len];
    buffer[..len].copy_from_slice(data);

    let ciphertext = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, len)
        .map_err(|_| CryptoError::EncryptionError)?;

    let mut result = Vec::with_capacity(iv.len() + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(ciphertext);
    Ok(result)
}

/// AES-256-CBC decryption
pub fn decrypt_aes_256_cbc(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 || encrypted_data.len() < 16 {
        return Err(CryptoError::DecryptionError);
    }
    let (iv, ciphertext) = encrypted_data.split_at(16);
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let mut buffer = ciphertext.to_vec();

    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionError)?;

    Ok(plaintext.to_vec())
}

/// Hash password with Argon2
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::PasswordHashError(e.to_string()))?;
    Ok(password_hash.to_string())
}

/// Verify password against hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| CryptoError::PasswordHashError(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Derive key using PBKDF2
pub fn derive_key_pbkdf2(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, &mut key);
    key
}

/// ECIES encryption
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

/// ECIES decryption
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
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| CryptoError::DecryptionError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation_and_seed_derivation() {
        let mnemonic = generate_mnemonic().unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        let seed = derive_seed_from_mnemonic(&mnemonic, "").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_signing_key_derivation() {
        let seed = [0u8; 32];
        let key = derive_signing_key(&seed);
        assert!(key.to_bytes().len() == 32);
    }

    #[test]
    fn test_aes_encryption_decryption() {
        let key = [42u8; 32];
        let data = b"Hello Zero Protocol!";
        let encrypted = encrypt_aes_256_cbc(data, &key).unwrap();
        assert_ne!(data.to_vec(), encrypted);
        let decrypted = decrypt_aes_256_cbc(&encrypted, &key).unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_password_hashing() {
        let password = "super_secure_password";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_ecies_encryption_decryption() {
        let recipient_secret = SecretKey::random(&mut OsRng);
        let recipient_pub = recipient_secret.public_key();
        let recipient_pub_bytes = recipient_pub.to_sec1_bytes();
        let data = b"Secret Message";
        let encrypted = encrypt_ecies(&recipient_pub_bytes, data).unwrap();
        assert_ne!(data.to_vec(), encrypted);
        let decrypted = decrypt_ecies(&recipient_secret.to_bytes(), &encrypted).unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_ed25519_signatures() {
        let seed = [1u8; 32];
        let signing_key = derive_signing_key(&seed);
        let verifying_key = signing_key.verifying_key();
        let data = b"Sign this important email";
        let signature = sign_data(&signing_key, data);
        assert!(verify_signature(verifying_key.as_bytes(), data, &signature).is_ok());
        let modified_data = b"Tampered data";
        assert!(verify_signature(verifying_key.as_bytes(), modified_data, &signature).is_err());
    }
}
