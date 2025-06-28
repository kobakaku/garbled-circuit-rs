use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key as AesKey, KeyInit, Nonce};
use rand::Rng;

// Magic bytes for key verification
const MAGIC_BYTES: &[u8] = b"GARB";

// Simplified key type - just a 16-byte array for AES
#[derive(Clone, Debug, PartialEq)]
pub struct Key(pub [u8; 16]);

impl Key {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        Key(key)
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let cipher = Aes128Gcm::new(AesKey::<Aes128Gcm>::from_slice(&self.0));
        let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for simplicity
        cipher.encrypt(nonce, data).unwrap()
    }

    pub fn encrypt_with_magic(&self, data: &[u8]) -> Vec<u8> {
        // Prepend magic bytes to the data before encryption
        let mut data_with_magic = Vec::new();
        data_with_magic.extend_from_slice(MAGIC_BYTES);
        data_with_magic.extend_from_slice(data);

        let cipher = Aes128Gcm::new(AesKey::<Aes128Gcm>::from_slice(&self.0));
        let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for simplicity
        cipher.encrypt(nonce, data_with_magic.as_slice()).unwrap()
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes128Gcm::new(AesKey::<Aes128Gcm>::from_slice(&self.0));
        let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for simplicity
        cipher.decrypt(nonce, data).map_err(|_| "Decryption failed")
    }

    pub fn decrypt_with_magic_verification(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes128Gcm::new(AesKey::<Aes128Gcm>::from_slice(&self.0));
        let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for simplicity

        match cipher.decrypt(nonce, data) {
            Ok(decrypted) => {
                // Verify magic bytes
                if decrypted.len() < MAGIC_BYTES.len() {
                    return Err("Decrypted data too short");
                }

                if &decrypted[0..MAGIC_BYTES.len()] != MAGIC_BYTES {
                    return Err("Invalid magic bytes");
                }

                // Return data without magic bytes
                Ok(decrypted[MAGIC_BYTES.len()..].to_vec())
            }
            Err(_) => Err("Decryption failed"),
        }
    }
}

impl Default for Key {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_creation() {
        let key1 = Key::new();
        let key2 = Key::new();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should have correct length
        assert_eq!(key1.0.len(), 16);
        assert_eq!(key2.0.len(), 16);
    }

    #[test]
    fn test_key_default() {
        let key1 = Key::default();
        let key2 = Key::default();

        // Default keys should be different
        assert_ne!(key1, key2);
        assert_eq!(key1.0.len(), 16);
    }

    #[test]
    fn test_key_encrypt_decrypt() {
        let key = Key::new();
        let data = b"Hello, World!";

        let encrypted = key.encrypt(data);
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_key_encrypt_decrypt_with_magic() {
        let key = Key::new();
        let data = b"Secret message";

        let encrypted = key.encrypt_with_magic(data);
        let decrypted = key.decrypt_with_magic_verification(&encrypted).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_magic_bytes_verification() {
        let key = Key::new();
        let data = b"Test data";

        let encrypted_with_magic = key.encrypt_with_magic(data);
        let encrypted_without_magic = key.encrypt(data);

        // Should succeed with magic bytes
        assert!(key
            .decrypt_with_magic_verification(&encrypted_with_magic)
            .is_ok());

        // Should fail without magic bytes
        assert!(key
            .decrypt_with_magic_verification(&encrypted_without_magic)
            .is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = Key::new();
        let key2 = Key::new();
        let data = b"Secret data";

        let encrypted = key1.encrypt(data);

        // Should fail with wrong key
        assert!(key2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_magic_verification_with_wrong_key() {
        let key1 = Key::new();
        let key2 = Key::new();
        let data = b"Secret data";

        let encrypted = key1.encrypt_with_magic(data);

        // Should fail with wrong key
        assert!(key2.decrypt_with_magic_verification(&encrypted).is_err());
    }

    #[test]
    fn test_empty_data_encryption() {
        let key = Key::new();
        let empty_data = b"";

        let encrypted = key.encrypt(empty_data);
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(empty_data.to_vec(), decrypted);
    }

    #[test]
    fn test_large_data_encryption() {
        let key = Key::new();
        let large_data = vec![42u8; 1000];

        let encrypted = key.encrypt(&large_data);
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(large_data, decrypted);
    }

    #[test]
    fn test_key_equality() {
        let bytes = [1u8; 16];
        let key1 = Key(bytes);
        let key2 = Key(bytes);
        let key3 = Key([2u8; 16]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
