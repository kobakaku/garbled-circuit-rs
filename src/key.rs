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
