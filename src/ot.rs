use crate::key::Key;
use rand::{thread_rng, Rng};
use std::collections::HashMap;

/// Simple 1-out-of-2 Oblivious Transfer implementation
/// This is a simplified educational implementation for demonstration purposes.
/// In production, use elliptic curve cryptography for better security.
#[derive(Clone, Debug)]
pub struct OTSender {
    // For simplicity, we'll use a basic implementation
    // In practice, this would use public key cryptography
    pub messages: Vec<Vec<u8>>,
    pub random_values: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct OTReceiver {
    pub choice_bit: u8,
    pub received_message: Option<Vec<u8>>,
}

impl OTSender {
    /// Create a new OT sender with two messages
    pub fn new(message0: Vec<u8>, message1: Vec<u8>) -> Self {
        let mut rng = thread_rng();
        OTSender {
            messages: vec![message0, message1],
            random_values: vec![rng.gen(), rng.gen()],
        }
    }

    /// Phase 1: Send encrypted messages to receiver
    /// In a real implementation, this would use public key encryption
    pub fn send_encrypted_messages(&self) -> Vec<Vec<u8>> {
        let mut encrypted_messages = Vec::new();

        for (i, message) in self.messages.iter().enumerate() {
            // Simple XOR encryption with random value (insecure - for demonstration only)
            let mut encrypted = Vec::new();
            let random_bytes = self.random_values[i].to_le_bytes();

            for (j, &byte) in message.iter().enumerate() {
                encrypted.push(byte ^ random_bytes[j % 8]);
            }
            encrypted_messages.push(encrypted);
        }

        encrypted_messages
    }

    /// Phase 2: Send decryption key for chosen message
    pub fn send_decryption_key(&self, choice: u8) -> u64 {
        if choice == 0 || choice == 1 {
            self.random_values[choice as usize]
        } else {
            panic!("Invalid choice bit: {}", choice);
        }
    }
}

impl OTReceiver {
    /// Create a new OT receiver with a choice bit
    pub fn new(choice_bit: u8) -> Self {
        if choice_bit != 0 && choice_bit != 1 {
            panic!("Choice bit must be 0 or 1, got: {}", choice_bit);
        }

        OTReceiver {
            choice_bit,
            received_message: None,
        }
    }

    /// Phase 1: Receive encrypted messages but can't decrypt yet
    pub fn receive_encrypted_messages(&mut self, encrypted_messages: Vec<Vec<u8>>) {
        // Store the encrypted messages, but can't decrypt without the key
        // In practice, the receiver would only receive the message they can decrypt
        self.received_message = Some(encrypted_messages[self.choice_bit as usize].clone());
    }

    /// Phase 2: Decrypt the chosen message using the provided key
    pub fn decrypt_message(&mut self, decryption_key: u64) -> Vec<u8> {
        if let Some(encrypted_message) = &self.received_message {
            let mut decrypted = Vec::new();
            let key_bytes = decryption_key.to_le_bytes();

            for (i, &byte) in encrypted_message.iter().enumerate() {
                decrypted.push(byte ^ key_bytes[i % 8]);
            }

            decrypted
        } else {
            panic!("No encrypted message received");
        }
    }
}

/// Simplified OT protocol for garbled circuits
/// This demonstrates the concept but lacks the security of a real OT implementation
pub fn perform_ot_protocol(
    alice_wires: &[u32],
    alice_inputs: &HashMap<u32, u8>,
    keys: &HashMap<u32, (Key, Key)>,
) -> HashMap<u32, Key> {
    let mut selected_keys = HashMap::new();

    for &wire_id in alice_wires {
        if let (Some(&input_bit), Some((key0, key1))) =
            (alice_inputs.get(&wire_id), keys.get(&wire_id))
        {
            // Alice selects the key corresponding to her input
            let selected_key = if input_bit == 0 { key0 } else { key1 };
            selected_keys.insert(wire_id, selected_key.clone());
        }
    }

    selected_keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ot() {
        let message0 = b"Hello Alice".to_vec();
        let message1 = b"Hello Bob!!".to_vec();

        let sender = OTSender::new(message0.clone(), message1.clone());
        let mut receiver = OTReceiver::new(1); // Choose message 1

        let encrypted_messages = sender.send_encrypted_messages();
        receiver.receive_encrypted_messages(encrypted_messages);

        let decryption_key = sender.send_decryption_key(1);
        let decrypted = receiver.decrypt_message(decryption_key);

        assert_eq!(decrypted, message1);
    }

    #[test]
    fn test_ot_with_keys() {
        let key0 = Key::new();
        let key1 = Key::new();

        let sender = OTSender::new(key0.0.to_vec(), key1.0.to_vec());
        let mut receiver = OTReceiver::new(0); // Choose key0

        let encrypted_messages = sender.send_encrypted_messages();
        receiver.receive_encrypted_messages(encrypted_messages);

        let decryption_key = sender.send_decryption_key(0);
        let decrypted = receiver.decrypt_message(decryption_key);

        assert_eq!(decrypted, key0.0.to_vec());
    }
}
