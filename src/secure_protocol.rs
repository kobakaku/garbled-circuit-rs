use crate::circuit::Circuit;
use crate::garbled::GarbledCircuit;
use crate::key::Key;
use crate::ot::{OTReceiver, OTSender};
use std::collections::HashMap;

// AES key size in bytes
const AES_KEY_SIZE: usize = 16;

/// Alice's side of the garbled circuit protocol
pub struct Alice {
    pub circuit: Circuit,
    pub garbled_circuit: GarbledCircuit,
    pub inputs: HashMap<u32, u8>,
}

/// Bob's side of the garbled circuit protocol  
pub struct Bob {
    pub inputs: HashMap<u32, u8>,
    pub received_keys: HashMap<u32, Key>,
}

impl Alice {
    pub fn new(circuit: Circuit, inputs: HashMap<u32, u8>) -> Self {
        let garbled_circuit = GarbledCircuit::new(circuit.clone());
        Alice {
            circuit,
            garbled_circuit,
            inputs,
        }
    }

    /// Alice prepares the garbled circuit and sends it to Bob
    pub fn send_garbled_circuit(&self) -> GarbledCircuit {
        // In a real implementation, this would be sent over the network
        self.garbled_circuit.clone()
    }

    /// Alice sets up OT senders for her input wires
    pub fn setup_ot_for_inputs(&self) -> HashMap<u32, OTSender> {
        let mut ot_senders = HashMap::new();

        if let Some(ref alice_wires) = self.circuit.alice {
            for &wire_id in alice_wires {
                if let Some((key0, key1)) = self.garbled_circuit.get_all_keys().get(&wire_id) {
                    let sender = OTSender::new(key0.0.to_vec(), key1.0.to_vec());
                    ot_senders.insert(wire_id, sender);
                }
            }
        }

        ot_senders
    }

    /// Alice sends OT keys to Bob based on her actual inputs
    /// In reality, this would use cryptographic OT where Alice doesn't know which key Bob receives
    pub fn send_ot_keys(&self, ot_senders: &HashMap<u32, OTSender>) -> HashMap<u32, Key> {
        let mut keys_for_bob = HashMap::new();

        if let Some(ref alice_wires) = self.circuit.alice {
            for &wire_id in alice_wires {
                if let (Some(&alice_bit), Some(sender)) =
                    (self.inputs.get(&wire_id), ot_senders.get(&wire_id))
                {
                    // Alice sends the key corresponding to her input bit via OT
                    // In real OT, Bob would only be able to decrypt one of the two keys
                    let encrypted_messages = sender.send_encrypted_messages();
                    let decryption_key = sender.send_decryption_key(alice_bit);

                    // Simulate Bob receiving and decrypting the key
                    let mut receiver = OTReceiver::new(alice_bit); // In reality, Bob chooses this
                    receiver.receive_encrypted_messages(encrypted_messages);
                    let decrypted_key_bytes = receiver.decrypt_message(decryption_key);

                    if decrypted_key_bytes.len() >= AES_KEY_SIZE {
                        let mut key_array = [0u8; AES_KEY_SIZE];
                        key_array.copy_from_slice(&decrypted_key_bytes[0..AES_KEY_SIZE]);
                        keys_for_bob.insert(wire_id, Key(key_array));
                    }
                }
            }
        }

        keys_for_bob
    }
}

impl Bob {
    pub fn new(inputs: HashMap<u32, u8>) -> Self {
        Bob {
            inputs,
            received_keys: HashMap::new(),
        }
    }

    /// Bob receives keys from Alice via OT (for Alice's input wires)
    pub fn receive_ot_keys(&mut self, alice_keys: HashMap<u32, Key>) {
        self.received_keys.extend(alice_keys);
    }

    /// Bob selects his own input keys from the garbled circuit
    pub fn select_own_input_keys(&mut self, garbled_circuit: &GarbledCircuit) {
        if let Some(ref bob_wires) = garbled_circuit.circuit.bob {
            for &wire_id in bob_wires {
                if let Some(&bob_bit) = self.inputs.get(&wire_id) {
                    let keys = garbled_circuit.get_all_keys();
                    if let Some((key0, key1)) = keys.get(&wire_id) {
                        let selected_key = if bob_bit == 0 { key0 } else { key1 };
                        self.received_keys.insert(wire_id, selected_key.clone());
                    }
                }
            }
        }
    }

    /// Bob evaluates the garbled circuit using the keys he has
    pub fn evaluate_circuit(&self, garbled_circuit: &GarbledCircuit) -> HashMap<u32, u8> {
        // Use the shared evaluation logic from GarbledCircuit
        let final_wire_values = garbled_circuit.evaluate_gates(self.received_keys.clone());
        garbled_circuit.extract_outputs(&final_wire_values)
    }
}

/// Execute the complete two-party protocol
pub fn execute_secure_protocol(
    circuit: Circuit,
    alice_inputs: HashMap<u32, u8>,
    bob_inputs: HashMap<u32, u8>,
) -> HashMap<u32, u8> {
    // Alice's side
    let alice = Alice::new(circuit, alice_inputs);
    let garbled_circuit = alice.send_garbled_circuit();
    let ot_senders = alice.setup_ot_for_inputs();
    let alice_keys_for_bob = alice.send_ot_keys(&ot_senders);

    // Bob's side
    let mut bob = Bob::new(bob_inputs);
    bob.receive_ot_keys(alice_keys_for_bob);
    bob.select_own_input_keys(&garbled_circuit);

    // Bob evaluates the circuit
    bob.evaluate_circuit(&garbled_circuit)
}
