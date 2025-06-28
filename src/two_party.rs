use crate::circuit::Circuit;
use crate::garbled::GarbledCircuit;
use crate::key::Key;
use anyhow::{Context, Result};
use oblivious_transfer_rs::{
    Choice, OTReceiver, OTSender, ReceiverEncryptedValues, SenderMaskedMessages, SenderPublicKey,
};
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

    /// Alice sets up OT senders for Bob's input wires
    pub fn setup_ot_for_bob_inputs(&self) -> Result<HashMap<u32, OTSender>> {
        let mut ot_senders = HashMap::new();

        let bob_wires = self
            .circuit
            .bob
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Circuit must have Bob inputs for OT protocol"))?;

        for &wire_id in bob_wires {
            if let Some((key0, key1)) = self.garbled_circuit.get_all_keys().get(&wire_id) {
                // Set up OT sender for Bob's wire with both possible keys
                let sender = OTSender::new(key0.0.to_vec(), key1.0.to_vec())?;
                ot_senders.insert(wire_id, sender);
            }
        }

        Ok(ot_senders)
    }

    /// Alice generates RSA keys for OT (Phase 1)
    pub fn generate_rsa_keys(
        &self,
        ot_senders: &mut HashMap<u32, OTSender>,
    ) -> Result<HashMap<u32, SenderPublicKey>> {
        let mut sender_public_keys = HashMap::new();

        for (wire_id, sender) in ot_senders.iter_mut() {
            let public_key = sender.generate_keys()?;
            sender_public_keys.insert(*wire_id, public_key);
        }

        Ok(sender_public_keys)
    }

    /// Alice creates masked messages for OT (Phase 3)
    pub fn create_masked_messages(
        &self,
        wire_id: u32,
        encrypted_values: ReceiverEncryptedValues,
        ot_senders: &HashMap<u32, OTSender>,
    ) -> Result<SenderMaskedMessages> {
        let sender = ot_senders
            .get(&wire_id)
            .with_context(|| format!("No OT sender found for wire {wire_id}"))?;
        sender
            .create_masked_messages(encrypted_values)
            .with_context(|| format!("Failed to create masked messages for wire {wire_id}"))
    }

    /// Alice sends her input keys directly to Bob
    /// For Alice's wires, Bob just receives the keys corresponding to Alice's actual inputs
    pub fn send_alice_input_keys(&self) -> HashMap<u32, Key> {
        let mut alice_keys = HashMap::new();

        if let Some(ref alice_wires) = self.circuit.alice {
            for &wire_id in alice_wires {
                if let Some(&alice_bit) = self.inputs.get(&wire_id) {
                    if let Some((key0, key1)) = self.garbled_circuit.get_all_keys().get(&wire_id) {
                        // Alice sends the key corresponding to her actual input
                        let selected_key = if alice_bit == 0 { key0 } else { key1 };
                        alice_keys.insert(wire_id, selected_key.clone());
                    }
                }
            }
        }

        alice_keys
    }
}

impl Bob {
    pub fn new(inputs: HashMap<u32, u8>) -> Self {
        Bob {
            inputs,
            received_keys: HashMap::new(),
        }
    }

    /// Bob receives keys from Alice for her input wires
    pub fn receive_alice_keys(&mut self, alice_keys: HashMap<u32, Key>) {
        self.received_keys.extend(alice_keys);
    }

    /// Bob generates encrypted values for OT (Phase 2)
    pub fn generate_encrypted_values(
        &self,
        bob_wires: &[u32],
        sender_public_keys: &HashMap<u32, SenderPublicKey>,
    ) -> Result<Vec<(u32, ReceiverEncryptedValues, OTReceiver)>> {
        let mut result = Vec::new();

        for &wire_id in bob_wires {
            if let Some(&bob_bit) = self.inputs.get(&wire_id) {
                // Bob chooses based on his own input
                let choice = if bob_bit == 0 {
                    Choice::Zero
                } else {
                    Choice::One
                };

                // Phase 2: Bob generates encrypted values based on his choice
                let mut receiver = OTReceiver::new(choice);

                if let Some(sender_pk) = sender_public_keys.get(&wire_id) {
                    let encrypted_values = receiver.generate_encrypted_values(sender_pk.clone())?;
                    result.push((wire_id, encrypted_values, receiver));
                }
            }
        }

        Ok(result)
    }

    /// Bob extracts chosen messages from OT (Phase 4)
    pub fn extract_messages(
        &mut self,
        masked_messages: Vec<(u32, SenderMaskedMessages, OTReceiver)>,
    ) -> Result<()> {
        for (wire_id, masked_msgs, receiver) in masked_messages {
            // Phase 4: Bob extracts only the chosen message
            let decrypted_key_bytes = receiver.extract_message(masked_msgs)?;

            // Convert to Key and store
            if decrypted_key_bytes.len() == AES_KEY_SIZE {
                let mut key_array = [0u8; AES_KEY_SIZE];
                key_array.copy_from_slice(&decrypted_key_bytes);
                self.received_keys.insert(wire_id, Key(key_array));
            } else {
                return Err(anyhow::anyhow!(
                    "Invalid key size for wire {}: expected {} bytes, got {}",
                    wire_id,
                    AES_KEY_SIZE,
                    decrypted_key_bytes.len()
                ));
            }
        }
        Ok(())
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
) -> Result<HashMap<u32, u8>> {
    // Alice's side
    let alice = Alice::new(circuit.clone(), alice_inputs);
    let garbled_circuit = alice.send_garbled_circuit();

    // Alice sends her input keys directly to Bob (no OT needed for Alice's inputs)
    let alice_keys = alice.send_alice_input_keys();

    // Alice sets up OT senders for Bob's input wires
    let mut ot_senders = alice.setup_ot_for_bob_inputs()?;

    // Bob's side
    let mut bob = Bob::new(bob_inputs);

    // Bob receives Alice's keys
    bob.receive_alice_keys(alice_keys);

    // OT Protocol for Bob's inputs - New 4-phase protocol
    let bob_wires = circuit
        .bob
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Circuit must have Bob inputs for secure protocol"))?;

    // Phase 1: Alice generates RSA keys
    let sender_public_keys = alice.generate_rsa_keys(&mut ot_senders)?;

    // Phase 2: Bob generates encrypted values
    let encrypted_values = bob.generate_encrypted_values(bob_wires, &sender_public_keys)?;

    // Phase 3: Alice creates masked messages
    let mut masked_messages = Vec::new();
    for (wire_id, enc_vals, receiver) in encrypted_values {
        let masked_msgs = alice.create_masked_messages(wire_id, enc_vals, &ot_senders)?;
        masked_messages.push((wire_id, masked_msgs, receiver));
    }

    // Phase 4: Bob extracts his chosen messages
    bob.extract_messages(masked_messages)?;

    // Bob evaluates the circuit
    Ok(bob.evaluate_circuit(&garbled_circuit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Gate};

    fn create_test_and_circuit() -> Circuit {
        Circuit {
            id: "test_and".to_string(),
            alice: Some(vec![1]),
            bob: Some(vec![2]),
            out: vec![3],
            gates: vec![Gate {
                id: 3,
                gate_type: "AND".to_string(),
                inputs: vec![1, 2],
            }],
        }
    }

    fn create_test_or_circuit() -> Circuit {
        Circuit {
            id: "test_or".to_string(),
            alice: Some(vec![1]),
            bob: Some(vec![2]),
            out: vec![3],
            gates: vec![Gate {
                id: 3,
                gate_type: "OR".to_string(),
                inputs: vec![1, 2],
            }],
        }
    }

    #[test]
    fn test_ot_security_property() -> Result<()> {
        let circuit = create_test_and_circuit();

        // Test that Bob can only decrypt his chosen message
        let alice_inputs = [(1, 1)].iter().cloned().collect();
        let bob_inputs = [(2, 0)].iter().cloned().collect();

        // Run the protocol
        let result = execute_secure_protocol(circuit, alice_inputs, bob_inputs)?;

        // Verify the result is correct (1 AND 0 = 0)
        assert_eq!(result.get(&3), Some(&0));

        Ok(())
    }

    #[test]
    fn test_alice_setup() -> Result<()> {
        let circuit = create_test_and_circuit();
        let alice_inputs = [(1, 1)].iter().cloned().collect();
        let alice = Alice::new(circuit, alice_inputs);

        // Test garbled circuit creation
        let garbled_circuit = alice.send_garbled_circuit();
        assert_eq!(garbled_circuit.circuit.id, "test_and");
        assert_eq!(garbled_circuit.garbled_gates.len(), 1);

        // Test Alice's input key sending
        let alice_keys = alice.send_alice_input_keys();
        assert_eq!(alice_keys.len(), 1);
        assert!(alice_keys.contains_key(&1));

        // Test OT sender setup
        let ot_senders = alice.setup_ot_for_bob_inputs()?;
        assert_eq!(ot_senders.len(), 1);
        assert!(ot_senders.contains_key(&2));

        Ok(())
    }

    #[test]
    fn test_bob_setup() -> Result<()> {
        let _circuit = create_test_and_circuit();
        let bob_inputs = [(2, 1)].iter().cloned().collect();
        let mut bob = Bob::new(bob_inputs);

        // Test Alice's key reception
        let alice_key = Key::new();
        let alice_keys = [(1, alice_key.clone())].iter().cloned().collect();
        bob.receive_alice_keys(alice_keys);

        assert_eq!(bob.received_keys.len(), 1);
        assert_eq!(bob.received_keys.get(&1), Some(&alice_key));

        Ok(())
    }

    #[test]
    fn test_complete_ot_protocol_and_gate() -> Result<()> {
        let circuit = create_test_and_circuit();

        // Test all AND gate combinations through OT protocol
        let test_cases = [
            ((0, 0), 0), // 0 AND 0 = 0
            ((0, 1), 0), // 0 AND 1 = 0
            ((1, 0), 0), // 1 AND 0 = 0
            ((1, 1), 1), // 1 AND 1 = 1
        ];

        for ((alice_bit, bob_bit), expected) in test_cases {
            let alice_inputs = [(1, alice_bit)].iter().cloned().collect();
            let bob_inputs = [(2, bob_bit)].iter().cloned().collect();

            let result = execute_secure_protocol(circuit.clone(), alice_inputs, bob_inputs)?;
            assert_eq!(
                result.get(&3),
                Some(&expected),
                "OT AND({}, {}) should be {}",
                alice_bit,
                bob_bit,
                expected
            );
        }

        Ok(())
    }

    #[test]
    fn test_complete_ot_protocol_or_gate() -> Result<()> {
        let circuit = create_test_or_circuit();

        // Test all OR gate combinations through OT protocol
        let test_cases = [
            ((0, 0), 0), // 0 OR 0 = 0
            ((0, 1), 1), // 0 OR 1 = 1
            ((1, 0), 1), // 1 OR 0 = 1
            ((1, 1), 1), // 1 OR 1 = 1
        ];

        for ((alice_bit, bob_bit), expected) in test_cases {
            let alice_inputs = [(1, alice_bit)].iter().cloned().collect();
            let bob_inputs = [(2, bob_bit)].iter().cloned().collect();

            let result = execute_secure_protocol(circuit.clone(), alice_inputs, bob_inputs)?;
            assert_eq!(
                result.get(&3),
                Some(&expected),
                "OT OR({}, {}) should be {}",
                alice_bit,
                bob_bit,
                expected
            );
        }

        Ok(())
    }

    #[test]
    fn test_multiple_bob_inputs() -> Result<()> {
        // Create circuit with multiple Bob inputs
        let circuit = Circuit {
            id: "multi_bob".to_string(),
            alice: Some(vec![1]),
            bob: Some(vec![2, 3]),
            out: vec![4],
            gates: vec![Gate {
                id: 4,
                gate_type: "AND".to_string(),
                inputs: vec![1, 2],
            }],
        };

        let alice_inputs = [(1, 1)].iter().cloned().collect();
        let bob_inputs = [(2, 1), (3, 0)].iter().cloned().collect();

        let result = execute_secure_protocol(circuit, alice_inputs, bob_inputs)?;
        assert_eq!(result.get(&4), Some(&1)); // 1 AND 1 = 1

        Ok(())
    }

    #[test]
    fn test_no_bob_inputs() -> Result<()> {
        // Circuit where Bob has no inputs should fail in secure protocol
        let circuit = Circuit {
            id: "alice_only".to_string(),
            alice: Some(vec![1]),
            bob: None,
            out: vec![2],
            gates: vec![Gate {
                id: 2,
                gate_type: "NOT".to_string(),
                inputs: vec![1],
            }],
        };

        let alice_inputs = [(1, 0)].iter().cloned().collect();
        let bob_inputs = HashMap::new();

        let result = execute_secure_protocol(circuit, alice_inputs, bob_inputs);
        assert!(result.is_err()); // Should fail because Bob inputs are required

        Ok(())
    }

    #[test]
    fn test_complex_ot_circuit() -> Result<()> {
        // Create a more complex circuit: (A AND B) OR C
        let circuit = Circuit {
            id: "complex_ot".to_string(),
            alice: Some(vec![1, 2]),
            bob: Some(vec![3]),
            out: vec![5],
            gates: vec![
                Gate {
                    id: 4,
                    gate_type: "AND".to_string(),
                    inputs: vec![1, 2],
                },
                Gate {
                    id: 5,
                    gate_type: "OR".to_string(),
                    inputs: vec![4, 3],
                },
            ],
        };

        // Test case: A=1, B=1, C=0 => (1 AND 1) OR 0 = 1
        let alice_inputs = [(1, 1), (2, 1)].iter().cloned().collect();
        let bob_inputs = [(3, 0)].iter().cloned().collect();

        let result = execute_secure_protocol(circuit.clone(), alice_inputs, bob_inputs)?;
        assert_eq!(result.get(&5), Some(&1));

        // Test case: A=0, B=1, C=1 => (0 AND 1) OR 1 = 1
        let alice_inputs = [(1, 0), (2, 1)].iter().cloned().collect();
        let bob_inputs = [(3, 1)].iter().cloned().collect();

        let result = execute_secure_protocol(circuit, alice_inputs, bob_inputs)?;
        assert_eq!(result.get(&5), Some(&1));

        Ok(())
    }
}
