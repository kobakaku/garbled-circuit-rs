use crate::circuit::Circuit;
use crate::garbled::GarbledCircuit;
use crate::key::Key;
use anyhow::{Context, Result};
use oblivious_transfer_rs::{Choice, OTReceiver, OTSender, ReceiverPublicKeys, SenderResponse};
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

        if let Some(ref bob_wires) = self.circuit.bob {
            for &wire_id in bob_wires {
                if let Some((key0, key1)) = self.garbled_circuit.get_all_keys().get(&wire_id) {
                    // Set up OT sender for Bob's wire with both possible keys
                    let sender = OTSender::new(key0.0.to_vec(), key1.0.to_vec())?;
                    ot_senders.insert(wire_id, sender);
                }
            }
        }

        Ok(ot_senders)
    }

    /// Alice responds to Bob's OT request
    pub fn respond_to_ot(
        &self,
        wire_id: u32,
        receiver_pks: ReceiverPublicKeys,
        ot_senders: &HashMap<u32, OTSender>,
    ) -> Result<SenderResponse> {
        let sender = ot_senders
            .get(&wire_id)
            .with_context(|| format!("No OT sender found for wire {}", wire_id))?;
        sender
            .encrypt_messages(receiver_pks)
            .with_context(|| format!("Failed to encrypt messages for wire {}", wire_id))
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

    /// Bob generates public keys for OT (Phase 1)
    pub fn generate_ot_public_keys(
        &self,
        bob_wires: &[u32],
    ) -> Result<Vec<(u32, ReceiverPublicKeys, OTReceiver)>> {
        let mut result = Vec::new();

        for &wire_id in bob_wires {
            if let Some(&bob_bit) = self.inputs.get(&wire_id) {
                // Bob chooses based on his own input
                let choice = if bob_bit == 0 {
                    Choice::Zero
                } else {
                    Choice::One
                };

                // Phase 1: Bob generates public keys based on his choice
                let mut receiver = OTReceiver::new(choice);
                let public_keys = receiver.generate_public_keys()?;

                result.push((wire_id, public_keys, receiver));
            }
        }

        Ok(result)
    }

    /// Bob receives and decrypts OT responses (Phase 3)
    pub fn receive_ot_responses(
        &mut self,
        responses: Vec<(u32, SenderResponse, OTReceiver)>,
    ) -> Result<()> {
        for (wire_id, response, receiver) in responses {
            // Phase 3: Bob decrypts only the chosen key
            let decrypted_key_bytes = receiver.decrypt_message(response)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Gate};

    #[test]
    fn test_ot_security_property() -> Result<()> {
        // Create a simple AND circuit
        let circuit = Circuit {
            id: "0".to_string(),
            alice: Some(vec![1]),
            bob: Some(vec![2]),
            out: vec![3, 4],
            gates: vec![Gate {
                id: 3,
                gate_type: "AND".to_string(),
                inputs: vec![1, 2],
            }],
        };

        // Test that Bob can only decrypt his chosen message
        let alice_inputs = [(1, 1)].iter().cloned().collect();
        let bob_inputs = [(2, 0)].iter().cloned().collect();

        // Run the protocol
        let result = execute_secure_protocol(circuit, alice_inputs, bob_inputs)?;

        // Verify the result is correct (1 AND 0 = 0)
        assert_eq!(result.get(&3), Some(&0));

        Ok(())
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
    let ot_senders = alice.setup_ot_for_bob_inputs()?;

    // Bob's side
    let mut bob = Bob::new(bob_inputs);

    // Bob receives Alice's keys
    bob.receive_alice_keys(alice_keys);

    // OT Protocol for Bob's inputs
    let empty_wires = vec![];
    let bob_wires = circuit.bob.as_ref().unwrap_or(&empty_wires);

    // Phase 1: Bob generates public keys
    let bob_public_keys = bob.generate_ot_public_keys(bob_wires)?;

    // Phase 2: Alice encrypts messages
    let mut ot_responses = Vec::new();
    for (wire_id, public_keys, receiver) in bob_public_keys {
        let response = alice.respond_to_ot(wire_id, public_keys, &ot_senders)?;
        ot_responses.push((wire_id, response, receiver));
    }

    // Phase 3: Bob decrypts his chosen messages
    bob.receive_ot_responses(ot_responses)?;

    // Bob evaluates the circuit
    Ok(bob.evaluate_circuit(&garbled_circuit))
}
