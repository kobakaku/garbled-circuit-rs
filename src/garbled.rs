use crate::circuit::{Circuit, Gate};
use crate::key::Key;
use std::collections::HashMap;

// AES key size in bytes
const AES_KEY_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct GarbledGate {
    pub id: u32,
    pub gate_type: String,
    pub inputs: Vec<u32>,
    pub garbled_table: HashMap<Vec<u8>, Vec<u8>>,
}

impl GarbledGate {
    pub fn new(gate: &Gate, keys: &HashMap<u32, (Key, Key)>) -> Self {
        let mut garbled_gate = GarbledGate {
            id: gate.id,
            gate_type: gate.gate_type.clone(),
            inputs: gate.inputs.clone(),
            garbled_table: HashMap::new(),
        };

        match gate.gate_type.as_str() {
            "AND" => garbled_gate.create_and_table(keys),
            "OR" => garbled_gate.create_or_table(keys),
            "NOT" => garbled_gate.create_not_table(keys),
            _ => panic!("Unsupported gate type: {}", gate.gate_type),
        }

        garbled_gate
    }

    fn create_binary_gate_table<F>(&mut self, keys: &HashMap<u32, (Key, Key)>, truth_table: F)
    where
        F: Fn(u8, u8) -> u8,
    {
        let in_a = self.inputs[0];
        let in_b = self.inputs[1];
        let output_keys = keys.get(&self.id).unwrap();

        for a_bit in 0..2 {
            for b_bit in 0..2 {
                let result_bit = truth_table(a_bit, b_bit);

                let key_a = if a_bit == 0 {
                    &keys[&in_a].0
                } else {
                    &keys[&in_a].1
                };
                let key_b = if b_bit == 0 {
                    &keys[&in_b].0
                } else {
                    &keys[&in_b].1
                };
                let output_key = if result_bit == 0 {
                    &output_keys.0
                } else {
                    &output_keys.1
                };

                // Encrypt output key with both input keys using magic bytes
                let encrypted_once = key_a.encrypt_with_magic(&output_key.0);
                let encrypted_twice = key_b.encrypt_with_magic(&encrypted_once);

                let index = vec![a_bit, b_bit];
                self.garbled_table.insert(index, encrypted_twice);
            }
        }
    }

    fn create_and_table(&mut self, keys: &HashMap<u32, (Key, Key)>) {
        // Truth table for AND: 00->0, 01->0, 10->0, 11->1
        self.create_binary_gate_table(keys, |a, b| if a == 1 && b == 1 { 1 } else { 0 });
    }

    fn create_or_table(&mut self, keys: &HashMap<u32, (Key, Key)>) {
        // Truth table for OR: 00->0, 01->1, 10->1, 11->1
        self.create_binary_gate_table(keys, |a, b| if a == 1 || b == 1 { 1 } else { 0 });
    }

    fn create_not_table(&mut self, keys: &HashMap<u32, (Key, Key)>) {
        let input_wire = self.inputs[0];
        let output_keys = keys.get(&self.id).unwrap();

        // Truth table for NOT: 0->1, 1->0
        for bit in 0..2 {
            let result_bit = 1 - bit;

            let input_key = if bit == 0 {
                &keys[&input_wire].0
            } else {
                &keys[&input_wire].1
            };
            let output_key = if result_bit == 0 {
                &output_keys.0
            } else {
                &output_keys.1
            };

            let encrypted = input_key.encrypt_with_magic(&output_key.0);

            let index = vec![bit];
            self.garbled_table.insert(index, encrypted);
        }
    }
}

#[derive(Clone, Debug)]
pub struct GarbledCircuit {
    pub circuit: Circuit,
    pub keys: HashMap<u32, (Key, Key)>,
    pub garbled_gates: Vec<GarbledGate>,
}

impl GarbledCircuit {
    pub fn new(circuit: Circuit) -> Self {
        let mut keys = HashMap::new();

        // Generate keys for all wires
        let mut all_wires = std::collections::HashSet::new();
        for gate in &circuit.gates {
            all_wires.insert(gate.id);
            for &input in &gate.inputs {
                all_wires.insert(input);
            }
        }

        for wire in all_wires {
            keys.insert(wire, (Key::new(), Key::new()));
        }

        // Create garbled gates
        let mut garbled_gates = Vec::new();
        for gate in &circuit.gates {
            garbled_gates.push(GarbledGate::new(gate, &keys));
        }

        GarbledCircuit {
            circuit,
            keys,
            garbled_gates,
        }
    }

    /// Evaluate all gates given initial wire values
    pub fn evaluate_gates(&self, mut wire_values: HashMap<u32, Key>) -> HashMap<u32, Key> {
        // Evaluate gates in order
        for gate in &self.garbled_gates {
            match gate.gate_type.as_str() {
                "NOT" => {
                    let input_key = wire_values[&gate.inputs[0]].clone();

                    // Try both possible input values to find the correct one
                    for bit in 0..2 {
                        let index = vec![bit];
                        if let Some(encrypted) = gate.garbled_table.get(&index) {
                            if let Ok(decrypted) =
                                input_key.decrypt_with_magic_verification(encrypted)
                            {
                                if decrypted.len() >= AES_KEY_SIZE {
                                    let mut key_bytes = [0u8; AES_KEY_SIZE];
                                    key_bytes.copy_from_slice(&decrypted[0..AES_KEY_SIZE]);
                                    wire_values.insert(gate.id, Key(key_bytes));
                                    break;
                                }
                            }
                        }
                    }
                }
                "AND" | "OR" => {
                    let key_a = wire_values[&gate.inputs[0]].clone();
                    let key_b = wire_values[&gate.inputs[1]].clone();

                    // Try all possible input combinations
                    let mut found = false;
                    for a_bit in 0..2 {
                        for b_bit in 0..2 {
                            let index = vec![a_bit, b_bit];
                            if let Some(encrypted_twice) = gate.garbled_table.get(&index) {
                                if let Ok(encrypted_once) =
                                    key_b.decrypt_with_magic_verification(encrypted_twice)
                                {
                                    if let Ok(decrypted) =
                                        key_a.decrypt_with_magic_verification(&encrypted_once)
                                    {
                                        if decrypted.len() >= AES_KEY_SIZE {
                                            let mut key_bytes = [0u8; AES_KEY_SIZE];
                                            key_bytes.copy_from_slice(&decrypted[0..AES_KEY_SIZE]);
                                            wire_values.insert(gate.id, Key(key_bytes));
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if found {
                            break;
                        }
                    }
                }
                _ => panic!("Unsupported gate type: {}", gate.gate_type),
            }
        }

        wire_values
    }

    /// Determine output values from final wire keys
    pub fn extract_outputs(&self, wire_values: &HashMap<u32, Key>) -> HashMap<u32, u8> {
        let mut results = HashMap::new();
        for &output_wire in &self.circuit.out {
            if let Some(result_key) = wire_values.get(&output_wire) {
                let output_keys = &self.keys[&output_wire];
                if result_key == &output_keys.0 {
                    results.insert(output_wire, 0);
                } else if result_key == &output_keys.1 {
                    results.insert(output_wire, 1);
                } else {
                    panic!("Unable to determine output for wire {output_wire}");
                }
            }
        }
        results
    }

    /// Get keys for debugging purposes (not secure in real protocol)
    pub fn get_all_keys(&self) -> &HashMap<u32, (Key, Key)> {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Gate};

    fn create_test_and_circuit() -> Circuit {
        Circuit {
            id: "test_and".to_string(),
            gates: vec![Gate {
                id: 3,
                gate_type: "AND".to_string(),
                inputs: vec![1, 2],
            }],
            alice: Some(vec![1]),
            bob: Some(vec![2]),
            out: vec![3],
        }
    }

    #[test]
    fn test_garbled_circuit_creation() {
        let circuit = create_test_and_circuit();
        let garbled_circuit = GarbledCircuit::new(circuit.clone());

        assert_eq!(garbled_circuit.circuit.id, "test_and");
        assert_eq!(garbled_circuit.garbled_gates.len(), 1);
        assert_eq!(garbled_circuit.garbled_gates[0].gate_type, "AND");

        // Should have keys for all wires (1, 2, 3)
        assert!(garbled_circuit.keys.contains_key(&1));
        assert!(garbled_circuit.keys.contains_key(&2));
        assert!(garbled_circuit.keys.contains_key(&3));
    }

    #[test]
    fn test_garbled_gate_table_creation() {
        let circuit = create_test_and_circuit();
        let garbled_circuit = GarbledCircuit::new(circuit);

        let garbled_gate = &garbled_circuit.garbled_gates[0];

        // AND gate should have 4 entries in garbled table (2^2 combinations)
        assert_eq!(garbled_gate.garbled_table.len(), 4);

        // Check that all possible input combinations exist
        for a in 0..2 {
            for b in 0..2 {
                let index = vec![a, b];
                assert!(garbled_gate.garbled_table.contains_key(&index));
            }
        }
    }

    #[test]
    fn test_wire_key_consistency() {
        let circuit = create_test_and_circuit();
        let garbled_circuit = GarbledCircuit::new(circuit);

        // Get all keys
        let keys = garbled_circuit.get_all_keys();

        // Each wire should have exactly 2 keys (for 0 and 1)
        for (wire_id, (key0, key1)) in keys {
            assert_ne!(key0, key1, "Keys for wire {} should be different", wire_id);
            assert_eq!(key0.0.len(), 16, "Key should be 16 bytes");
            assert_eq!(key1.0.len(), 16, "Key should be 16 bytes");
        }
    }
}
