use garbled_circuit_rs::{execute_secure_protocol, prepare_party_inputs, Circuit, GarbledCircuit};
use std::env;
use std::path::Path;

fn parse_binary_string(s: &str) -> Result<Vec<u8>, String> {
    s.chars()
        .map(|c| match c {
            '0' => Ok(0),
            '1' => Ok(1),
            _ => Err(format!("Invalid binary digit: {}", c)),
        })
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "Usage: {} <circuit_index> [alice_input] [bob_input] [--ot]",
            args[0]
        );
        eprintln!("  circuit_index: 0-based index of the circuit to evaluate");
        eprintln!("  alice_input: Binary string for Alice's input (e.g., '10' for inputs 1,0)");
        eprintln!("  bob_input: Binary string for Bob's input (e.g., '1' for input 1)");
        eprintln!("  --ot: Use Oblivious Transfer protocol for secure evaluation");
        eprintln!("\nExamples:");
        eprintln!(
            "  {} 0 1 1      # Run circuit 0 with Alice=1, Bob=1 (standard)",
            args[0]
        );
        eprintln!(
            "  {} 0 1 1 --ot # Run circuit 0 with Alice=1, Bob=1 (with OT)",
            args[0]
        );
        std::process::exit(1);
    }

    // Parse circuit index
    let circuit_index: usize = match args[1].parse() {
        Ok(idx) => idx,
        Err(_) => {
            eprintln!("Error: Invalid circuit index '{}'", args[1]);
            std::process::exit(1);
        }
    };

    // Load circuits from JSON file
    let json_path = Path::new("circuits/bool.json");
    let circuits = match Circuit::from_json_file(&json_path) {
        Ok(circuits) => circuits,
        Err(e) => {
            eprintln!("Error: Failed to load {}: {}", json_path.display(), e);
            std::process::exit(1);
        }
    };

    // Check if circuit index is valid
    if circuit_index >= circuits.len() {
        eprintln!(
            "Error: Circuit index {} is out of range. Available circuits: 0-{}",
            circuit_index,
            circuits.len() - 1
        );
        eprintln!("\nAvailable circuits:");
        for (i, circuit) in circuits.iter().enumerate() {
            eprintln!("  {}: {}", i, circuit.id);
        }
        std::process::exit(1);
    }

    let circuit = &circuits[circuit_index];

    // Parse Alice's input if provided
    let alice_input = if args.len() > 2 && &args[2] != "--ot" {
        match parse_binary_string(&args[2]) {
            Ok(bits) => Some(bits),
            Err(e) => {
                eprintln!("Error in Alice's input: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Parse Bob's input if provided
    // Need to check if the argument is --ot flag or actual input
    let bob_input = if args.len() > 3 && &args[3] != "--ot" {
        match parse_binary_string(&args[3]) {
            Ok(bits) => Some(bits),
            Err(e) => {
                eprintln!("Error in Bob's input: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Check if OT flag is provided
    let use_ot = args.iter().any(|arg| arg == "--ot");

    // Evaluate the circuit
    let garbled_circuit = GarbledCircuit::new(circuit.clone());

    // Get input wires
    let empty_vec = vec![];
    let alice_wires = circuit.alice.as_ref().unwrap_or(&empty_vec);
    let bob_wires = circuit.bob.as_ref().unwrap_or(&empty_vec);

    // Prepare inputs for both parties
    let alice_inputs = prepare_party_inputs(&alice_input, alice_wires, "Alice");
    let bob_inputs = prepare_party_inputs(&bob_input, bob_wires, "Bob");

    // Choose evaluation method based on OT flag
    let result = if use_ot {
        execute_secure_protocol(circuit.clone(), alice_inputs, bob_inputs)
    } else {
        garbled_circuit.evaluate(&alice_inputs, &bob_inputs)
    };

    // Print the results
    let bob_wires = circuit.bob.as_ref().unwrap_or(&empty_vec);

    // Print Alice inputs
    if !alice_wires.is_empty() {
        print!("Alice");
        for (i, &wire) in alice_wires.iter().enumerate() {
            if let Some(ref alice_bits) = alice_input {
                print!("[{}]={} ", wire, alice_bits.get(i).unwrap_or(&0));
            }
        }
    }

    // Print Bob inputs
    if !bob_wires.is_empty() {
        print!("Bob");
        for (i, &wire) in bob_wires.iter().enumerate() {
            if let Some(ref bob_bits) = bob_input {
                print!("[{}]={} ", wire, bob_bits.get(i).unwrap_or(&0));
            }
        }
        print!(" ");
    }

    // Print outputs
    print!("Output");
    for &out_wire in &circuit.out {
        print!("[{}]={} ", out_wire, result.get(&out_wire).unwrap_or(&0));
    }
    println!();
}
