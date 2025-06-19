# Garbled Circuit Implementation in Rust

This is a simplified implementation of Yao's Garbled Circuit protocol in Rust, designed for educational purposes and proof-of-concept demonstrations.

## Generation and References

This code was generated with [Claude Code](https://claude.ai/code) 🤖

This implementation is based on and references the following repository:
- https://github.com/ojroques/garbled-circuit

## Features

- **Basic Logic Gates**: Supports AND, OR, and NOT gates
- **Modular Design**: Clean separation of concerns with separate modules for keys, circuits, and garbled operations
- **Two Evaluation Modes**: Standard evaluation and secure evaluation with Oblivious Transfer protocol
- **Magic Bytes Security**: Built-in verification to prevent acceptance of invalid decryption results

## Architecture

The implementation is divided into several modules:

- `src/key.rs` - Cryptographic key management using AES-GCM with magic bytes verification
- `src/circuit.rs` - Circuit and gate definitions loaded from JSON
- `src/garbled.rs` - Garbled gate creation and circuit evaluation logic  
- `src/ot.rs` - Oblivious Transfer protocol for secure key exchange
- `src/secure_protocol.rs` - Alice and Bob roles for two-party secure computation
- `src/lib.rs` - Public API and module organization
- `src/main.rs` - Command-line interface and example usage

## Usage

### Quick Start with Makefile

```bash
# Standard evaluation
make and      # Test all AND gate combinations
make or       # Test all OR gate combinations
make not      # Test all NOT gate combinations
make and-or   # Test complex AND and OR circuit combinations
make all      # Run all standard tests

# With Oblivious Transfer protocol
make and-ot      # Test AND gate with OT protocol
make or-ot       # Test OR gate with OT protocol
make not-ot      # Test NOT gate with OT protocol
make and-or-ot   # Test complex circuit with OT protocol
make all-ot      # Run all tests with OT protocol

# Show available commands
make help
```

### Command Line Interface

```bash
cargo run -- [circuit_file.json] <circuit_index> [alice_input] [bob_input] [--ot]
```

Parameters:
- `circuit_file.json`: Optional JSON file containing circuits (default: circuits/bool.json)
- `circuit_index`: 0-based index of the circuit to evaluate (required)
- `alice_input`: Binary string for Alice's input (e.g., '10' for inputs 1,0)
- `bob_input`: Binary string for Bob's input (e.g., '1' for input 1)
- `--ot`: Use Oblivious Transfer protocol for secure evaluation (optional)

### Examples

```bash
# Run AND circuit with Alice=1, Bob=1
cargo run -- 0 1 1

# Run OR circuit with Alice=1, Bob=0
cargo run -- 1 1 0

# Run NOT circuit with Alice=1 (no Bob input needed)
cargo run -- 2 1

# Run AND and OR circuit with Alice=11 (2 bits), Bob=1
cargo run -- 3 11 1

# Run with Oblivious Transfer protocol
cargo run -- 0 1 1 --ot

# Run with custom circuit file
cargo run -- circuits/max.json 0 11 00

# Show usage and list available circuits
cargo run
```

The program loads circuits from the `circuits/bool.json` file by default, or from a specified JSON file if provided.

## Circuit Format

Circuits are loaded from JSON files with the following structure:

```json
{
  "name": "circuit_collection_name",
  "circuits": [
    {
      "id": "Circuit Name",
      "alice": [1, 2],      // Alice's input wire IDs
      "bob": [3, 4],        // Bob's input wire IDs (optional)
      "out": [5],           // Output wire IDs
      "gates": [
        {
          "id": 5,          // Gate output wire ID
          "type": "AND",    // Gate type (AND, OR, NOT)
          "in": [1, 2]      // Input wire IDs
        }
      ]
    }
  ]
}
```

The program expects a `circuits/bool.json` file in the current directory containing the circuit definitions.

## Security Features

### ✅ Implemented Security Measures

1. **Magic Bytes Verification**
   - All encrypted keys include magic bytes ("GARB") for verification
   - Prevents acceptance of random data as valid decryption results
   - Provides integrity checking for garbled circuit evaluation

2. **Oblivious Transfer (OT) Protocol**
   - Basic 1-out-of-2 OT implementation for secure key exchange
   - Alice can transfer keys corresponding to her inputs without revealing them
   - Educational implementation demonstrating OT concepts
   - Use `--ot` flag to enable OT-based evaluation

### Known Limitations

3. **No Point-and-Permute Optimization**
   - Missing p-bit optimization used in efficient implementations
   - **Impact**: Less efficient evaluation compared to optimized versions

4. **No Free XOR Optimization**
   - XOR gates could be evaluated without garbled tables
   - **Impact**: Unnecessary computational overhead for XOR operations

5. **Limited Error Handling**
   - Minimal error recovery and validation beyond magic bytes verification

6. **No Network Communication**
   - Currently runs locally only
   - For distributed execution, network layer would be needed

## Example Output

### Using Makefile

```bash
$ make and
======== AND ========
Alice[1]=0 Bob[2]=0  Output[3]=0 
Alice[1]=0 Bob[2]=1  Output[3]=0 
Alice[1]=1 Bob[2]=0  Output[3]=0 
Alice[1]=1 Bob[2]=1  Output[3]=1

$ make and-ot
======== AND with OT ========
Alice[1]=0 Bob[2]=0  Output[3]=0 
Alice[1]=0 Bob[2]=1  Output[3]=0 
Alice[1]=1 Bob[2]=0  Output[3]=0 
Alice[1]=1 Bob[2]=1  Output[3]=1

$ make or
======== OR ========
Alice[1]=0 Bob[2]=0  Output[3]=0 
Alice[1]=0 Bob[2]=1  Output[3]=1 
Alice[1]=1 Bob[2]=0  Output[3]=1 
Alice[1]=1 Bob[2]=1  Output[3]=1 
```

### Using Cargo directly

```bash
$ cargo run -- 0 1 1
Alice[1]=1 Bob[2]=1  Output[3]=1 

$ cargo run -- 0 1 1 --ot
Alice[1]=1 Bob[2]=1  Output[3]=1 

$ cargo run -- 3 10 1 --ot
Alice[1]=0 [2]=1 Bob[3]=1  Output[5]=1 

$ cargo run -- circuits/max.json 0 11 00
Alice[1]=1 [2]=1 Bob[3]=0 [4]=0  Output[10]=1 [19]=1

$ cargo run
Usage: target/debug/garbled_circuit_rs [circuit_file.json] <circuit_index> [alice_input] [bob_input] [--ot]
  circuit_file.json: Optional JSON file containing circuits (default: circuits/bool.json)
  circuit_index: 0-based index of the circuit to evaluate
  alice_input: Binary string for Alice's input (e.g., '10' for inputs 1,0)
  bob_input: Binary string for Bob's input (e.g., '1' for input 1)
  --ot: Use Oblivious Transfer protocol for secure evaluation

Examples:
  target/debug/garbled_circuit_rs 0 1 1      # Run circuit 0 with Alice=1, Bob=1 (standard)
  target/debug/garbled_circuit_rs 0 1 1 --ot # Run circuit 0 with Alice=1, Bob=1 (with OT)
  target/debug/garbled_circuit_rs circuits/max.json 0 11 00 # Run max circuit with custom file
```

## Educational Purpose

This implementation prioritizes:
- **Clarity** over efficiency
- **Simplicity** over security
- **Understanding** over optimization

For production use, implement the missing security features listed above.

## Dependencies

- `serde` - Serialization framework
- `rand` - Random number generation
- `aes-gcm` - AES-GCM encryption
- `hex` - Hexadecimal encoding/decoding

## License

This project is for educational purposes. Please implement proper security measures before any production use.