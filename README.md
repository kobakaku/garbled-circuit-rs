# Garbled Circuit Implementation in Rust

A secure two-party computation implementation using garbled circuits with mandatory Oblivious Transfer (OT) protocol in Rust.

## Generation and References

This code was generated with [Claude Code](https://claude.ai/code) 🤖

This implementation is based on and references the following repository:
- https://github.com/ojroques/garbled-circuit

## Features

- **Secure Two-Party Computation**: Mandatory use of Oblivious Transfer protocol for all evaluations
- **Basic Logic Gates**: Supports AND, OR, and NOT gates
- **Modular Design**: Clean separation of concerns with separate modules for keys, circuits, and garbled operations
- **Magic Bytes Security**: Built-in verification to prevent acceptance of invalid decryption results
- **Privacy Preserving**: Bob's inputs remain private through OT protocol

## Architecture

The implementation is divided into several modules:

- `src/key.rs` - Cryptographic key management using AES-GCM with magic bytes verification
- `src/circuit.rs` - Circuit and gate definitions loaded from JSON
- `src/garbled.rs` - Garbled gate creation and circuit evaluation logic  
- `src/two_party.rs` - Alice and Bob roles for two-party secure computation with OT
- `src/lib.rs` - Public API and module organization
- `src/main.rs` - Command-line interface and example usage

## Usage

### Command Line Interface

```bash
cargo run -- [circuit_file.json] <circuit_index> [alice_input] [bob_input]
```

Parameters:
- `circuit_file.json`: Optional JSON file containing circuits (default: circuits/bool.json)
- `circuit_index`: 0-based index of the circuit to evaluate (required)
- `alice_input`: Binary string for Alice's input (e.g., '10' for inputs 1,0)
- `bob_input`: Binary string for Bob's input (e.g., '1' for input 1)

**Note**: All circuits are evaluated using secure Oblivious Transfer protocol

### Examples

```bash
# Run AND circuit with Alice=1, Bob=1
cargo run -- 0 1 1

# Run OR circuit with Alice=1, Bob=0
cargo run -- 1 1 0

# Run AND and OR circuit with Alice=11 (2 bits), Bob=1
cargo run -- 3 11 1

# Run with custom circuit file
cargo run -- circuits/max.json 0 11 00

# Show usage and list available circuits
cargo run
```

**Important**: All circuits require Bob to have at least one input wire for the secure protocol to work.

The program loads circuits from the `circuits/bool.json` file by default, or from a specified JSON file if provided.

## Circuit Format

Circuits are loaded from JSON files with the following structure:

```json
[
  {
    "id": "Circuit Name",
    "alice": [1, 2],      // Alice's input wire IDs
    "bob": [3, 4],        // Bob's input wire IDs
    "out": [5],           // Output wire IDs
    "gates": [
      {
        "id": 5,          // Gate output wire ID
        "gate_type": "AND", // Gate type (AND, OR, NOT)
        "inputs": [1, 2]  // Input wire IDs
      }
    ]
  }
]
```

The program expects a `circuits/bool.json` file in the current directory containing the circuit definitions.

## Security Features

### ✅ Implemented Security Measures

1. **Mandatory Oblivious Transfer (OT) Protocol**
   - All circuits are evaluated using secure 4-phase OT protocol
   - Bob uses OT to receive his input keys without revealing his choices to Alice
   - Provides honest-but-curious security guarantees

2. **Magic Bytes Verification**
   - All encrypted keys include magic bytes ("GARB") for verification
   - Prevents acceptance of random data as valid decryption results
   - Provides integrity checking for garbled circuit evaluation

3. **Input Privacy**
   - Alice's inputs are revealed only through selected keys
   - Bob's inputs remain completely private through OT
   - Only final output is revealed to both parties

### Protocol Flow

1. **Setup**: Alice creates garbled circuit with encrypted truth tables
2. **Key Distribution**: Alice sends her input keys directly to Bob
3. **Oblivious Transfer**: 4-phase OT protocol for Bob's input keys
   - Phase 1: Alice generates RSA key pairs for each Bob wire
   - Phase 2: Bob creates encrypted values based on his input choices
   - Phase 3: Alice creates masked messages for both possible keys
   - Phase 4: Bob extracts only his chosen keys
4. **Evaluation**: Bob evaluates garbled circuit using received keys
5. **Output**: Both parties learn the computation result

### Known Limitations

1. **No Point-and-Permute Optimization**
   - Missing p-bit optimization used in efficient implementations
   - **Impact**: Less efficient evaluation compared to optimized versions

2. **No Free XOR Optimization**
   - XOR gates could be evaluated without garbled tables
   - **Impact**: Unnecessary computational overhead for XOR operations

3. **Bob Input Requirement**
   - All circuits must have at least one Bob input wire
   - **Impact**: Cannot handle Alice-only computations in secure mode

4. **No Network Communication**
   - Currently runs locally only
   - For distributed execution, network layer would be needed

## Example Output

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

$ make max
======== MAX (2-bit) ========
Alice[1]=0 [2]=0 Bob[3]=0 [4]=0  Output[10]=0 [19]=0 
Alice[1]=0 [2]=0 Bob[3]=0 [4]=1  Output[10]=0 [19]=1 
Alice[1]=0 [2]=0 Bob[3]=1 [4]=0  Output[10]=1 [19]=0 
Alice[1]=0 [2]=0 Bob[3]=1 [4]=1  Output[10]=1 [19]=1 
Alice[1]=0 [2]=1 Bob[3]=0 [4]=0  Output[10]=0 [19]=1 
Alice[1]=0 [2]=1 Bob[3]=0 [4]=1  Output[10]=0 [19]=1 
Alice[1]=0 [2]=1 Bob[3]=1 [4]=0  Output[10]=1 [19]=0 
Alice[1]=0 [2]=1 Bob[3]=1 [4]=1  Output[10]=1 [19]=1 
Alice[1]=1 [2]=0 Bob[3]=0 [4]=0  Output[10]=1 [19]=0 
Alice[1]=1 [2]=0 Bob[3]=0 [4]=1  Output[10]=1 [19]=0 
Alice[1]=1 [2]=0 Bob[3]=1 [4]=0  Output[10]=1 [19]=0 
Alice[1]=1 [2]=0 Bob[3]=1 [4]=1  Output[10]=1 [19]=1 
Alice[1]=1 [2]=1 Bob[3]=0 [4]=0  Output[10]=1 [19]=1 
Alice[1]=1 [2]=1 Bob[3]=0 [4]=1  Output[10]=1 [19]=1 
Alice[1]=1 [2]=1 Bob[3]=1 [4]=0  Output[10]=1 [19]=1 
Alice[1]=1 [2]=1 Bob[3]=1 [4]=1  Output[10]=1 [19]=1
```

## Testing

Run all tests:
```bash
cargo test
```

Run specific test categories:
```bash
# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test integration_tests
```

## Requirements

- **Bob Inputs Required**: The secure protocol requires Bob to have at least one input wire
- **Binary Inputs**: All inputs must be binary (0 or 1)
- **Complete Inputs**: All specified input wires must have corresponding values

## License

This project is for learning purposes. Please implement proper security measures before any production use.