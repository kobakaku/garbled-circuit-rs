# Default target
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make and      - Run AND circuit with all input combinations"
	@echo "  make or       - Run OR circuit with all input combinations"
	@echo "  make not      - Run NOT circuit with all input combinations"
	@echo "  make and-or   - Run AND and OR circuit with all input combinations"
	@echo "  make max      - Run MAX circuit with all 2-bit input combinations"
	@echo "  make all      - Run all standard tests"
	@echo "  make build    - Build the project"
	@echo "  make clean    - Clean build artifacts"

# Build the project
.PHONY: build
build:
	cargo build

# Clean build artifacts
.PHONY: clean
clean:
	cargo clean

# Run AND circuit with all combinations
.PHONY: and
and: build
	@echo ======== AND ========
	@cargo run --quiet -- 0 0 0
	@cargo run --quiet -- 0 0 1
	@cargo run --quiet -- 0 1 0
	@cargo run --quiet -- 0 1 1

# Run OR circuit with all combinations
.PHONY: or
or: build
	@echo ======== OR ========
	@cargo run --quiet -- 1 0 0
	@cargo run --quiet -- 1 0 1
	@cargo run --quiet -- 1 1 0
	@cargo run --quiet -- 1 1 1

# Run NOT circuit with all combinations
.PHONY: not
not: build
	@echo ======== NOT ========
	@cargo run --quiet -- 2 0
	@cargo run --quiet -- 2 1

# Run AND and OR circuit with all combinations
.PHONY: and-or
and-or: build
	@echo ======== AND and OR ========
	@cargo run --quiet -- 3 00 0
	@cargo run --quiet -- 3 00 1
	@cargo run --quiet -- 3 10 0
	@cargo run --quiet -- 3 10 1
	@cargo run --quiet -- 3 01 0
	@cargo run --quiet -- 3 01 1
	@cargo run --quiet -- 3 11 0
	@cargo run --quiet -- 3 11 1

# Run MAX circuit with all 2-bit combinations
.PHONY: max
max: build
	@echo ======== MAX \(2-bit\) ========
	@cargo run --quiet -- circuits/max.json 0 00 00
	@cargo run --quiet -- circuits/max.json 0 00 01
	@cargo run --quiet -- circuits/max.json 0 00 10
	@cargo run --quiet -- circuits/max.json 0 00 11
	@cargo run --quiet -- circuits/max.json 0 01 00
	@cargo run --quiet -- circuits/max.json 0 01 01
	@cargo run --quiet -- circuits/max.json 0 01 10
	@cargo run --quiet -- circuits/max.json 0 01 11
	@cargo run --quiet -- circuits/max.json 0 10 00
	@cargo run --quiet -- circuits/max.json 0 10 01
	@cargo run --quiet -- circuits/max.json 0 10 10
	@cargo run --quiet -- circuits/max.json 0 10 11
	@cargo run --quiet -- circuits/max.json 0 11 00
	@cargo run --quiet -- circuits/max.json 0 11 01
	@cargo run --quiet -- circuits/max.json 0 11 10
	@cargo run --quiet -- circuits/max.json 0 11 11

# Run all standard tests
.PHONY: all
all: and or not and-or max
