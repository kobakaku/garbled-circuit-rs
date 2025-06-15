# Default target
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make and      - Run AND circuit with all input combinations"
	@echo "  make or       - Run OR circuit with all input combinations"
	@echo "  make not      - Run NOT circuit with all input combinations"
	@echo "  make and-or   - Run AND and OR circuit with all input combinations"
	@echo "  make and-ot   - Run AND circuit with OT protocol"
	@echo "  make or-ot    - Run OR circuit with OT protocol"
	@echo "  make not-ot   - Run NOT circuit with OT protocol"
	@echo "  make and-or-ot - Run AND and OR circuit with OT protocol"
	@echo "  make all      - Run all standard tests"
	@echo "  make all-ot   - Run all tests with OT protocol"
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

# Run AND circuit with OT protocol
.PHONY: and-ot
and-ot: build
	@echo ======== AND with OT ========
	@cargo run --quiet -- 0 0 0 --ot
	@cargo run --quiet -- 0 0 1 --ot
	@cargo run --quiet -- 0 1 0 --ot
	@cargo run --quiet -- 0 1 1 --ot

# Run OR circuit with OT protocol
.PHONY: or-ot
or-ot: build
	@echo ======== OR with OT ========
	@cargo run --quiet -- 1 0 0 --ot
	@cargo run --quiet -- 1 0 1 --ot
	@cargo run --quiet -- 1 1 0 --ot
	@cargo run --quiet -- 1 1 1 --ot

# Run NOT circuit with OT protocol
.PHONY: not-ot
not-ot: build
	@echo ======== NOT with OT ========
	@cargo run --quiet -- 2 0 --ot
	@cargo run --quiet -- 2 1 --ot

# Run AND and OR circuit with OT protocol
.PHONY: and-or-ot
and-or-ot: build
	@echo ======== AND and OR with OT ========
	@cargo run --quiet -- 3 00 0 --ot
	@cargo run --quiet -- 3 00 1 --ot
	@cargo run --quiet -- 3 10 0 --ot
	@cargo run --quiet -- 3 10 1 --ot
	@cargo run --quiet -- 3 01 0 --ot
	@cargo run --quiet -- 3 01 1 --ot
	@cargo run --quiet -- 3 11 0 --ot
	@cargo run --quiet -- 3 11 1 --ot

# Run all standard tests
.PHONY: all
all: and or not and-or

# Run all tests with OT protocol
.PHONY: all-ot
all-ot: and-ot or-ot not-ot and-or-ot
