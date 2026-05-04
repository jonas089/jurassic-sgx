## sgx-attest — Rust attestation pipeline on legacy SGX (Fortanix EDP).
##
## The Makefile only does *builds*. Enclave loading, key derivation,
## signing, registry, and verification all live inside the `sgx-attest`
## Rust binary (cli/src/main.rs). It opens /dev/isgx, talks to aesmd,
## ECREATEs/EADDs/EINITs the enclave, captures its stdout, and processes
## the result — no `ftxsgx-runner` shellout.

CARGO        ?= cargo
TARGET       := x86_64-fortanix-unknown-sgx
RELEASE_DIR  := target/release
SGX_DIR      := target/$(TARGET)/release

ENCLAVE_ELF  := $(SGX_DIR)/fibonacci
ENCLAVE_SGXS := $(SGX_DIR)/fibonacci.sgxs

CLI          := $(RELEASE_DIR)/sgx-attest

REGISTRY     := registry.json
ENVELOPE     := envelope.json

HEAP_SIZE    := 0x100000
STACK_SIZE   := 0x40000
THREADS      := 1

N            ?= 20

.PHONY: all build cli enclave enroll publish run verify demo tamper-test test clean

all: build

build: cli enclave

cli: $(CLI)

$(CLI): cli/src/main.rs crates/attestations/src/*.rs
	$(CARGO) build --release -p sgx-attest-cli

enclave: $(ENCLAVE_SGXS)

$(ENCLAVE_ELF): programs/fibonacci/src/main.rs crates/attestations/src/*.rs
	$(CARGO) build -p fibonacci --release --target $(TARGET)

$(ENCLAVE_SGXS): $(ENCLAVE_ELF)
	ftxsgx-elf2sgxs $(ENCLAVE_ELF) \
	    --heap-size $(HEAP_SIZE) \
	    --stack-size $(STACK_SIZE) \
	    --threads $(THREADS) \
	    --debug

enroll: build
	$(CLI) enroll --sgxs $(ENCLAVE_SGXS) --registry $(REGISTRY)

publish: build
	$(CLI) publish --registry $(REGISTRY)

run: build
	$(CLI) run --sgxs $(ENCLAVE_SGXS) --out $(ENVELOPE) -- $(N)

verify: build
	$(CLI) verify --registry $(REGISTRY) --envelope $(ENVELOPE)

demo: clean-artifacts build
	@echo "=== ENROLL ==="    ; $(MAKE) --no-print-directory enroll
	@echo                     ; echo "=== PUBLISH ===" ; $(MAKE) --no-print-directory publish
	@echo                     ; echo "=== RUN fib($(N)) ===" ; $(MAKE) --no-print-directory run N=$(N)
	@echo                     ; echo "=== VERIFY ===" ; $(MAKE) --no-print-directory verify

tamper-test: build
	@command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
	@python3 -c 'import json; e=json.load(open("$(ENVELOPE)")); e["output"]=list(b"{\"fib_n\":\"9999\",\"n\":20}"); open("envelope_tampered.json","w").write(json.dumps(e))'
	@echo "expecting FAIL:"
	@! $(CLI) verify --registry $(REGISTRY) --envelope envelope_tampered.json && echo "tamper-test PASS (verifier rejected)"

test:
	$(CARGO) test -p attestations

clean-artifacts:
	rm -f $(REGISTRY) $(ENVELOPE) envelope_tampered.json root.txt

clean: clean-artifacts
	$(CARGO) clean
