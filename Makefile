## sgx-attest: Rust attestation pipeline on legacy SGX (Fortanix EDP)
##
## Usage:
##   make build          # compile host tools + fibonacci enclave (.sgxs)
##   make enroll         # run fibonacci-enroll inside SGX, append leaf to registry.json
##   make publish        # print Merkle root of registry.json, write root.txt
##   make compute N=20   # run fibonacci(N) inside SGX, write envelope.json
##   make verify         # external-style verification of envelope.json against registry.json
##   make demo           # full end-to-end: clean, build, enroll, publish, compute, verify
##   make tamper-test    # mutate the output and confirm the verifier rejects it
##   make clean          # cargo clean + remove generated artifacts

CARGO        ?= cargo
TARGET       := x86_64-fortanix-unknown-sgx
RELEASE_DIR  := target/release
SGX_DIR      := target/$(TARGET)/release

ENCLAVE_ELF  := $(SGX_DIR)/fibonacci
ENCLAVE_SGXS := $(SGX_DIR)/fibonacci.sgxs

REGISTRY     := registry.json
ENVELOPE     := envelope.json

HEAP_SIZE    := 0x100000
STACK_SIZE   := 0x40000
THREADS      := 1

N            ?= 20

.PHONY: all build host-tools enclave enroll publish compute verify demo tamper-test test clean

all: build

build: host-tools enclave

host-tools:
	$(CARGO) build --release --workspace --exclude fibonacci

enclave: $(ENCLAVE_SGXS)

$(ENCLAVE_ELF): programs/fibonacci/src/main.rs crates/attest-enclave/src/lib.rs crates/attest-core/src/lib.rs
	$(CARGO) build -p fibonacci --release --target $(TARGET)

$(ENCLAVE_SGXS): $(ENCLAVE_ELF)
	ftxsgx-elf2sgxs $(ENCLAVE_ELF) \
	    --heap-size $(HEAP_SIZE) \
	    --stack-size $(STACK_SIZE) \
	    --threads $(THREADS) \
	    --debug

enroll: build
	ftxsgx-runner $(ENCLAVE_SGXS) enroll \
	    | $(RELEASE_DIR)/enroll $(REGISTRY)

publish: build
	$(RELEASE_DIR)/publish-root $(REGISTRY)

compute: build
	ftxsgx-runner $(ENCLAVE_SGXS) compute $(N) > $(ENVELOPE)
	@echo "wrote $(ENVELOPE) ($$(wc -c < $(ENVELOPE)) bytes)"

verify: build
	$(RELEASE_DIR)/verify-envelope $(REGISTRY) $(ENVELOPE)

demo: clean-artifacts build
	@echo "=== ENROLL ==="
	@$(MAKE) --no-print-directory enroll
	@echo
	@echo "=== PUBLISH ==="
	@$(MAKE) --no-print-directory publish
	@echo
	@echo "=== COMPUTE fib($(N)) ==="
	@$(MAKE) --no-print-directory compute N=$(N)
	@echo
	@echo "=== VERIFY ==="
	@$(MAKE) --no-print-directory verify

tamper-test: build
	@command -v python3 >/dev/null || { echo "python3 required for tamper-test"; exit 1; }
	@python3 -c 'import json; e=json.load(open("$(ENVELOPE)")); e["output"]=list(b"{\"fib_n\":\"9999\",\"n\":20}"); open("envelope_tampered.json","w").write(json.dumps(e))'
	@echo "expecting FAIL:"
	@! $(RELEASE_DIR)/verify-envelope $(REGISTRY) envelope_tampered.json && echo "tamper-test PASS (verifier rejected)"

test:
	$(CARGO) test --workspace --exclude fibonacci

clean-artifacts:
	rm -f $(REGISTRY) $(ENVELOPE) envelope_tampered.json root.txt

clean: clean-artifacts
	$(CARGO) clean
