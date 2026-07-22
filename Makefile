## sgx-attest — build the host CLI and the SGX enclave image.
## Everything else (enroll/publish/run/verify/demo/tamper-test) is a
## subcommand of the `sgx-attest` binary itself.

CLI       := target/release/sgx-attest
SGXS      := target/x86_64-fortanix-unknown-sgx/release/fibonacci.sgxs
N         ?= 20

# Programs runnable via `make dry-run <program>`.
PROGRAMS  := fibonacci hello-rustc

# Positional program name after `dry-run` (default: fibonacci).
DRY_PROG  := $(or $(filter $(PROGRAMS),$(filter-out dry-run,$(MAKECMDGOALS))),fibonacci)
# Args forwarded to the program's compute mode; fibonacci takes N.
DRY_ARGS  ?= $(if $(filter fibonacci,$(DRY_PROG)),$(N))

.PHONY: build demo dry-run tamper-test clean $(PROGRAMS)
.DEFAULT_GOAL := build

build: $(CLI) $(SGXS)

$(CLI):
	cargo build --release -p sgx-attest-cli

$(SGXS):
	cargo build --release -p fibonacci --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/fibonacci \
	    --heap-size 0x100000 --stack-size 0x40000 --threads 1 --debug

demo: build
	$(CLI) demo --sgxs $(SGXS) --n $(N)

# Full pipeline without SGX (works on macOS / any host): stub identity,
# no hardware root of trust — for checking that programs run correctly.
# Usage: make dry-run [fibonacci|hello-rustc] [N=42]
dry-run: $(CLI)
	cargo build --release -p $(DRY_PROG)
	$(CLI) enroll  --native target/release/$(DRY_PROG)
	$(CLI) publish
	$(CLI) run     --native target/release/$(DRY_PROG) -- $(DRY_ARGS)
	$(CLI) verify

# Program names are accepted as extra goals for dry-run; nothing to do here.
$(PROGRAMS):
	@:

tamper-test: $(CLI)
	$(CLI) tamper-test

clean:
	cargo clean
	rm -f registry.json envelope.json envelope_tampered.json root.txt
