## sgx-attest — build the host CLI and the SGX enclave image.
## Everything else (enroll/publish/run/verify/demo/tamper-test) is a
## subcommand of the `sgx-attest` binary itself.

CLI        := target/release/sgx-attest
SGXS       := target/x86_64-fortanix-unknown-sgx/release/fibonacci.sgxs
REPLAY_SGXS := target/x86_64-fortanix-unknown-sgx/release/replay-rustc.sgxs
N          ?= 20
# Rust source to compile-prove (used by replay-sgx / replay-dry).
SRC        ?= examples/hello.rs
SRC_NAME   := $(basename $(notdir $(SRC)))

# Programs runnable via `make dry-run <program>`.
PROGRAMS  := fibonacci hello-rustc

# Positional program name after `dry-run` (default: fibonacci).
DRY_PROG  := $(or $(filter $(PROGRAMS),$(filter-out dry-run,$(MAKECMDGOALS))),fibonacci)
# Args forwarded to the program's compute mode; fibonacci takes N.
DRY_ARGS  ?= $(if $(filter fibonacci,$(DRY_PROG)),$(N))

.PHONY: build demo demo-fib dry-run tamper-test replay-sgx replay-dry replay-sgx-compile replay-dry-compile clean $(PROGRAMS)
.DEFAULT_GOAL := build

build: $(CLI) $(SGXS)

$(CLI):
	cargo build --release -p sgx-attest-cli

$(SGXS):
	cargo build --release -p fibonacci --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/fibonacci \
	    --heap-size 0x100000 --stack-size 0x40000 --threads 1 --debug

# `make demo` runs verifiable compilation in SGX: the enclave compiles a real
# Rust program inside the rvlinux emulator and attests source→binary, with a
# live progress bar. (The old fibonacci demo is `make demo-fib`.)
demo: replay-sgx-compile

demo-fib: build
	$(CLI) demo --sgxs $(SGXS) --n $(N)

## --- Verifiable compilation: replay a real rustc build inside SGX --------
$(REPLAY_SGXS):
	cargo build --release -p replay-rustc --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/replay-rustc \
	    --heap-size 0x80000000 --stack-size 0x400000 --threads 2 --debug

## --- Verifiable compilation via the rvlinux emulator (the real thing) ------
# Toolchain rootfs bundle + source to compile (override on the command line).
BUNDLE ?= ../verifiable-compilation/wrapped-rustc/rootfs/rootfs.zkfs
RS     ?= ../verifiable-compilation/wrapped-rustc/fixtures/hello.rs

# Attested compilation INSIDE SGX: the enclave runs real rustc + rust-lld in
# the emulator over the bundle (fed on stdin) and signs the source→binary bind.
replay-sgx-compile: $(CLI) $(REPLAY_SGXS)
	$(CLI) enroll  --sgxs $(REPLAY_SGXS)
	$(CLI) publish
	$(CLI) compile-attest --sgxs $(REPLAY_SGXS) --bundle $(BUNDLE) --source $(RS)
	$(CLI) verify-compile

# Same, without SGX (any host): stub identity, no hardware root of trust.
replay-dry-compile: $(CLI)
	cargo build --release -p replay-rustc
	$(CLI) enroll  --native target/release/replay-rustc
	$(CLI) publish
	$(CLI) compile-attest --native target/release/replay-rustc --bundle $(BUNDLE) --source $(RS)
	$(CLI) verify-compile

# Full pipeline in SGX: rustc runs OUTSIDE the enclave (transcribe); the
# enclave replays what it can, pins the rest, and attests source->binary.
# Usage: make replay-sgx [SRC=path/to/prog.rs]
replay-sgx: $(CLI) $(REPLAY_SGXS)
	$(CLI) transcribe $(SRC) --name $(SRC_NAME)
	$(CLI) enroll --sgxs $(REPLAY_SGXS)
	$(CLI) publish
	$(CLI) replay --sgxs $(REPLAY_SGXS)
	$(CLI) verify-transcript --binary build/$(SRC_NAME)

# Same pipeline without SGX (macOS / any host): stub identity, no root of trust.
replay-dry: $(CLI)
	cargo build --release -p replay-rustc
	$(CLI) transcribe $(SRC) --name $(SRC_NAME)
	$(CLI) enroll --native target/release/replay-rustc
	$(CLI) publish
	$(CLI) replay --native target/release/replay-rustc
	$(CLI) verify-transcript --binary build/$(SRC_NAME)

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
	rm -f registry.json envelope.json envelope_tampered.json root.txt transcript.json
	rm -rf build build2
