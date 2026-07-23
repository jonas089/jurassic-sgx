## jurassic-sgx — verifiable compilation on SGX.
##
##   make build       build the CLI and the SGX enclave
##   make demo        attested compilation inside SGX: the enclave runs real
##                    rustc + rust-lld in the rvlinux emulator and signs
##                    source -> binary, with a live progress bar
##   make demo-dry    same, without SGX (any host; stub identity, no root of trust)
##   make bundle      (re)build fixtures/rootfs.zkfs from source explicitly
##
## PROGRAM selects *what* gets compiled, for both demo and demo-dry: a single
## .rs source file, or a workspace directory (one or more crates, each with
## its own Cargo.toml somewhere under it) — auto-detected from whether
## PROGRAM is a file or a directory, so there's one variable to override
## regardless of which kind of program it is. Defaults to fixtures/hello.rs.
##
##   make demo-dry PROGRAM=fixtures/hello.rs
##   make demo-dry PROGRAM=fixtures/workspace-demo
##   make demo-dry PROGRAM=fixtures/workspace-devdeps-demo DEV=1
##   make demo     PROGRAM=path/to/your/single_file.rs
##   make demo     PROGRAM=path/to/your/workspace
##
## DEV=1 additionally links each workspace crate's [dev-dependencies] (only
## meaningful when PROGRAM is a workspace, e.g. workspace-devdeps-demo).
##
## The toolchain bundle (fixtures/rootfs.zkfs, pinned rustc tarballs merged
## with the committed glibc) no longer needs a separate build step: any CLI
## command that needs it builds + caches it automatically on first use, the
## same way crates.io dependencies are now fetched lazily. `make bundle`
## still exists for pre-warming the cache (e.g. in CI) or forcing a rebuild.

CLI           := target/release/sgx-attest
REPLAY_SGXS   := target/x86_64-fortanix-unknown-sgx/release/replay-rustc.sgxs
REPLAY_NATIVE := target/release/replay-rustc
FIB_SGXS      := target/x86_64-fortanix-unknown-sgx/release/fibonacci.sgxs
BUNDLE        := fixtures/rootfs.zkfs
N             ?= 20

# What to compile. A workspace is any PROGRAM that's a directory (crate
# discovery walks it recursively for Cargo.tomls, so it need not have one at
# its root — see compilation/rustc/src/workspace.rs); anything else is
# treated as a single source file.
PROGRAM   ?= fixtures/hello.rs
WORKSPACE := $(shell test -d "$(PROGRAM)" && echo 1)
DEV       ?=
DEV_FLAG  := $(if $(DEV),--dev,)

# $(CLI)/$(REPLAY_SGXS)/$(REPLAY_NATIVE)/$(FIB_SGXS) are marked .PHONY so
# they always re-run cargo (which is incremental, so this is cheap). Without
# this, make treats the existing binary as up-to-date even when its sources
# changed, and later targets (demo, demo-dry, ...) silently run a stale
# CLI/enclave.
.PHONY: build demo demo-dry demo-fib bundle tamper-test clean \
        $(CLI) $(REPLAY_SGXS) $(REPLAY_NATIVE) $(FIB_SGXS)
.DEFAULT_GOAL := build

# ---- build everything needed for `make demo` --------------------------------
build: $(CLI) $(REPLAY_SGXS)

$(CLI):
	cargo build --release -p sgx-attest-cli

$(REPLAY_SGXS):
	cargo build --release -p replay-rustc --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/replay-rustc \
	    --heap-size 0x80000000 --stack-size 0x400000 --threads 2 --debug

$(REPLAY_NATIVE):
	cargo build --release -p replay-rustc

# ---- explicit/manual toolchain bundle build (optional — see header) --------
bundle: $(CLI)
	bash scripts/build-bundle.sh

# ---- the demo: attested compilation in SGX, for whatever PROGRAM points at --
demo: build
	$(CLI) enroll  --sgxs $(REPLAY_SGXS)
	$(CLI) publish
ifeq ($(WORKSPACE),1)
	$(CLI) compile-workspace-attest --sgxs $(REPLAY_SGXS) --bundle $(BUNDLE) --workspace $(PROGRAM) $(DEV_FLAG)
	$(CLI) verify-compile-workspace
else
	$(CLI) compile-attest --sgxs $(REPLAY_SGXS) --bundle $(BUNDLE) --source $(PROGRAM)
	$(CLI) verify-compile
endif

# Same pipeline without SGX (macOS / any host): stub identity, no root of trust.
demo-dry: $(CLI) $(REPLAY_NATIVE)
	$(CLI) enroll  --native $(REPLAY_NATIVE)
	$(CLI) publish
ifeq ($(WORKSPACE),1)
	$(CLI) compile-workspace-attest --native $(REPLAY_NATIVE) --bundle $(BUNDLE) --workspace $(PROGRAM) $(DEV_FLAG)
	$(CLI) verify-compile-workspace
else
	$(CLI) compile-attest --native $(REPLAY_NATIVE) --bundle $(BUNDLE) --source $(PROGRAM)
	$(CLI) verify-compile
endif

# ---- extras -----------------------------------------------------------------
# The original fibonacci attestation demo.
demo-fib: $(CLI) $(FIB_SGXS)
	$(CLI) demo --sgxs $(FIB_SGXS) --n $(N)

$(FIB_SGXS):
	cargo build --release -p fibonacci --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/fibonacci \
	    --heap-size 0x100000 --stack-size 0x40000 --threads 1 --debug

tamper-test: $(CLI)
	$(CLI) tamper-test

clean:
	cargo clean
	rm -f registry.json envelope.json envelope_tampered.json root.txt
	rm -rf build build2
