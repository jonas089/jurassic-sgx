## jurassic-sgx — verifiable compilation on SGX.
##
##   make build      build the CLI and the SGX enclave
##   make demo       attested compilation inside SGX: the enclave runs real
##                   rustc + rust-lld in the rvlinux emulator and signs
##                   source -> binary, with a live progress bar
##   make demo-dry   same, without SGX (any host; stub identity, no root of trust)
##   make bundle     (re)build fixtures/rootfs.zkfs from source explicitly
##
## The toolchain bundle (fixtures/rootfs.zkfs, pinned rustc tarballs merged
## with the committed glibc) no longer needs a separate build step: any CLI
## command that needs it builds + caches it automatically on first use, the
## same way crates.io dependencies are now fetched lazily. `make bundle`
## still exists for pre-warming the cache (e.g. in CI) or forcing a rebuild.

CLI         := target/release/sgx-attest
REPLAY_SGXS := target/x86_64-fortanix-unknown-sgx/release/replay-rustc.sgxs
FIB_SGXS    := target/x86_64-fortanix-unknown-sgx/release/fibonacci.sgxs
BUNDLE      := fixtures/rootfs.zkfs
RS          ?= fixtures/hello.rs
N           ?= 20

# $(CLI)/$(REPLAY_SGXS)/$(FIB_SGXS) are marked .PHONY so they always re-run
# cargo (which is incremental, so this is cheap). Without this, make treats
# the existing binary as up-to-date even when its sources changed, and later
# targets (demo, demo-dry, ...) silently run a stale CLI/enclave.
.PHONY: build demo demo-dry demo-fib bundle tamper-test clean \
        $(CLI) $(REPLAY_SGXS) $(FIB_SGXS)
.DEFAULT_GOAL := build

# ---- build everything needed for `make demo` --------------------------------
build: $(CLI) $(REPLAY_SGXS)

$(CLI):
	cargo build --release -p sgx-attest-cli

$(REPLAY_SGXS):
	cargo build --release -p replay-rustc --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/replay-rustc \
	    --heap-size 0x80000000 --stack-size 0x400000 --threads 2 --debug

# ---- explicit/manual toolchain bundle build (optional — see header) --------
bundle: $(CLI)
	bash scripts/build-bundle.sh

# ---- the demo: attested compilation in SGX ----------------------------------
demo: build
	$(CLI) enroll  --sgxs $(REPLAY_SGXS)
	$(CLI) publish
	$(CLI) compile-attest --sgxs $(REPLAY_SGXS) --bundle $(BUNDLE) --source $(RS)
	$(CLI) verify-compile

# Same pipeline without SGX (macOS / any host): stub identity, no root of trust.
demo-dry: $(CLI)
	cargo build --release -p replay-rustc
	$(CLI) enroll  --native target/release/replay-rustc
	$(CLI) publish
	$(CLI) compile-attest --native target/release/replay-rustc --bundle $(BUNDLE) --source $(RS)
	$(CLI) verify-compile

# Same, but for a multi-crate no_std workspace (Cargo.toml path/crates.io
# deps + features, no SGX).
WS ?= fixtures/workspace-demo
demo-workspace-dry: $(CLI)
	cargo build --release -p replay-rustc
	$(CLI) enroll  --native target/release/replay-rustc
	$(CLI) publish
	$(CLI) compile-workspace-attest --native target/release/replay-rustc --bundle $(BUNDLE) --workspace $(WS)
	$(CLI) verify-compile-workspace

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
	rm -f registry.json envelope.json envelope_tampered.json root.txt transcript.json
	rm -rf build build2
