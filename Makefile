## jurassic-sgx — verifiable compilation on SGX.
##
##   make build      build the CLI, the SGX enclave, and the toolchain bundle
##                   (bundle is built FROM SOURCE: pinned rustc tarballs +
##                   committed glibc — no large blob in git)
##   make demo       attested compilation inside SGX: the enclave runs real
##                   rustc + rust-lld in the rvlinux emulator and signs
##                   source -> binary, with a live progress bar
##   make demo-dry   same, without SGX (any host; stub identity, no root of trust)
##   make bundle     (re)build fixtures/rootfs.zkfs from source

CLI         := target/release/sgx-attest
REPLAY_SGXS := target/x86_64-fortanix-unknown-sgx/release/replay-rustc.sgxs
FIB_SGXS    := target/x86_64-fortanix-unknown-sgx/release/fibonacci.sgxs
BUNDLE      := fixtures/rootfs.zkfs
RS          ?= fixtures/hello.rs
N           ?= 20

.PHONY: build demo demo-dry demo-fib bundle tamper-test clean
.DEFAULT_GOAL := build

# ---- build everything needed for `make demo` --------------------------------
build: $(CLI) $(REPLAY_SGXS) $(BUNDLE)

$(CLI):
	cargo build --release -p sgx-attest-cli

$(REPLAY_SGXS):
	cargo build --release -p replay-rustc --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/replay-rustc \
	    --heap-size 0x80000000 --stack-size 0x400000 --threads 2 --debug

# ---- the toolchain bundle, built from source --------------------------------
# Downloads the pinned rustc 1.96.1 riscv64 tarballs (sha256-verified) and packs
# them with the committed glibc via mkbundle. ~105MB download, no blob in git.
bundle: $(BUNDLE)
$(BUNDLE): $(CLI) scripts/build-bundle.sh fixtures/glibc/libc.so.6
	bash scripts/build-bundle.sh

# ---- the demo: attested compilation in SGX ----------------------------------
demo: build
	$(CLI) enroll  --sgxs $(REPLAY_SGXS)
	$(CLI) publish
	$(CLI) compile-attest --sgxs $(REPLAY_SGXS) --bundle $(BUNDLE) --source $(RS)
	$(CLI) verify-compile

# Same pipeline without SGX (macOS / any host): stub identity, no root of trust.
demo-dry: $(CLI) $(BUNDLE)
	cargo build --release -p replay-rustc
	$(CLI) enroll  --native target/release/replay-rustc
	$(CLI) publish
	$(CLI) compile-attest --native target/release/replay-rustc --bundle $(BUNDLE) --source $(RS)
	$(CLI) verify-compile

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
