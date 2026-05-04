## sgx-attest — build the host CLI and the SGX enclave image.
## Everything else (enroll/publish/run/verify/demo/tamper-test) is a
## subcommand of the `sgx-attest` binary itself.

CLI       := target/release/sgx-attest
SGXS      := target/x86_64-fortanix-unknown-sgx/release/fibonacci.sgxs
N         ?= 20

.PHONY: build demo tamper-test clean
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

tamper-test: build
	$(CLI) tamper-test

clean:
	cargo clean
	rm -f registry.json envelope.json envelope_tampered.json root.txt
