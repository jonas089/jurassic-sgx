# jurassic-sgx

A Rust attestation pipeline for **legacy Intel SGX** (no Flexible Launch
Control, no DCAP, no live Intel attestation service). Replaces Intel's PKI with
a self-hosted Merkle tree of `(MRENCLAVE, pubkey)` leaves while keeping the
hardware-rooted execution-integrity guarantee.

Built and verified on a Xeon E3 + Supermicro X11SSH-F box running the
out-of-tree `/dev/isgx` driver, Intel PSW 2.19, and aesmd EPID flow.

## Trust model

1. The enclave runs `EGETKEY` (key=Seal, policy=MRENCLAVE) inside SGX. The CPU
   mixes its fused root sealing secret with the current MRENCLAVE and returns
   16 bytes that *only this exact enclave on this exact CPU* can ever produce.
2. Those bytes feed HKDF-SHA256 → 32-byte seed → Ed25519 keypair. The privkey
   never leaves enclave memory.
3. The registry operator runs the enclave once on a known-good SGX box,
   captures the self-signed `(MRENCLAVE, pubkey)`, adds it as a leaf to a
   sorted-leaf binary Merkle tree, and publishes the root.
4. Each program execution emits a signed `Envelope { Attestation, input,
   output }` whose Ed25519 signature covers `(MRENCLAVE, program_id,
   input_hash, output_hash, nonce, timestamp)`.
5. External verifiers — no SGX required — check: Merkle proof of the leaf
   under the published root, pubkey/MRENCLAVE match, recomputed I/O hashes
   match, signature valid.

## Layout

```
crates/attestations/      one library:
  src/core.rs               types: Attestation, Envelope, Leaf, hashing
  src/enclave.rs            in-enclave SDK: EGETKEY → HKDF → Ed25519, commit/enroll
  src/registry.rs           sorted-leaf binary Merkle tree
  src/verify.rs             pure-Rust external verifier (no SGX)

programs/fibonacci/       example workload (single binary, two modes)

cli/                      one host-side binary (`sgx-attest`):
                          subcommands enroll / publish / run / verify
                          loads + runs the enclave directly via
                          enclave-runner + sgxs-loaders + aesm-client
                          (no ftxsgx-runner shellout)
```

## Requirements

- nightly Rust (`rust-toolchain.toml` pins it)
- target `x86_64-fortanix-unknown-sgx`
- `fortanix-sgx-tools` (only for `ftxsgx-elf2sgxs`)
- `sgxs-tools` (optional)
- An SGX-capable CPU + working Intel PSW + aesmd; for legacy CPUs (no FLC) you
  also need the out-of-tree `/dev/isgx` driver

## Quickstart

```bash
make demo            # build, enroll, publish, run fib(20), verify
make tamper-test     # mutate output, confirm verifier rejects
make run N=42        # compute fib(42), write envelope.json
make verify          # external verification of envelope.json
```

Or directly:

```bash
sgx-attest enroll  --sgxs path/to/fibonacci.sgxs
sgx-attest publish
sgx-attest run     --sgxs path/to/fibonacci.sgxs --out envelope.json -- 20
sgx-attest verify  --registry registry.json --envelope envelope.json
```

## Caveats

- "Execution trace" here means input/output hash-binding, not instruction-level
  tracing.
- Legacy SGX EPC caps usable enclave memory around ~90 MB before slow paging.
- I/O crosses the OCall boundary; pin all inputs by hash if integrity matters.
- The registry operator is the trust anchor — Intel's PKI does not enter the
  verification path.

## License

MIT OR Apache-2.0
