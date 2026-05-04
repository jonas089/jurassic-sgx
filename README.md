# jurassic-sgx

A Rust attestation pipeline for **legacy Intel SGX** (no Flexible Launch Control,
no DCAP, no live Intel attestation service). Replaces Intel's PKI with a
self-hosted Merkle tree of `(MRENCLAVE, pubkey)` leaves, while keeping the
hardware-rooted execution-integrity guarantee.

Built and verified on a Xeon E3 + Supermicro X11SSH-F box running the
out-of-tree `/dev/isgx` driver, Intel PSW 2.19, and aesmd EPID flow.

## Trust model

1. The enclave runs `EGETKEY` (key=Seal, policy=MRENCLAVE) inside SGX. The CPU
   mixes its fused root sealing secret with the current MRENCLAVE and returns
   16 bytes that *only this exact enclave on this exact CPU* can ever produce.
2. Those bytes feed HKDF-SHA256 → 32-byte seed → Ed25519 keypair. The privkey
   never leaves enclave memory.
3. The registry operator runs the enclave once on a known-good SGX machine,
   captures the self-signed `(MRENCLAVE, pubkey)`, adds it as a leaf to a
   sorted-leaf binary Merkle tree, and publishes the root.
4. Each program execution emits a signed `Envelope { Attestation, input, output }`
   where the Ed25519 signature covers `(MRENCLAVE, program_id, input_hash,
   output_hash, nonce, timestamp)`.
5. External verifiers — no SGX required — check: Merkle proof of the leaf
   under the published root, pubkey/MRENCLAVE match, recomputed input/output
   hashes match, signature valid.

## Layout

```
crates/
  attest-core/        shared types: Attestation, Envelope, Leaf, hashing
  attest-enclave/     in-enclave SDK: EGETKEY -> HKDF -> Ed25519, commit/enroll
  attest-registry/    sorted-leaf binary Merkle tree
  attest-verify/      pure-Rust external verifier (no SGX)
programs/
  fibonacci/          example workload: enroll | compute <n>
tools/
  enroll/             append a leaf to registry.json
  publish-root/       print Merkle root, write root.txt
  run-and-verify/     verify-envelope <registry.json> <envelope.json>
```

## Requirements

- nightly Rust (`rust-toolchain.toml` pins it)
- target `x86_64-fortanix-unknown-sgx`
- `fortanix-sgx-tools`, `sgxs-tools`
- An SGX-capable CPU + a working Intel PSW + aesmd; for legacy CPUs (no FLC) you
  also need the out-of-tree `/dev/isgx` driver

## Quickstart

```bash
make demo            # clean, build, enroll, publish, compute fib(20), verify
make tamper-test     # mutate output, confirm verifier rejects
make compute N=42    # compute fib(42), write envelope.json
make verify          # external verification of envelope.json
```

## Caveats

- "Execution trace" here means input/output hash-binding, not instruction-level
  tracing. The attestation says: this MRENCLAVE produced this output from this
  input, signed by a key only this enclave on this CPU can derive.
- Legacy SGX EPC caps usable enclave memory around ~90 MB before slow paging.
- I/O crosses the OCall boundary; pin all inputs by hash if integrity matters.
- The registry operator is the trust anchor. They are the *only* gatekeeper —
  Intel's PKI does not enter the verification path.

## License

MIT OR Apache-2.0
