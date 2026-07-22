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

crates/rvlinux/           a from-scratch, deterministic RV64GC + Zicsr
                          usermode-Linux emulator (runs unmodified riscv64
                          ELF binaries, e.g. the real rustc/rust-lld, inside
                          the enclave). See crates/rvlinux/SPEC.md — the
                          audit companion doc — and "Emulator spec & audit
                          notes" below.

compilation/rustc/        verifiable compilation built on top of rvlinux:
                          single-file and multi-crate-workspace rustc→
                          rust-lld→run pipelines, kept separate from the
                          generic attestation/emulator code since it's just
                          one use case of both.

programs/fibonacci/       example workload (single binary, two modes)
programs/replay-rustc/    the verifiable-compilation enclave binary

cli/                      one host-side binary (`sgx-attest`):
                          subcommands enroll / publish / run / verify /
                          compile-attest / compile-workspace-attest / ...
                          loads + runs the enclave directly via
                          enclave-runner + sgxs-loaders + aesm-client
                          (no ftxsgx-runner shellout)
```

## Emulator spec & audit notes

`crates/rvlinux` is a custom, from-scratch RISC-V emulator — anyone auditing
this repo should start with **[`crates/rvlinux/SPEC.md`](crates/rvlinux/SPEC.md)**,
which maps every implemented instruction/syscall against the reference specs
below and — more importantly — lists every place its behavior *deliberately*
diverges from real hardware or a real kernel (deterministic time/randomness,
no `execve`/`fork`, unenforced page protection, partial CSR support, ...).
Every source file in `crates/rvlinux/src/` also carries function-level doc
comments tying its logic back to the relevant spec section.

Reference specifications used throughout:
- RISC-V Instruction Set Manual, Volume I (Unprivileged Architecture):
  <https://github.com/riscv/riscv-isa-manual> (rendered:
  <https://riscv.github.io/riscv-isa-manual/snapshot/spec/#vol:unpriv>;
  ratified releases: <https://riscv.org/specifications/>)
- RISC-V ELF psABI: <https://github.com/riscv-non-isa/riscv-elf-psabi-doc>
- Linux generic syscall ABI (riscv64 uses it unmodified):
  <https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h>

## Requirements

- nightly Rust (`rust-toolchain.toml` pins it)
- target `x86_64-fortanix-unknown-sgx`
- `fortanix-sgx-tools` (only for `ftxsgx-elf2sgxs`)
- `sgxs-tools` (optional)
- An SGX-capable CPU + working Intel PSW + aesmd; for legacy CPUs (no FLC) you
  also need the out-of-tree `/dev/isgx` driver

## Quickstart

```bash
make demo                 # build, enroll, publish, run fib(20), verify
make dry-run fibonacci    # same pipeline without SGX (works on macOS), stub identity
make dry-run hello-rustc  # dry-run the verifiable-compilation example
make tamper-test          # mutate output, confirm verifier rejects
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

## Dry run (no SGX, any platform)

Every subcommand that takes `--sgxs` also accepts `--native <binary>` instead:
the program runs as an ordinary process using a stub MRENCLAVE/seal key
(`attestations` substitutes it when not compiled for `target_env = "sgx"`).
The full enroll → publish → run → verify pipeline works, so you can develop
and test programs on a machine without SGX (e.g. a Mac); it just proves
nothing about hardware. The SGX loader dependencies are only pulled in on
x86_64 Linux, so the workspace compiles everywhere.

```bash
cargo build --release -p fibonacci        # native host build
sgx-attest demo --native target/release/fibonacci --n 20
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
