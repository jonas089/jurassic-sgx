//! Verifiable compilation: run the real `rustc` + `rust-lld` toolchain
//! inside the `rvlinux` RISC-V emulator — single-file or multi-crate
//! workspace — and commit to the resulting source→binary binding.
//!
//! Deliberately its own crate, separate from the generic SGX attestation
//! pipeline (`attestations`) and the generic RISC-V emulator (`rvlinux`):
//! compiling Rust source is just *one* thing you can attest to running
//! inside the enclave, and shouldn't be mingled into either of those.
//!
//! `no_std` + `alloc` by default so it builds for the enclave
//! (`programs/replay-rustc`); the `host` feature adds `workspace`
//! (Cargo.toml discovery) and the `mkbundle` binary, neither of which ever
//! runs inside the enclave.

#![cfg_attr(not(feature = "host"), no_std)]

extern crate alloc;
#[cfg(feature = "host")]
extern crate std;

pub mod pipeline;
pub mod public_values;
#[cfg(feature = "host")]
pub mod workspace;

/// Where the packed workspace source tree is mounted inside the guest fs;
/// shared by the CLI (which packs it there) and the enclave (whose
/// `public_values::PlanCrateUnit::entry` paths, relative to the workspace
/// root, get this prefix) so the two sides can't drift apart.
pub const WORKSPACE_SRC_ROOT: &str = "/work/src";

/// Join argv with NUL for hashing (unambiguous since args can't contain NUL).
pub fn argv_bytes(argv: &[alloc::string::String]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            out.push(0);
        }
        out.extend_from_slice(a.as_bytes());
    }
    out
}
