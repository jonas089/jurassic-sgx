//! Shared types between the SP1 guest and the host script.

#![no_std]

extern crate alloc;

use serde::{Deserialize, Serialize};

/// Everything the proof publicly commits to.
///
/// The statement proven is:
///   "Running the rustc toolchain identified by `bundle_sha256` on the source
///    identified by `source_sha256`, with the argv vectors identified by
///    `rustc_argv_sha256` / `lld_argv_sha256`, produced the object file
///    `obj_sha256` and the linked ELF `bin_sha256`; executing that ELF
///    produced stdout `stdout_sha256` — all inside a deterministic RV64
///    usermode Linux emulator."
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CompilationPublicValues {
    /// sha256 of the rootfs bundle (toolchain + libc): the compiler identity.
    pub bundle_sha256: [u8; 32],
    /// sha256 of the Rust source file being compiled.
    pub source_sha256: [u8; 32],
    /// sha256 of rustc argv (strings joined with '\0').
    pub rustc_argv_sha256: [u8; 32],
    /// sha256 of rust-lld argv (strings joined with '\0').
    pub lld_argv_sha256: [u8; 32],
    /// sha256 of the emitted object file.
    pub obj_sha256: [u8; 32],
    /// sha256 of the linked static ELF executable.
    pub bin_sha256: [u8; 32],
    /// sha256 of the stdout produced by running the compiled ELF.
    pub stdout_sha256: [u8; 32],
    pub rustc_exit: i32,
    pub lld_exit: i32,
    pub run_exit: i32,
    pub rustc_instret: u64,
    pub lld_instret: u64,
    pub run_instret: u64,
}

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
