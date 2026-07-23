//! Public values a compile proof commits to — shared between the host (CLI:
//! builds requests, verifies envelopes) and the guest (`replay-rustc`:
//! signs these as the Envelope's `output`).

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Everything a single-file compile proof publicly commits to.
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

// ---------------------------------------------------------------------------
// Multi-crate workspace compilation: a host-built plan of local crates + path
// dependencies, sent to the enclave alongside the packed source tree, and the
// public values the enclave commits to after executing that exact plan.

/// Whether a plan unit is a dependency (`--extern`-able rlib) or the final
/// linked program.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanCrateType {
    Lib,
    Bin,
}

/// One crate in a [`BuildPlanDto`]: where its root file lives (relative to
/// the workspace source root) and which earlier units it `--extern`s on.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PlanCrateUnit {
    pub name: String,
    pub entry: String,
    pub crate_type: PlanCrateType,
    /// This crate's own `Cargo.toml` `edition` (defaults to `"2015"` if
    /// omitted, matching real Cargo).
    pub edition: String,
    /// Activated feature names, passed to rustc as `--cfg feature="name"`.
    pub cfg_features: Vec<String>,
    /// `(extern_name, dependency unit name)` pairs.
    pub externs: Vec<(String, String)>,
}

/// The host-computed, already-topologically-sorted build plan for a
/// multi-crate workspace: local path dependencies and (optionally)
/// crates.io dependencies fetched and vendored in by `workspace::discover`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BuildPlanDto {
    pub units: Vec<PlanCrateUnit>,
}

/// Public values recorded for one compiled unit within a workspace build.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UnitPublicValues {
    pub name: String,
    pub crate_type: PlanCrateType,
    pub externs: Vec<(String, String)>,
    pub argv_sha256: [u8; 32],
    pub artifact_sha256: [u8; 32],
    pub exit_code: i32,
    pub instret: u64,
}

/// Everything a multi-crate compile-workspace proof publicly commits to,
/// mirroring [`CompilationPublicValues`] but for an N-crate build: the
/// executed plan (bound via `plan_sha256`, and per-unit above), the whole
/// source tree (`source_tree_sha256`), and the final link + run.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePublicValues {
    pub bundle_sha256: [u8; 32],
    pub source_tree_sha256: [u8; 32],
    /// sha256 of the exact build-plan JSON bytes the enclave received (this
    /// is also the Envelope's signed `input`, so a verifier can decode and
    /// display the plan that was actually executed).
    pub plan_sha256: [u8; 32],
    pub units: Vec<UnitPublicValues>,
    pub link_argv_sha256: [u8; 32],
    pub bin_sha256: [u8; 32],
    pub stdout_sha256: [u8; 32],
    pub link_exit: i32,
    pub run_exit: i32,
    pub link_instret: u64,
    pub run_instret: u64,
}
