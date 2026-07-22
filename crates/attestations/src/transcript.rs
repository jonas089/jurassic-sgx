//! Compilation transcript: a serialized record of a `rustc` compilation
//! produced on the (untrusted) host, plus the report the enclave emits after
//! selectively *replaying* the parts it can and pinning the rest as public
//! inputs.
//!
//! The transcript handed to the enclave is deliberately compact: it carries the
//! full source bytes (so the enclave can hash + parse them itself) but only the
//! *hashes* of the heavy artifacts (MIR, LLVM-IR, object, binary). The bulky
//! artifacts stay on the host; the enclave attests over their hashes.
//!
//! These types are plain serde structs — no parser dependency — so the verifier
//! and the host tool can use them without enabling the `replay` feature.

use serde::{Deserialize, Serialize};

use crate::core::Hash32;

/// How the enclave should treat a step in the compilation chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Replay {
    /// The enclave recomputes this step's output from the source using a named
    /// pure replayer and checks it against the declared `output` hash.
    InEnclave { replayer: String },
    /// The enclave cannot reproduce this step (needs LLVM / the linker / the
    /// sysroot). It accepts the declared `output` as a pinned public input.
    PublicInput,
}

/// One stage boundary in the compilation, e.g. `source -> ast`, `mir -> obj`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step {
    /// Human-readable stage name, e.g. `"source"`, `"ast"`, `"mir"`, `"obj"`.
    pub name: String,
    /// Whether the enclave replays this step or trusts it as a public input.
    pub replay: Replay,
    /// Hashes of the artifacts feeding this step (used to check chain
    /// contiguity: a step's inputs must contain the previous step's output).
    pub inputs: Vec<Hash32>,
    /// Hash of the artifact this step produced.
    pub output: Hash32,
}

/// An external input the enclave cannot reproduce, pinned by hash so a verifier
/// (or a second, more capable prover) can independently check it: sysroot
/// rlibs, the `rustc` binary itself, etc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInput {
    /// Path or logical name of the input.
    pub name: String,
    /// SHA-256 of the input's bytes.
    pub hash: Hash32,
}

/// The compact transcript fed to the enclave.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transcript {
    pub program: String,
    pub rustc_version: String,
    pub target: String,
    pub flags: Vec<String>,
    /// Full source bytes — the enclave hashes and parses these itself.
    pub source: Vec<u8>,
    /// Inputs the host read that the enclave cannot reproduce, pinned by hash.
    pub public_inputs: Vec<PublicInput>,
    /// The ordered compilation chain, from source to binary.
    pub steps: Vec<Step>,
    /// Hash of the final linked binary (the chain endpoint).
    pub binary: Hash32,
}

/// Verdict for a single step the enclave replayed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepResult {
    pub name: String,
    pub replayer: String,
    /// The hash the transcript claimed for this step's output.
    pub expected: Hash32,
    /// The hash the enclave independently recomputed.
    pub recomputed: Hash32,
    pub ok: bool,
}

/// What the enclave emits (as the `output` of the signed envelope) after
/// replaying a transcript. Binds the source to the binary via the steps the
/// enclave could verify, and enumerates exactly what it had to trust.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayReport {
    pub program: String,
    pub rustc_version: String,
    pub target: String,
    /// SHA-256 the enclave computed over the source it received.
    pub source_hash: Hash32,
    /// The binary hash the enclave attests this compilation produced.
    pub binary_hash: Hash32,
    /// Steps the enclave recomputed in-enclave, with verdicts.
    pub replayed: Vec<StepResult>,
    /// Steps/inputs the enclave trusted as given, pinned by hash.
    pub public_inputs: Vec<PublicInput>,
    /// True iff every step's inputs chain to the previous output and the last
    /// output equals `binary`.
    pub chain_ok: bool,
    /// True iff every in-enclave replay matched its declared output.
    pub all_replays_ok: bool,
}

impl ReplayReport {
    /// The attestation is meaningful only if the chain is contiguous and every
    /// replayed step matched.
    pub fn verified(&self) -> bool {
        self.chain_ok && self.all_replays_ok
    }
}
