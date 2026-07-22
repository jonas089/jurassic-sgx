//! In-enclave replay engine (feature `replay`).
//!
//! Given a [`Transcript`], recompute the steps marked [`Replay::InEnclave`]
//! using pure, no-I/O Rust (so this runs on `x86_64-fortanix-unknown-sgx`),
//! verify the hash chain is contiguous from source to binary, and produce a
//! [`ReplayReport`]. Steps marked [`Replay::PublicInput`] are trusted as given
//! and pinned by hash.
//!
//! The set of replayers is the extensibility point: as more of the pipeline
//! becomes reproducible in-enclave, entries move from `PublicInput` to
//! `InEnclave` and the attestation strengthens with no format change.

use quote::ToTokens;

use crate::core::{sha256, Hash32};
use crate::transcript::{Replay, ReplayReport, Step, StepResult, Transcript};

/// Canonicalize Rust source by parsing it with `syn` and re-emitting the token
/// stream, then hashing the normalized text. Pure computation, no I/O — the
/// enclave independently re-derives this from the source bytes it received.
///
/// This is a real reproduced step: the enclave proves it parsed *exactly* this
/// source into a well-formed Rust AST whose canonical form hashes to `output`.
pub fn canonical_ast_hash(source: &[u8]) -> Result<Hash32, String> {
    let text = core::str::from_utf8(source).map_err(|e| format!("source not utf-8: {e}"))?;
    let file = syn::parse_file(text).map_err(|e| format!("syn parse failed: {e}"))?;
    let normalized = file.into_token_stream().to_string();
    Ok(sha256(normalized.as_bytes()))
}

/// Run a named replayer against the transcript. Returns the recomputed output
/// hash, or `None` if the replayer name is unknown or recomputation failed.
fn run_replayer(name: &str, t: &Transcript) -> Option<Hash32> {
    match name {
        // The enclave re-hashes the source it received.
        "source-sha256" => Some(sha256(&t.source)),
        // The enclave re-parses the source into a canonical AST.
        "syn-canonical-ast" => canonical_ast_hash(&t.source).ok(),
        _ => None,
    }
}

/// Replay a transcript: recompute the in-enclave steps, verify chain
/// contiguity, and summarize what was verified vs. trusted.
pub fn replay(t: &Transcript) -> ReplayReport {
    let mut replayed: Vec<StepResult> = Vec::new();
    let mut chain_ok = true;
    let mut all_replays_ok = true;
    let mut prev_output: Option<Hash32> = None;

    for step in &t.steps {
        // Chain contiguity: every step after the first must consume the
        // previous step's output.
        if let Some(prev) = prev_output {
            if !step.inputs.contains(&prev) {
                chain_ok = false;
            }
        }

        if let Step { replay: Replay::InEnclave { replayer }, output, name, .. } = step {
            let recomputed = run_replayer(replayer, t);
            let ok = recomputed == Some(*output);
            if !ok {
                all_replays_ok = false;
            }
            replayed.push(StepResult {
                name: name.clone(),
                replayer: replayer.clone(),
                expected: *output,
                recomputed: recomputed.unwrap_or([0u8; 32]),
                ok,
            });
        }

        prev_output = Some(step.output);
    }

    // The chain must terminate at the declared binary hash.
    if prev_output != Some(t.binary) {
        chain_ok = false;
    }

    ReplayReport {
        program: t.program.clone(),
        rustc_version: t.rustc_version.clone(),
        target: t.target.clone(),
        source_hash: sha256(&t.source),
        binary_hash: t.binary,
        replayed,
        public_inputs: t.public_inputs.clone(),
        chain_ok,
        all_replays_ok,
    }
}
