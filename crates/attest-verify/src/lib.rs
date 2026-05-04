//! Pure-Rust verifier. No SGX runtime required.
//!
//! Inputs:
//!   * `root`     — the published Merkle root of the trusted-pubkey registry.
//!   * `leaf`     — the (MRENCLAVE, pubkey, program_name) entry for this program.
//!   * `proof`    — Merkle inclusion proof of `leaf` under `root`.
//!   * `envelope` — the signed attestation + input + output emitted by the enclave.
//!
//! Checks:
//!   1. Merkle proof: `leaf` is in the tree under `root`.
//!   2. `signed.pubkey` matches `leaf.pubkey`.
//!   3. `signed.att.mrenclave` matches `leaf.mrenclave`.
//!   4. Recomputed input/output hashes match the attestation.
//!   5. Ed25519 signature over the attestation's canonical signing bytes is valid.

use attest_core::{sha256, Envelope, Hash32, Leaf, SignedAttestation};
use attest_registry::{verify_proof, MerkleProof};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Debug)]
pub enum VerifyError {
    MerkleProofFailed,
    PubkeyMismatch,
    MrenclaveMismatch,
    InputHashMismatch,
    OutputHashMismatch,
    BadPubkey,
    BadSignature,
}

pub struct Verified<'a> {
    pub mrenclave: [u8; 32],
    pub program_name: &'a str,
    pub input: &'a [u8],
    pub output: &'a [u8],
    pub timestamp_unix: u64,
}

pub fn verify_envelope<'a>(
    root: &Hash32,
    leaf: &'a Leaf,
    proof: &MerkleProof,
    envelope: &'a Envelope,
) -> Result<Verified<'a>, VerifyError> {
    if !verify_proof(root, leaf, proof) {
        return Err(VerifyError::MerkleProofFailed);
    }
    let SignedAttestation { att, pubkey, signature } = &envelope.signed;
    if pubkey.0 != leaf.pubkey.0 {
        return Err(VerifyError::PubkeyMismatch);
    }
    if att.mrenclave.0 != leaf.mrenclave.0 {
        return Err(VerifyError::MrenclaveMismatch);
    }
    if sha256(&envelope.input) != att.input_hash {
        return Err(VerifyError::InputHashMismatch);
    }
    if sha256(&envelope.output) != att.output_hash {
        return Err(VerifyError::OutputHashMismatch);
    }
    let vk = VerifyingKey::from_bytes(&pubkey.0).map_err(|_| VerifyError::BadPubkey)?;
    let sig = Signature::from_bytes(&signature.0);
    let msg = att.signing_bytes();
    vk.verify(&msg, &sig).map_err(|_| VerifyError::BadSignature)?;

    Ok(Verified {
        mrenclave: att.mrenclave.0,
        program_name: &leaf.program_name,
        input: &envelope.input,
        output: &envelope.output,
        timestamp_unix: att.timestamp_unix,
    })
}
