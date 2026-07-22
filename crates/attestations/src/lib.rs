//! End-to-end attestation library: shared types, in-enclave key derivation +
//! signing, host-side Merkle registry, and external verifier — all in one crate.

pub mod build_claim;
pub mod core;
pub mod enclave;
pub mod registry;
pub mod transcript;
pub mod verify;

#[cfg(feature = "replay")]
pub mod replay;

pub use crate::core::{
    sha256, Attestation, Envelope, Hash32, Leaf, Mrenclave, PubKey, Sig, SignedAttestation,
    DOMAIN_ATT, DOMAIN_KDF, DOMAIN_LEAF, DOMAIN_NODE, VERSION,
};
pub use crate::build_claim::{BuildClaim, TraceArtifact, DOMAIN_BUILD_CLAIM};
pub use crate::transcript::{
    PublicInput, Replay, ReplayReport, Step, StepResult, Transcript,
};
