//! End-to-end attestation library: shared types, in-enclave key derivation +
//! signing, host-side Merkle registry, and external verifier — all in one crate.

pub mod core;
pub mod enclave;
pub mod registry;
pub mod verify;

pub use crate::core::{
    sha256, Attestation, Envelope, Hash32, Leaf, Mrenclave, PubKey, Sig, SignedAttestation,
    DOMAIN_ATT, DOMAIN_KDF, DOMAIN_LEAF, DOMAIN_NODE, VERSION,
};
