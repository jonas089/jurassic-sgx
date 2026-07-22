//! The source→binary binding claim.
//!
//! An SP1 guest compiles source → binary and `commit`s a [`BuildClaim`] to its
//! public values. The host runs the guest in dry-run (`execute`) mode and
//! captures that claim. The in-enclave RISC-V executor *replays* the same guest
//! over the same input, re-derives the claim, and — only if it matches — signs
//! it via the existing `Envelope`/registry. Because the enclave recomputes the
//! compile, a wrong source cannot be bound to a given binary.
//!
//! All three components (guest, host, enclave) share this module so they agree
//! byte-for-byte on what is committed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::Hash32;

pub const DOMAIN_BUILD_CLAIM: &[u8] = b"sgx-attest:build-claim:v1";

/// The committed statement: "guest G, using toolchain T, compiled source S into
/// binary B."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildClaim {
    /// Hash of the SP1 guest program (rv32im ELF) that performed the build —
    /// the enclave must replay this exact guest.
    pub guest_id: Hash32,
    /// Hash of the toolchain the guest embedded/used (rustc + sysroot image).
    pub toolchain_id: Hash32,
    /// SHA-256 of the exact source bytes the compiler started from.
    pub source_hash: Hash32,
    /// SHA-256 of the binary the compiler produced.
    pub binary_hash: Hash32,
}

impl BuildClaim {
    /// Canonical, domain-separated commitment bytes. The SP1 guest commits
    /// exactly this digest; the enclave recomputes it from the replay and
    /// requires equality before attesting.
    pub fn commitment(&self) -> Hash32 {
        let mut h = Sha256::new();
        h.update(DOMAIN_BUILD_CLAIM);
        h.update(self.guest_id);
        h.update(self.toolchain_id);
        h.update(self.source_hash);
        h.update(self.binary_hash);
        h.finalize().into()
    }
}

/// What the host dry-run hands to the enclave: enough to deterministically
/// replay the guest and reproduce the claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceArtifact {
    /// SHA-256 of the SP1 guest ELF the enclave will replay (the ELF itself is
    /// streamed in separately / pinned in the registry, not carried inline).
    pub guest_elf_sha256: Hash32,
    /// The input fed to the guest on stdin: the source bytes plus any pinned
    /// inputs the guest reads (e.g. an embedded sysroot handle).
    pub input: Vec<u8>,
    /// The claim the host observed the dry-run commit. The enclave must
    /// independently reproduce this by replaying; it is NOT trusted as given.
    pub expected: BuildClaim,
}
