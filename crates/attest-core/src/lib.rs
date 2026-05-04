#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: u8 = 1;
pub const DOMAIN_LEAF: &[u8] = b"sgx-attest:leaf:v1";
pub const DOMAIN_NODE: &[u8] = b"sgx-attest:node:v1";
pub const DOMAIN_ATT:  &[u8] = b"sgx-attest:attestation:v1";
pub const DOMAIN_KDF:  &[u8] = b"sgx-attest:ed25519-derive:v1";

pub type Hash32 = [u8; 32];

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mrenclave(pub Hash32);

impl fmt::Debug for Mrenclave {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mrenclave({})", hex::encode(self.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PubKey(pub [u8; 32]);

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PubKey({})", hex::encode(self.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sig(#[serde(with = "serde_arrays")] pub [u8; 64]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({})", hex::encode(self.0))
    }
}

mod serde_arrays {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        v.as_ref().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: alloc::vec::Vec<u8> = Deserialize::deserialize(d)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub version: u8,
    pub mrenclave: Mrenclave,
    pub program_id: Hash32,
    pub input_hash: Hash32,
    pub output_hash: Hash32,
    pub nonce: Hash32,
    pub timestamp_unix: u64,
}

impl Attestation {
    /// Canonical signing bytes: domain-separated, fixed layout.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(DOMAIN_ATT);
        h.update([self.version]);
        h.update(self.mrenclave.0);
        h.update(self.program_id);
        h.update(self.input_hash);
        h.update(self.output_hash);
        h.update(self.nonce);
        h.update(self.timestamp_unix.to_le_bytes());
        h.finalize().to_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub att: Attestation,
    pub pubkey: PubKey,
    pub signature: Sig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Leaf {
    pub mrenclave: Mrenclave,
    pub pubkey: PubKey,
    pub program_name: String,
}

impl Leaf {
    pub fn hash(&self) -> Hash32 {
        let mut h = Sha256::new();
        h.update(DOMAIN_LEAF);
        h.update(self.mrenclave.0);
        h.update(self.pubkey.0);
        h.update((self.program_name.len() as u32).to_le_bytes());
        h.update(self.program_name.as_bytes());
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub signed: SignedAttestation,
    pub input:  Vec<u8>,
    pub output: Vec<u8>,
}

pub fn sha256(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
