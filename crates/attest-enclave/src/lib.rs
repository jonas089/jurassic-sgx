//! In-enclave SDK: derive a per-enclave Ed25519 identity from EGETKEY,
//! sign a structured Attestation over (input, output) and emit an Envelope.
//!
//! Input is taken from `argv[1]` (UTF-8 string) so that EDP stdin EOF quirks
//! don't bite us; bytes-as-string is fine for our workloads (numeric inputs,
//! JSON, etc.).

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use attest_core::{
    sha256, Attestation, Envelope, Hash32, Mrenclave, PubKey, Sig, SignedAttestation,
    DOMAIN_KDF, VERSION,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;

#[cfg(target_env = "sgx")]
fn platform_seal_and_mrenclave() -> ([u8; 32], [u8; 16]) {
    use sgx_isa::{Keyname, Keypolicy, Keyrequest, Report};
    let self_report = Report::for_self();
    let mrenclave = self_report.mrenclave;

    let kreq = Keyrequest {
        keyname: Keyname::Seal as u16,
        keypolicy: Keypolicy::MRENCLAVE,
        ..Default::default()
    };
    let seal16 = kreq.egetkey().expect("EGETKEY failed");
    (mrenclave, seal16)
}

#[cfg(not(target_env = "sgx"))]
fn platform_seal_and_mrenclave() -> ([u8; 32], [u8; 16]) {
    let mr = sha256(b"non-sgx-stub-mrenclave");
    let mut seal = [0u8; 16];
    seal.copy_from_slice(&sha256(b"non-sgx-stub-seal")[..16]);
    (mr, seal)
}

fn derive_signing_key(seal16: &[u8; 16], mrenclave: &[u8; 32]) -> SigningKey {
    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_KDF), seal16);
    let mut seed = [0u8; 32];
    let mut info = Vec::with_capacity(DOMAIN_KDF.len() + mrenclave.len());
    info.extend_from_slice(b"ed25519-seed/");
    info.extend_from_slice(mrenclave);
    hk.expand(&info, &mut seed).expect("hkdf expand");
    SigningKey::from_bytes(&seed)
}

pub struct Identity {
    pub mrenclave: [u8; 32],
    pub signing_key: SigningKey,
}

impl Identity {
    pub fn derive() -> Self {
        let (mrenclave, seal16) = platform_seal_and_mrenclave();
        let sk = derive_signing_key(&seal16, &mrenclave);
        Self { mrenclave, signing_key: sk }
    }
    pub fn pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

/// Take input from argv[1] (UTF-8) — EDP propagates argv via usercall.
pub fn read_input_from_argv() -> Vec<u8> {
    std::env::args().nth(1).unwrap_or_default().into_bytes()
}

pub fn write_envelope_stdout(env: &Envelope) {
    let s = serde_json::to_string(env).expect("serialize envelope");
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes()).unwrap();
    out.write_all(b"\n").unwrap();
}

fn fresh_nonce() -> Hash32 {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).expect("getrandom");
    n
}

fn program_id(program_name: &str) -> Hash32 {
    let mut buf = Vec::with_capacity(16 + program_name.len());
    buf.extend_from_slice(b"program-id-v1/");
    buf.extend_from_slice(program_name.as_bytes());
    sha256(&buf)
}

/// Run a pure compute closure inside the enclave: caller-provided input, compute, sign, emit.
pub fn commit_with_input<F>(program_name: &str, input: Vec<u8>, f: F)
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    let id = Identity::derive();
    let output = f(&input);

    let att = Attestation {
        version: VERSION,
        mrenclave: Mrenclave(id.mrenclave),
        program_id: program_id(program_name),
        input_hash: sha256(&input),
        output_hash: sha256(&output),
        nonce: fresh_nonce(),
        timestamp_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    let msg = att.signing_bytes();
    let sig = id.signing_key.sign(&msg);
    let signed = SignedAttestation {
        att,
        pubkey: PubKey(id.pubkey()),
        signature: Sig(sig.to_bytes()),
    };
    let envelope = Envelope { signed, input, output };
    write_envelope_stdout(&envelope);
}

pub fn enroll(program_name: &str) {
    let id = Identity::derive();
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(b"sgx-attest:enroll:v1");
    h.update(id.mrenclave);
    h.update(id.pubkey());
    h.update(program_name.as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let sig = id.signing_key.sign(&digest);

    let proof = serde_json::json!({
        "version": VERSION,
        "mrenclave": hex::encode(id.mrenclave),
        "pubkey":    hex::encode(id.pubkey()),
        "program_name": program_name,
        "self_signature": hex::encode(sig.to_bytes()),
    });
    println!("{}", proof);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_key_on_stub() {
        let a = Identity::derive();
        let b = Identity::derive();
        assert_eq!(a.pubkey(), b.pubkey());
    }
}
