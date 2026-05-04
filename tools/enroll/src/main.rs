//! Read an enrollment proof (JSON) from stdin, append the leaf to a registry file.
//!
//! The enrollment proof is the JSON the fibonacci-enroll enclave prints on stdout.
//! Trust model: the registry operator runs this only on output captured directly
//! from a known-good SGX box; the self-signature is checked here as a sanity check.

use std::io::Read;

use attest_core::{Leaf, Mrenclave, PubKey};
use attest_registry::Registry;

fn main() {
    let registry_path = std::env::args().nth(1)
        .expect("usage: enroll <registry.json>");

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let proof: serde_json::Value = serde_json::from_str(&input).expect("parse proof");

    let mrenclave_hex = proof["mrenclave"].as_str().expect("mrenclave");
    let pubkey_hex    = proof["pubkey"].as_str().expect("pubkey");
    let program_name  = proof["program_name"].as_str().expect("program_name");
    let sig_hex       = proof["self_signature"].as_str().expect("self_signature");

    let mrenclave: [u8; 32] = hex::decode(mrenclave_hex).unwrap().try_into().unwrap();
    let pubkey:    [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();

    // sanity-check self-signature
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sgx-attest:enroll:v1");
    h.update(mrenclave);
    h.update(pubkey);
    h.update(program_name.as_bytes());
    let digest: [u8; 32] = h.finalize().into();

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).expect("pubkey");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    vk.verify(&digest, &sig).expect("self-signature invalid");

    let mut registry: Registry = if std::path::Path::new(&registry_path).exists() {
        let s = std::fs::read_to_string(&registry_path).unwrap();
        serde_json::from_str(&s).unwrap_or_else(|_| Registry::new())
    } else {
        Registry::new()
    };
    registry.add(Leaf {
        mrenclave: Mrenclave(mrenclave),
        pubkey: PubKey(pubkey),
        program_name: program_name.to_string(),
    });
    std::fs::write(&registry_path, serde_json::to_string_pretty(&registry).unwrap()).unwrap();

    println!("enrolled program={} MRENCLAVE={}", program_name, mrenclave_hex);
    println!("registry root = {}", hex::encode(registry.root()));
}

