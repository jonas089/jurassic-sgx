//! verify-envelope <registry.json> <envelope.json>
//!
//! Looks up the leaf for the envelope's MRENCLAVE in the registry,
//! generates a Merkle proof, and runs the full verifier.
//! Anyone can do this — no SGX required.

use attest_core::Envelope;
use attest_registry::Registry;
use attest_verify::verify_envelope;

fn main() {
    let mut args = std::env::args().skip(1);
    let registry_path = args.next().expect("usage: verify-envelope <registry.json> <envelope.json>");
    let envelope_path = args.next().expect("usage: verify-envelope <registry.json> <envelope.json>");

    let registry: Registry = serde_json::from_str(&std::fs::read_to_string(&registry_path).unwrap()).unwrap();
    let envelope: Envelope = serde_json::from_str(&std::fs::read_to_string(&envelope_path).unwrap()).unwrap();

    let root = registry.root();
    let mr = envelope.signed.att.mrenclave.0;
    let leaf = registry.leaves.iter().find(|l| l.mrenclave.0 == mr)
        .unwrap_or_else(|| panic!("MRENCLAVE {} not in registry", hex::encode(mr)))
        .clone();
    let proof = registry.prove(&mr).expect("merkle proof");

    match verify_envelope(&root, &leaf, &proof, &envelope) {
        Ok(v) => {
            println!("PASS");
            println!("  registry root = {}", hex::encode(root));
            println!("  MRENCLAVE     = {}", hex::encode(v.mrenclave));
            println!("  program       = {}", v.program_name);
            println!("  timestamp     = {}", v.timestamp_unix);
            println!("  input  ({:>4}B) = {}", v.input.len(),
                     std::str::from_utf8(v.input).unwrap_or(&hex::encode(v.input)));
            println!("  output ({:>4}B) = {}", v.output.len(),
                     std::str::from_utf8(v.output).unwrap_or(&hex::encode(v.output)));
        }
        Err(e) => {
            eprintln!("FAIL: {:?}", e);
            std::process::exit(1);
        }
    }
}
