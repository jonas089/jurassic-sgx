//! Reads a registry.json, prints the Merkle root and writes a `root.txt`.
use attest_registry::Registry;

fn main() {
    let registry_path = std::env::args().nth(1).expect("usage: publish-root <registry.json>");
    let s = std::fs::read_to_string(&registry_path).unwrap();
    let r: Registry = serde_json::from_str(&s).unwrap();
    let root = r.root();
    let hex_root = hex::encode(root);
    println!("Merkle root: {}", hex_root);
    println!("Leaves     : {}", r.leaves.len());
    for l in &r.leaves {
        println!("  - program={:<16} MRENCLAVE={} PUBKEY={}",
                 l.program_name,
                 hex::encode(l.mrenclave.0),
                 hex::encode(l.pubkey.0));
    }
    let dst = std::path::Path::new(&registry_path).with_file_name("root.txt");
    std::fs::write(&dst, format!("{}\n", hex_root)).unwrap();
    println!("wrote {}", dst.display());
}
