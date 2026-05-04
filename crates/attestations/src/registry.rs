//! Sorted-leaf binary Merkle tree of `(MRENCLAVE, pubkey, program_name)` leaves.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::{Hash32, Leaf, DOMAIN_NODE};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    pub leaves: Vec<Leaf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: Hash32,
    pub siblings: Vec<Hash32>,
    pub directions: Vec<bool>, // true = sibling is on the right
}

fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_NODE);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

impl Registry {
    pub fn new() -> Self { Self::default() }

    pub fn add(&mut self, leaf: Leaf) {
        if !self.leaves.iter().any(|l| l.mrenclave == leaf.mrenclave) {
            self.leaves.push(leaf);
        }
        self.leaves.sort_by(|a, b| a.mrenclave.0.cmp(&b.mrenclave.0));
    }

    fn leaf_hashes(&self) -> Vec<Hash32> {
        self.leaves.iter().map(Leaf::hash).collect()
    }

    pub fn root(&self) -> Hash32 {
        let leaves = self.leaf_hashes();
        if leaves.is_empty() { return [0u8; 32]; }
        let mut layer = leaves;
        while layer.len() > 1 {
            if layer.len() % 2 == 1 { layer.push(*layer.last().unwrap()); }
            layer = layer.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
        }
        layer[0]
    }

    pub fn prove(&self, mrenclave: &[u8; 32]) -> Option<MerkleProof> {
        let leaves = self.leaf_hashes();
        let leaf_index = self.leaves.iter().position(|l| &l.mrenclave.0 == mrenclave)?;
        let leaf_hash = leaves[leaf_index];
        let mut layer = leaves;
        let mut idx = leaf_index;
        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        while layer.len() > 1 {
            if layer.len() % 2 == 1 { layer.push(*layer.last().unwrap()); }
            let sib_idx = idx ^ 1;
            siblings.push(layer[sib_idx]);
            directions.push(idx % 2 == 0);
            layer = layer.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
            idx /= 2;
        }
        Some(MerkleProof { leaf_index, leaf_hash, siblings, directions })
    }
}

pub fn verify_proof(root: &Hash32, leaf: &Leaf, proof: &MerkleProof) -> bool {
    if leaf.hash() != proof.leaf_hash { return false; }
    let mut acc = proof.leaf_hash;
    for (sib, &right) in proof.siblings.iter().zip(proof.directions.iter()) {
        acc = if right { node_hash(&acc, sib) } else { node_hash(sib, &acc) };
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Mrenclave, PubKey};

    fn mk_leaf(name: &str, seed: u8) -> Leaf {
        Leaf {
            mrenclave: Mrenclave([seed; 32]),
            pubkey: PubKey([seed.wrapping_add(1); 32]),
            program_name: name.into(),
        }
    }

    #[test]
    fn single_leaf_root_and_proof() {
        let mut r = Registry::new();
        let l = mk_leaf("fib", 7);
        r.add(l.clone());
        let root = r.root();
        let proof = r.prove(&l.mrenclave.0).unwrap();
        assert!(verify_proof(&root, &l, &proof));
    }

    #[test]
    fn three_leaf_proof() {
        let mut r = Registry::new();
        for s in [3u8, 1, 2] { r.add(mk_leaf("p", s)); }
        let root = r.root();
        for s in [1u8, 2, 3] {
            let l = mk_leaf("p", s);
            let p = r.prove(&l.mrenclave.0).unwrap();
            assert!(verify_proof(&root, &l, &p));
        }
    }
}
