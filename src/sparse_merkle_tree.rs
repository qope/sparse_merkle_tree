use plonky2::{
    hash::{hash_types::RichField, merkle_proofs::MerkleProof},
    plonk::config::Hasher,
};

use std::collections::HashMap;

#[derive(Debug)]
pub struct SparseMerkleTree<F: RichField, H: Hasher<F>> {
    pub height: usize,
    pub nodes: HashMap<Vec<bool>, Node<F, H>>,
    zero_hashes: Vec<H::Hash>,
}

impl<F: RichField, H: Hasher<F>> SparseMerkleTree<F, H> {
    pub fn new(height: usize) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let node = Node::Leaf::<F, H> {
            value: vec![F::ZERO; 4],
        };
        let mut h = node.hash();
        zero_hashes.push(h);
        for _ in 0..height {
            let node = Node::InnerNode::<F, H> { left: h, right: h };
            h = node.hash();
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let nodes: HashMap<Vec<bool>, Node<F, H>> = HashMap::new();

        Self {
            height,
            nodes,
            zero_hashes,
        }
    }

    pub fn get_leaf(&self, path: &Vec<bool>) -> Vec<F> {
        assert_eq!(path.len(), self.height);
        match self.nodes.get(path) {
            Some(Node::Leaf { value }) => value.clone(),
            _ => panic!(),
        }
    }

    pub fn get_node_hash(&self, path: &Vec<bool>) -> H::Hash {
        assert!(path.len() <= self.height);
        match self.nodes.get(path) {
            Some(node) => node.hash(),
            None => self.zero_hashes[path.len()],
        }
    }

    pub fn get_root(&self) -> H::Hash {
        self.get_node_hash(&vec![])
    }

    pub fn get_sibling_hash(&self, path: &Vec<bool>) -> H::Hash {
        assert!(path.len() > 0);
        // TODO maybe more elegant code exists
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];
        self.get_node_hash(&path)
    }

    pub fn update(&mut self, path: &Vec<bool>, value: Vec<F>) {
        assert_eq!(path.len(), self.height);
        let mut path = path.clone();

        self.nodes.insert(path.clone(), Node::Leaf { value });

        loop {
            let hash = self.get_node_hash(&path);
            let parent_path = path[0..path.len() - 1].to_vec();
            self.nodes.insert(
                parent_path,
                if path[path.len() - 1] {
                    Node::InnerNode {
                        left: self.get_sibling_hash(&path),
                        right: hash,
                    }
                } else {
                    Node::InnerNode {
                        left: hash,
                        right: self.get_sibling_hash(&path),
                    }
                },
            );
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }
    }

    pub fn prove(&self, path: &Vec<bool>) -> MerkleProof<F, H> {
        assert_eq!(path.len(), self.height);
        let mut path = path.clone();
        let mut siblings = vec![];
        loop {
            siblings.push(self.get_sibling_hash(&path));
            if path.len() == 1 {
                break;
            } else {
                path.pop();
            }
        }
        MerkleProof { siblings }
    }
}

#[derive(Debug)]
pub enum Node<F: RichField, H: Hasher<F>> {
    InnerNode { left: H::Hash, right: H::Hash },
    Leaf { value: Vec<F> },
}

impl<F: RichField, H: Hasher<F>> Node<F, H> {
    fn hash(&self) -> H::Hash {
        match self {
            Node::InnerNode { left, right } => H::two_to_one(left.clone(), right.clone()),
            Node::Leaf { value } => H::hash_or_noop(&value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::types::Sample,
        hash::{merkle_proofs::verify_merkle_proof, poseidon::PoseidonHash},
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type H = PoseidonHash;

    fn usize_to_vec(x: usize, length: usize) -> Vec<bool> {
        let mut x = x;
        let mut v = vec![];
        for _ in 0..length {
            v.push((x & 1) == 1);
            x >>= 1;
        }
        v.reverse();
        v
    }

    #[test]
    fn tree_test() {
        let mut rng = rand::thread_rng();
        let height = 100;
        let mut tree = SparseMerkleTree::<F, H>::new(height);

        for _ in 0..10000 {
            let index = rng.gen_range(0..1 << height);
            let path = usize_to_vec(index, height);
            let new_leaf = F::rand_vec(4);
            tree.update(&path, new_leaf.clone());
            let proof = tree.prove(&path);
            assert_eq!(tree.get_leaf(&path), new_leaf.clone());
            verify_merkle_proof(new_leaf, index, tree.get_root(), &proof).unwrap();
        }
    }
}
