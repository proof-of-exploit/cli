use super::utils::{Nibbles, Trie};
use crate::error::Error;
use ethers::types::{Bytes, H256};

#[derive(Debug, Clone)]
pub struct StorageTrie(Trie);

impl StorageTrie {
    pub fn new() -> Self {
        StorageTrie(Trie::new())
    }

    pub fn from_root(root: H256) -> Self {
        StorageTrie(Trie::from_root(root))
    }

    pub fn set_root(&mut self, root: H256) -> Result<(), Error> {
        self.0.set_root(root)
    }

    pub fn root(&self) -> Option<H256> {
        self.0.root
    }

    pub fn get_value(&self, path: Nibbles) -> Result<H256, Error> {
        let bytes = self.0.get_value(path)?;
        Ok(H256::from_slice(bytes.to_vec().as_slice()))
    }

    pub fn set_value(&mut self, path: Nibbles, new_value: H256) -> Result<(), Error> {
        self.0
            .set_value(path, Bytes::from(new_value.as_bytes().to_vec()))
    }

    pub fn load_proof(
        &mut self,
        key: Nibbles,
        value: H256,
        proof: Vec<Bytes>,
    ) -> Result<(), Error> {
        self.0
            .load_proof(key, Bytes::from(value.as_bytes().to_vec()), proof)
    }
}
