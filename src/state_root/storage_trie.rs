use super::utils::{Nibbles, Trie};
use crate::error::Error;
use ethers::{
    prelude::EthDisplay,
    types::{BigEndianHash, Bytes, H256, U256},
};

#[derive(Debug, Clone, EthDisplay, PartialEq)]
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

    pub fn get_value(&self, key: U256) -> Result<U256, Error> {
        let path = Nibbles::from_uint(key)?;
        let bytes = self.0.get_value(path)?;
        Ok(U256::from_big_endian(bytes.to_vec().as_slice()))
    }

    pub fn set_value(&mut self, key: U256, new_value: U256) -> Result<(), Error> {
        let path = Nibbles::from_uint(key)?;
        self.0.set_value(path, u256_to_bytes(new_value))
    }

    pub fn load_proof(&mut self, key: U256, value: U256, proof: Vec<Bytes>) -> Result<(), Error> {
        let path = Nibbles::from_uint(key)?;
        self.0.load_proof(path, u256_to_bytes(value), proof)
    }
}

fn u256_to_bytes(value: U256) -> Bytes {
    let mut vec = H256::from_uint(&value).as_bytes().to_vec();
    loop {
        if vec[0] == 0 {
            vec.remove(0);
        } else {
            break;
        }
    }
    Bytes::from(vec)
}
