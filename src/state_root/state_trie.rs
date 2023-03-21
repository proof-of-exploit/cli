use std::collections::HashMap;

use ethers::types::{EIP1186ProofResponse, H256};

use super::{account_trie::AccountTrie, storage_trie::StorageTrie};

pub struct StateTrie {
    account_trie: AccountTrie,
    storage_tries: HashMap<H256, StorageTrie>,
}

impl StateTrie {
    pub fn new() -> Self {
        StateTrie {
            account_trie: AccountTrie::new(),
            storage_tries: HashMap::new(),
        }
    }

    pub fn from_root(root: H256) -> Self {
        StateTrie {
            account_trie: AccountTrie::from_root(root),
            storage_tries: HashMap::new(),
        }
    }

    pub fn load_proof(&self, proof: EIP1186ProofResponse) {
        todo!()
    }
}
