use std::collections::HashMap;

use ethers::{
    prelude::EthDisplay,
    types::{Address, EIP1186ProofResponse, H256, U256},
};

use crate::error::Error;

use super::{
    account_trie::{AccountData, AccountTrie},
    storage_trie::StorageTrie,
};

#[derive(Clone, Debug, EthDisplay, PartialEq)]
pub struct StateTrie {
    pub account_trie: AccountTrie,
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

    pub fn root(&self) -> Option<H256> {
        self.account_trie.root()
    }

    pub fn get_storage_trie(&mut self, storage_root: H256) -> StorageTrie {
        if !self.storage_tries.contains_key(&storage_root) {
            StorageTrie::from_root(storage_root)
        } else {
            self.storage_tries.get(&storage_root).unwrap().to_owned()
        }
    }

    pub fn set_storage_value(
        &mut self,
        address: Address,
        slot: U256,
        value: U256,
    ) -> Result<(), Error> {
        let mut account_data = self.account_trie.get_account_data(address)?;
        let mut storage_trie = self
            .storage_tries
            .remove(&account_data.storage_root)
            .expect("storage trie not present, this should not happen");
        storage_trie.set_value(slot, value)?;
        account_data.storage_root = storage_trie.root().unwrap();
        self.storage_tries
            .insert(storage_trie.root().unwrap(), storage_trie);
        self.account_trie.set_account_data(address, account_data)?;
        Ok(())
    }

    pub fn load_proof(&mut self, proof: EIP1186ProofResponse) -> Result<(), Error> {
        self.account_trie.load_proof(
            proof.address,
            AccountData {
                balance: proof.balance,
                nonce: U256::from(proof.nonce.as_u64()),
                code_hash: proof.code_hash,
                storage_root: proof.storage_hash,
            },
            proof.account_proof,
        )?;

        let mut storage_trie = self.get_storage_trie(proof.storage_hash);
        for proof in proof.storage_proof {
            storage_trie.load_proof(
                U256::from_big_endian(proof.key.as_bytes()),
                proof.value, // error is here, value does not need to be 32 byte
                proof.proof,
            )?;
        }
        self.storage_tries.insert(proof.storage_hash, storage_trie);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EIP1186ProofResponse, StateTrie, U256};
    use ethers::types::StorageProof;
    use ethers_core::utils::hex;

    #[test]
    pub fn test_state_1() {
        // a contract was deployed on geth --dev
        // slot[1] = 2
        // slot[2] = 4
        let mut trie = StateTrie::new();

        // contract
        trie.load_proof(EIP1186ProofResponse {
            address: "0x730E01e70B028b44a9387119d78E1392E4848Cbc"
                .parse()
                .unwrap(),
            account_proof: vec![
                "0xf90151a0bfa1a037624f2e96cc598c63c0db6249cb0e507c2015af3e2ecb8b16b58f92b7a0ab8cdb808c8303bb61fb48e276217be9770fa83ecf3f90f2234d558885f5abf1a0d5a5048c1d78dafd61d8181577c08d6cd2b52fde48040a676be755dc69a275db80a01a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a04a0b5d7a91be5ee273cce27e2ad9a160d2faadd5a6ba518d384019b68728a4f62f4a0c2c799b60a0cd6acd42c1015512872e86c186bcf196e85061e76842f3b7cf86080a02e0d86c3befd177f574a20ac63804532889077e955320c9361cd10b7cc6f580980a06301b39b2ea8a44df8b0356120db64b788e71f52e1d7a6309d0d2e5b86fee7cb8080a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0a066a7662811491b3d352e969506b420d269e8b51a224f574b3b38b3463f43f0098080".parse().unwrap(),
                "0xf869a03a7a2ee9b4f54ecbf2e04737a19215c0864d20c9a332db61d093e9ec95b2e87ab846f8440180a029cf2043d2a8fd3c4ed584f1afd2976a366f90a84446c1bd73e251e097b1748ca02e3b8d783952495f405666042a1ceb57bd6848afbbc1f2aad92bc2b5f8169a16".parse().unwrap(),
            ],
            balance: "0x0".parse().unwrap(),
            code_hash: "0x2e3b8d783952495f405666042a1ceb57bd6848afbbc1f2aad92bc2b5f8169a16"
                .parse()
                .unwrap(),
            nonce: "0x1".parse().unwrap(),
            storage_hash: "0x29cf2043d2a8fd3c4ed584f1afd2976a366f90a84446c1bd73e251e097b1748c"
                .parse()
                .unwrap(),
            storage_proof: vec![
                StorageProof {
                    key: "0x0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap(),
                    value: "0x2".parse().unwrap(),
                    proof: vec![
                        "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc5808080808080a0236e8f61ecde6abfebc6c529441f782f62469d8a2cc47b7aace2c136bd3b1ff08080808080".parse().unwrap(),
                        "0xe2a0310e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf602".parse().unwrap()
                    ],
                },
                StorageProof {
                    key: "0x0000000000000000000000000000000000000000000000000000000000000002".parse().unwrap(),
                    value: "0x4".parse().unwrap(),
                    proof: vec![
                        "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc5808080808080a0236e8f61ecde6abfebc6c529441f782f62469d8a2cc47b7aace2c136bd3b1ff08080808080".parse().unwrap(),
                        "0xe2a0305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace04".parse().unwrap()
                    ],
                }
            ],
        }).unwrap();

        // tx sender
        trie.load_proof(EIP1186ProofResponse {
            address: "0x3736b9d9d35d8c4f41d98a412fe9211024453575"
                .parse()
                .unwrap(),
            account_proof: vec![
                "0xf90151a0bfa1a037624f2e96cc598c63c0db6249cb0e507c2015af3e2ecb8b16b58f92b7a0ab8cdb808c8303bb61fb48e276217be9770fa83ecf3f90f2234d558885f5abf1a0d5a5048c1d78dafd61d8181577c08d6cd2b52fde48040a676be755dc69a275db80a01a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a04a0b5d7a91be5ee273cce27e2ad9a160d2faadd5a6ba518d384019b68728a4f62f4a0c2c799b60a0cd6acd42c1015512872e86c186bcf196e85061e76842f3b7cf86080a02e0d86c3befd177f574a20ac63804532889077e955320c9361cd10b7cc6f580980a06301b39b2ea8a44df8b0356120db64b788e71f52e1d7a6309d0d2e5b86fee7cb8080a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0a066a7662811491b3d352e969506b420d269e8b51a224f574b3b38b3463f43f0098080".parse().unwrap(),
                "0xf889a03e19976962fea3751225213669050369b7cd26650bc43815007705e945b5aa57b866f86403a0ffffffffffffffffffffffffffffffffffffffffffffffffffff546059ae3c82a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".parse().unwrap(),
            ],
            balance: "0xffffffffffffffffffffffffffffffffffffffffffffffffffff546059ae3c82".parse().unwrap(),
            code_hash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                .parse()
                .unwrap(),
            nonce: "0x3".parse().unwrap(),
            storage_hash: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                .parse()
                .unwrap(),
            storage_proof: vec![],
        }).unwrap();

        assert_eq!(
            hex::encode(trie.root().unwrap()),
            "60bfaa2e6e61adcd645ce3aefc05c3bda2ed31f95fdd8bd5422dc2b8c78ae909"
        );

        println!("before {}", trie);

        trie.account_trie
            .set_nonce(
                "0x3736b9d9d35d8c4f41d98a412fe9211024453575"
                    .parse()
                    .unwrap(),
                U256::from(4),
            )
            .unwrap();
        trie.account_trie
            .set_balance(
                "0x3736b9d9d35d8c4f41d98a412fe9211024453575"
                    .parse()
                    .unwrap(),
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffff45eff0fafd74"
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        trie.set_storage_value(
            "0x730E01e70B028b44a9387119d78E1392E4848Cbc"
                .parse()
                .unwrap(),
            "0x1".parse().unwrap(),
            "0x8".parse().unwrap(),
        )
        .unwrap();

        println!("after {}", trie);

        assert_eq!(
            hex::encode(trie.root().unwrap()),
            "bf04d56bcfb758b80412e16f9d84ce369ba87534b4226f0d2d41482a2127e811"
        );
    }
}
