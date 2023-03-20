use std::{collections::HashMap, fmt};

use super::nibbles::Nibbles;
use crate::error::Error;

use ethers::{
    prelude::EthDisplay,
    types::{Bytes, H256},
    utils::{hex, keccak256, rlp::Rlp},
};

const EMPTY_ROOT_STR: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
const EMPTY_VALUE_STR: &str = "0x00";

#[derive(Clone, Debug, EthDisplay, PartialEq)]
pub struct Trie {
    root: Option<H256>,
    nodes: HashMap<H256, NodeData>,
}

impl Trie {
    pub fn new() -> Self {
        Trie {
            root: None,
            nodes: HashMap::new(),
        }
    }

    pub fn from_root(root: H256) -> Self {
        Trie {
            root: Some(root),
            nodes: HashMap::new(),
        }
    }

    pub fn set_root(&mut self, root: H256) -> Result<(), Error> {
        if self.root.is_some() {
            return Err(Error::InternalError("root already present"));
        }
        self.root = Some(root);
        Ok(())
    }

    pub fn load_proof(
        &mut self,
        key_: Nibbles,
        value_: Bytes,
        proof: Vec<Bytes>,
    ) -> Result<(), Error> {
        if proof.len() == 0 {
            if self.root.is_some() {
                if self.root.unwrap() != EMPTY_ROOT_STR.parse().unwrap() {
                    // enforce proof to be empt
                    return Err(Error::InternalError(
                        "Root is not empty, hence some proof is needed",
                    ));
                } else if value_ != EMPTY_VALUE_STR.parse::<Bytes>().unwrap() {
                    // enforce the values to be empty, since it is empty root
                    return Err(Error::InternalError(
                        "Value should be empty, since root is empty",
                    ));
                }
            }
            return Ok(());
        }

        // proof.len() > 0
        if self.root.is_none() {
            let proof_root = proof[0].clone();
            self.root = Some(H256::from(keccak256(proof_root)));
        }

        let mut root = self.root.unwrap();
        let mut key_current = key_.clone();

        for (i, proof_entry) in proof.iter().enumerate() {
            let hash_node_data = H256::from(keccak256(proof_entry.clone()));

            // check if node data is preimage of root
            if hash_node_data != root {
                return Err(Error::InternalError(
                    "proof entry hash does not match the node root",
                ));
            }

            // decode the node
            let node_data = NodeData::from_raw_rlp(proof_entry.to_owned())?;

            // if this is a leaf node (the last one), enforce key and value to be proper
            if let NodeData::Leaf { key, value } = node_data.clone() {
                if key != key_current {
                    return Err(Error::InternalError("key in leaf does not match input"));
                }
                if value != value_ {
                    return Err(Error::InternalError("value in leaf does not match input"));
                }
            }

            let some_node_data_stored = self.nodes.get(&hash_node_data);
            if some_node_data_stored.is_none() {
                self.nodes.insert(hash_node_data, node_data.clone());
            }

            println!("node_data {:?}", node_data);

            match node_data {
                NodeData::Extension { key, node } => {
                    root = node;
                    // skip nibbles already included in extension key in the current key
                    key_current = key_current.slice(key.len())?;
                }
                NodeData::Branch(arr) => {
                    for _child in arr {
                        // find the appropriate child node in branch
                        let hash_next = H256::from(keccak256(proof[i + 1].clone()));
                        if let Some(child) = _child && child == hash_next {
                            root = child;
                            // skip one nibble in the current key for branch nodes
                            key_current = key_current.slice(1)?;
                            break;
                        }
                    }
                }
                _ => return Ok(()),
            };
        }

        Ok(())
    }

    // useful for reducing verticle length of testing code
    pub fn nodes_get(&self, hash: &str) -> Option<&NodeData> {
        self.nodes.get(&hash.parse().unwrap())
    }
}

#[derive(Clone, PartialEq)]
pub enum NodeData {
    // Unknown,
    Leaf { key: Nibbles, value: Bytes },
    Branch([Option<H256>; 17]),
    Extension { key: Nibbles, node: H256 },
}

impl NodeData {
    pub fn from_raw_rlp(raw: Bytes) -> Result<Self, Error> {
        let rlp = Rlp::new(&raw);
        let num_items = rlp.item_count()?;
        match num_items {
            2 => Ok({
                let val_0 = Bytes::from(rlp.at(0)?.data()?.to_owned());
                let val_1 = Bytes::from(rlp.at(1)?.data()?.to_owned());

                let (key, terminator) = Nibbles::from_encoded_path_with_terminator(val_0.clone())?;
                if terminator {
                    NodeData::Leaf { key, value: val_1 }
                } else {
                    let hash = rlp.at(1)?.data()?.to_owned();
                    if hash.len() != 32 {
                        return Err(Error::InternalError("invalid hash length in Extension"));
                    }
                    NodeData::Extension {
                        key,
                        node: H256::from_slice(hash.as_slice()),
                    }
                }
            }),
            17 => Ok({
                let mut arr: [Option<H256>; 17] = Default::default();
                for i in 0..17 {
                    let value = rlp.at(i)?.data()?.to_owned();
                    arr[i] = match value.len() {
                        32 => Ok(Some(H256::from_slice(value.as_slice()))),
                        0 => Ok(None),
                        _ => Err(Error::InternalError("invalid hash length in Extension")),
                    }?
                }
                NodeData::Branch(arr)
            }),
            _ => Err(Error::InternalError("Unknown num_items")),
        }
    }
}

impl fmt::Debug for NodeData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = match self {
            // NodeData::Unknown => format!("Unknown"),
            NodeData::Leaf { key, value } => format!(
                "Leaf(key={}, value={:?})",
                key,
                hex::encode(value.to_owned())
            ),
            NodeData::Branch(branch) => format!(
                "Branch({:?}",
                branch
                    .iter()
                    .map(|node| {
                        if let Some(node) = node {
                            format!("{:?}", node)
                        } else {
                            format!("None")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            NodeData::Extension { key, node } => {
                format!("Extension(key={}, node={:?})", key, node)
            }
        };
        write!(f, "NodeData::{}", val)
    }
}

#[cfg(test)]
mod tests {
    use ethers::utils::hex;

    use super::{Nibbles, NodeData, Trie};

    #[test]
    pub fn test_node_data_new_leaf_node_1() {
        let node_data = NodeData::from_raw_rlp(
            "0xe3a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56308"
                .parse()
                .unwrap(),
        )
        .unwrap();

        println!("node_data {:#?}", node_data);

        assert_eq!(
            node_data,
            NodeData::Leaf {
                key: Nibbles::from_raw_path(
                    "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                        .parse()
                        .unwrap()
                ),
                value: "0x08".parse().unwrap(),
            }
        );
    }

    #[test]
    pub fn test_node_data_new_extension_node_1() {
        let node_data = NodeData::from_raw_rlp(
            "0xe583165a7ba0e46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                .parse()
                .unwrap(),
        )
        .unwrap();

        println!("node_data {:#?}", node_data);

        assert_eq!(
            node_data,
            NodeData::Extension {
                key: Nibbles::from_encoded_path("0x165a7b".parse().unwrap()).unwrap(),
                node: "0xe46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                    .parse()
                    .unwrap(),
            }
        );
    }

    #[test]
    pub fn test_node_data_new_branch_1() {
        let node_data = NodeData::from_raw_rlp(
            "0xf851a0e97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e8080808080808080808080a09487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee5043280808080"
                .parse()
                .unwrap(),
        )
        .unwrap();

        println!("node_data {:#?}", node_data);

        assert_eq!(
            node_data,
            NodeData::Branch([
                Some(
                    "0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e"
                        .parse()
                        .unwrap()
                ),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432"
                        .parse()
                        .unwrap()
                ),
                None,
                None,
                None,
                None,
            ])
        );
    }

    #[test]
    pub fn test_trie_new_empty_1() {
        let mut trie = Trie::from_root(
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                .parse()
                .unwrap(),
        );

        trie.load_proof(
            Nibbles::from_raw_path(
                "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563" // hash(pad(0))
                    .parse()
                    .unwrap(),
            ),
            "0x00".parse().unwrap(),
            vec![],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        assert!(trie.nodes.get(&trie.root.unwrap()).is_none());

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_new_one_element_1() {
        let mut trie = Trie::new();

        trie.load_proof(
            Nibbles::from_raw_path(
                "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563" // hash(pad(0))
                    .parse()
                    .unwrap(),
            ),
            "0x08".parse().unwrap(),
            vec![
                "0xe3a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56308"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "1c2e599f5f2a6cd75de40aada2a11971863dabd7a7378f1a3b268856a95829ba"
        );
        assert_eq!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_raw_path_str(
                    "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                ),
                value: "0x08".parse().unwrap(),
            }
        );

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_new_two_element_1() {
        let mut trie = Trie::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(   "0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0" // hash(pad(5))
               ),
            "0x09".parse().unwrap(),
            vec![
                "0xf851a0e97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e8080808080808080808080a09487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee5043280808080"
                    .parse()
                    .unwrap(),
                "0xe2a0336b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db009"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "45e335095c8915edb03eb2dc964ad3abff45427cc3da4925a96aba38b3fe196c"
        );
        assert_eq!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().to_owned(),
            NodeData::Branch([
                Some(
                    "0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
            ])
        );
        assert_eq!(
            trie.nodes_get("0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e")
                .unwrap()
                .to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_encoded_path_str(
                    "0x336b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
                )
                .unwrap(),
                value: "0x09".parse().unwrap(),
            }
        );
        assert!(trie
            .nodes_get("0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432")
            .is_none());

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_new_three_element_1() {
        let mut trie = Trie::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0xc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8" // hash(pad(5))
              ),
            "0x14".parse().unwrap(),
            vec![
                "0xf851a0c2af0751112c3efa2873802b452283ab1e2c60fde148a2f9e482ed03b8947e158080808080808080808080a0b3e6ad355d7116d0b4173e75e4c760082c8870e3b5b746cfadfea7101e834cc280808080"
                    .parse()
                    .unwrap(),
                "0xe583165a7ba0e46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                    .parse()
                    .unwrap(),
                "0xf85180808080808080a00c104f2019963f0df89d54742b14cd0ad7418cb208e9bc69bf80cb296926ffe9808080a04efd8a29c04796b9c9b13af2740864e48851a89ef4292575ab5f69b3a52c06c08080808080"
                    .parse()
                    .unwrap(),
                "0xdf9d38d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a814"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "83c3e173e44cf782dfc14c550c322661c26728efda96977ed472c71bb94e8692"
        );
        assert_eq!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().to_owned(),
            NodeData::Branch([
                Some(
                    "0xc2af0751112c3efa2873802b452283ab1e2c60fde148a2f9e482ed03b8947e15"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0xb3e6ad355d7116d0b4173e75e4c760082c8870e3b5b746cfadfea7101e834cc2"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
            ])
        );
        assert!(trie
            .nodes_get("0xc2af0751112c3efa2873802b452283ab1e2c60fde148a2f9e482ed03b8947e15")
            .is_none());
        assert_eq!(
            trie.nodes_get("0xb3e6ad355d7116d0b4173e75e4c760082c8870e3b5b746cfadfea7101e834cc2")
                .unwrap()
                .to_owned(),
            NodeData::Extension {
                key: Nibbles::from_encoded_path_str("0x165a7b").unwrap(),
                node: "0xe46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                    .parse()
                    .unwrap(),
            }
        );
        assert_eq!(
            trie.nodes_get("0xe46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944")
                .unwrap()
                .to_owned(),
            NodeData::Branch([
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0x0c104f2019963f0df89d54742b14cd0ad7418cb208e9bc69bf80cb296926ffe9"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                Some(
                    "0x4efd8a29c04796b9c9b13af2740864e48851a89ef4292575ab5f69b3a52c06c0"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
                None
            ])
        );
        assert!(trie
            .nodes_get("0x0c104f2019963f0df89d54742b14cd0ad7418cb208e9bc69bf80cb296926ffe9")
            .is_none());
        assert_eq!(
            trie.nodes_get("0x4efd8a29c04796b9c9b13af2740864e48851a89ef4292575ab5f69b3a52c06c0")
                .unwrap()
                .to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_encoded_path_str(
                    "0x38d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8"
                )
                .unwrap(),
                value: "0x14".parse().unwrap(),
            }
        );

        println!("trie {:#?}", trie);
        // assert!(false);
    }
}
