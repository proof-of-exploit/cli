use ethers_core::utils::{hex, keccak256, rlp::Rlp};

use super::nibbles::Nibbles;
use crate::{
    error::Error,
    types::zkevm_types::{Bytes, H256},
};

use std::fmt;

const EMPTY_ROOT_STR: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
const EMPTY_VALUE_STR: &str = "0x00";

#[derive(Clone, PartialEq)]
pub struct Node {
    hash: H256,
    should_hash_keys: bool,
    data: Box<NodeData>,
}

impl Node {
    pub fn new(root: H256) -> Self {
        Node {
            hash: root,
            should_hash_keys: true,
            data: Box::new(NodeData::Unknown),
        }
    }

    // existing leaf in the trie
    pub fn load_proof(
        &mut self,
        key_: Nibbles,
        value_: Bytes,
        proof: Vec<Bytes>,
    ) -> Result<(), Error> {
        if proof.len() == 0 {
            if self.hash != EMPTY_ROOT_STR.parse().unwrap() {
                // enforce proof to be empt
                return Err(Error::InternalError(
                    "Root is not empty, hence some proof is needed",
                ));
            } else if value_ != EMPTY_VALUE_STR.parse::<Bytes>().unwrap() {
                // enforce the values to be empty, since it is empty root
                return Err(Error::InternalError(
                    "Value should be empty, since root is empty",
                ));
            } else {
                return Ok(());
            }
        }
        // check if the proof's first layer hashes to the root
        // use first element in proof to layout first layer
        let entry = proof[0].clone();

        let hash = H256::from(keccak256(entry.clone()));
        if hash != self.hash {
            return Err(Error::InternalError(
                "proof entry hash does not match the node root",
            ));
        }

        let val = NodeData::new(entry)?;
        if *self.data == NodeData::Unknown {
            // we found the place where node can be placed
            *self.data = val.clone();

            // if this is a leaf node, enforce key and value to be proper
            if let NodeData::Leaf { key, value } = val {
                if key != key_ {
                    return Err(Error::InternalError("key in leaf does not match input"));
                }
                if value != value_ {
                    return Err(Error::InternalError("value in leaf does not match input"));
                }
            }
        }

        if proof.len() > 1 {
            let mut child_proof = proof;
            child_proof.remove(0);
            return match *self.data.clone() {
                NodeData::Extension { key, mut node } => {
                    let key_extension_lenth = key.len();
                    let key_next = key_.slice(key_extension_lenth)?;
                    node.load_proof(key_next, value_, child_proof)
                }
                NodeData::Branch(arr) => {
                    for _child in arr {
                        // find the appropriate child node and call load_proof on it
                        let hash_next = H256::from(keccak256(child_proof[0].clone()));
                        if let Some(mut child) = _child && child.hash == hash_next {
                            // skip one nibble in the key
                            let key_next = key_.slice(1)?;
                            child.load_proof(key_next, value_.clone(), child_proof.clone())?;
                        }
                    }
                    Ok(())
                }
                _ => Err(Error::InternalError("this should not happen in load_proof")),
            };
        }

        Ok(())
    }

    pub fn get_key(&self, key: Bytes) -> Bytes {
        if self.should_hash_keys {
            Bytes::from(keccak256(key).to_vec())
        } else {
            key
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum NodeData {
    Unknown,
    Leaf { key: Nibbles, value: Bytes },
    Branch([Option<Node>; 17]),
    Extension { key: Nibbles, node: Node },
}

impl NodeData {
    pub fn new(raw: Bytes) -> Result<Self, Error> {
        let rlp = Rlp::new(&raw);
        let num_items = rlp.item_count()?;
        match num_items {
            2 => Ok({
                let val_0 = Bytes::from(rlp.at(0)?.data()?.to_owned());
                let val_1 = Bytes::from(rlp.at(1)?.data()?.to_owned());

                let (key, terminator) = Nibbles::from_encoded_path(val_0.clone())?;
                if terminator {
                    NodeData::Leaf { key, value: val_1 }
                } else {
                    let hash = rlp.at(1)?.data()?.to_owned();
                    if hash.len() != 32 {
                        return Err(Error::InternalError("invalid hash length in Extension"));
                    }
                    NodeData::Extension {
                        key,
                        node: Node::new(H256::from_slice(hash.as_slice())),
                    }
                }
            }),
            17 => Ok({
                let mut arr: [Option<Node>; 17] = Default::default();
                for i in 0..17 {
                    let value = rlp.at(i)?.data()?.to_owned();
                    arr[i] = match value.len() {
                        32 => Ok(Some(Node::new(H256::from_slice(value.as_slice())))),
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

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Node (hash: {}, data: {:?})",
            hex::encode(self.hash),
            self.data
        )
    }
}

impl fmt::Debug for NodeData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = match self {
            NodeData::Unknown => format!("Unknown"),
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

    use crate::state_root::nibbles::Nibbles;

    use super::{Node, NodeData};

    #[test]
    pub fn test_node_data_new_leaf_node_1() {
        let node_data = NodeData::new(
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
    pub fn test_node_data_new_branch_1() {
        let node_data = NodeData::new(
            "0xf851a0e97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e8080808080808080808080a09487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee5043280808080"
                .parse()
                .unwrap(),
        )
        .unwrap();

        println!("node_data {:#?}", node_data);

        assert_eq!(
            node_data,
            NodeData::Branch([
                Some(Node::new(
                    "0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e"
                        .parse()
                        .unwrap(),
                )),
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
                Some(Node::new(
                    "0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432"
                        .parse()
                        .unwrap(),
                )),
                None,
                None,
                None,
                None,
            ])
        );
    }

    #[test]
    pub fn test_node_new_empty_1() {
        let mut node = Node::new(
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                .parse()
                .unwrap(),
        );

        node.load_proof(
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
            hex::encode(node.hash),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        assert_eq!(node.data, Box::new(NodeData::Unknown));

        println!("node {:#?}", node);
        // assert!(false);
    }

    #[test]
    pub fn test_node_new_one_element_1() {
        let mut node = Node::new(
            "0x1c2e599f5f2a6cd75de40aada2a11971863dabd7a7378f1a3b268856a95829ba"
                .parse()
                .unwrap(),
        );

        node.load_proof(
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
            hex::encode(node.hash),
            "1c2e599f5f2a6cd75de40aada2a11971863dabd7a7378f1a3b268856a95829ba"
        );
        assert_eq!(
            node.data,
            Box::new(NodeData::Leaf {
                key: Nibbles::from_raw_path(
                    "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                        .parse()
                        .unwrap()
                ),
                value: "0x08".parse().unwrap(),
            })
        );

        println!("node {:#?}", node);
        // assert!(false);
    }

    #[test]
    pub fn test_node_new_two_element_1() {
        let mut node = Node::new(
            "0x45e335095c8915edb03eb2dc964ad3abff45427cc3da4925a96aba38b3fe196c"
                .parse()
                .unwrap(),
        );

        node.load_proof(
            Nibbles::from_raw_path(   "0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0" // hash(pad(0))
                .parse()
                .unwrap()),
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
            hex::encode(node.hash),
            "45e335095c8915edb03eb2dc964ad3abff45427cc3da4925a96aba38b3fe196c"
        );
        assert_eq!(
            node.data,
            Box::new(NodeData::Branch([
                Some(Node::new(
                    "0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e"
                        .parse()
                        .unwrap(),
                )),
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
                Some(Node::new(
                    "0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432"
                        .parse()
                        .unwrap(),
                )),
                None,
                None,
                None,
                None,
            ]))
        );

        println!("node {:#?}", node);
        // assert!(false);
    }

    #[test]
    pub fn test_node_new_three_element_extension_1() {
        let mut node = Node::new(
            "0x83c3e173e44cf782dfc14c550c322661c26728efda96977ed472c71bb94e8692"
                .parse()
                .unwrap(),
        );
        println!("prr");
        node.load_proof(
            Nibbles::from_raw_path("0xc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8" // hash(pad(0))
                .parse()
                .unwrap()),
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
            ]).unwrap();

        println!("node {:#?}", node);
        assert!(false);
    }
}
