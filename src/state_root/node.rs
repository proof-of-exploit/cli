use ethers_core::utils::{hex, keccak256, rlp::Rlp};

use crate::{
    error::Error,
    types::zkevm_types::{Bytes, H256},
};

use super::key::Key;
use std::fmt;

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
    pub fn load_proof(&mut self, key: Bytes, value: Bytes, proof: Vec<Bytes>) -> Result<(), Error> {
        if proof.len() == 0 {
            // TODO: this might be zero if root hash is keccak256(rlp('0x'))
            return Err(Error::InternalError("Empty proof not allowed"));
        }
        // check if the proof's first layer hashes to the root
        // use first element in proof to layout first layer
        let entry = &proof[0].clone();

        let hash = H256::from(keccak256(entry));
        if hash != self.hash {
            return Err(Error::InternalError(
                "proof entry hash does not match the node root",
            ));
        }

        if proof.len() > 1 {
            let mut child_proof = proof;
            child_proof.remove(0);
            // TODO recursively call method of child node
        }

        todo!()
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
    Leaf { key: Bytes, value: Bytes },
    Branch([Option<Node>; 17]),
    Extension { key: Bytes, node: Node },
}

impl NodeData {
    pub fn new(raw: Bytes) -> Result<Self, Error> {
        let rlp = Rlp::new(&raw);
        let num_items = rlp.item_count()?;
        match num_items {
            2 => Ok({
                let val_0 = Bytes::from(rlp.at(0)?.data()?.to_owned());
                let val_1 = Bytes::from(rlp.at(1)?.data()?.to_owned());

                let (key, terminator) = Key::from_bytes_with_prefix(val_0.clone());
                if terminator {
                    NodeData::Leaf {
                        key: key.without_prefix(),
                        value: val_1,
                    }
                } else {
                    let hash = rlp.at(1)?.data()?.to_owned();
                    if hash.len() != 32 {
                        return Err(Error::InternalError("invalid hash length in Extension"));
                    }
                    NodeData::Extension {
                        key: key.without_prefix(),
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
                "Leaf(key={:?}, value={:?})",
                hex::encode(key.to_owned()),
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
                format!("Extension(key={:?}, node={:?})", key, node)
            }
        };
        write!(f, "NodeData::{}", val)
    }
}

#[cfg(test)]
mod tests {
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
                key: "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                    .parse()
                    .unwrap(),
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
}
