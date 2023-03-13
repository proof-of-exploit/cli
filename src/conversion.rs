use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use eth_types as zkevm_types;
use ethers::{
    types::{self as anvil_types},
    utils::hex,
};
use ethers_core::types as zkevm_types_2;

pub trait Conversion<T> {
    fn to_zkevm_type(&self) -> T;
}

impl Conversion<zkevm_types::U256> for anvil_types::U256 {
    fn to_zkevm_type(&self) -> zkevm_types::U256 {
        let mut new = zkevm_types::U256::zero();
        new.0 = self.0;
        new
    }
}

impl Conversion<zkevm_types::U64> for anvil_types::U64 {
    fn to_zkevm_type(&self) -> zkevm_types::U64 {
        let mut new = zkevm_types::U64::zero();
        new.0 = self.0;
        new
    }
}

impl Conversion<zkevm_types::U256> for anvil_types::H256 {
    fn to_zkevm_type(&self) -> zkevm_types::U256 {
        zkevm_types::U256::from_big_endian(self.as_bytes())
    }
}

impl Conversion<zkevm_types::H64> for anvil_types::H64 {
    fn to_zkevm_type(&self) -> zkevm_types::H64 {
        let mut new = zkevm_types::H64::zero();
        new.0 = self.0;
        new
    }
}

impl Conversion<zkevm_types::H256> for anvil_types::H256 {
    fn to_zkevm_type(&self) -> zkevm_types::H256 {
        let mut new = zkevm_types::H256::zero();
        new.0 = self.0;
        new
    }
}

impl Conversion<zkevm_types::H160> for anvil_types::H160 {
    fn to_zkevm_type(&self) -> zkevm_types::H160 {
        let mut new = zkevm_types::H160::zero();
        new.0 = self.0;
        new
    }
}

impl Conversion<zkevm_types::Bytes> for anvil_types::Bytes {
    fn to_zkevm_type(&self) -> zkevm_types::Bytes {
        zkevm_types::Bytes::from(self.to_vec())
    }
}

impl Conversion<zkevm_types_2::Bloom> for anvil_types::Bloom {
    fn to_zkevm_type(&self) -> zkevm_types_2::Bloom {
        zkevm_types_2::Bloom::from_slice(&self.0)
    }
}

impl Conversion<zkevm_types::Transaction> for anvil_types::Transaction {
    fn to_zkevm_type(&self) -> zkevm_types_2::Transaction {
        todo!()
    }
}

#[allow(non_camel_case_types)]
pub type anvil_Block = anvil_types::Block<anvil_types::Transaction>;

#[allow(non_camel_case_types)]
pub type zkevm_Block = zkevm_types::Block<zkevm_types::Transaction>;

impl Conversion<zkevm_Block> for anvil_Block {
    fn to_zkevm_type(&self) -> zkevm_Block {
        zkevm_types::Block {
            hash: match self.hash {
                Some(hash) => Some(hash.to_zkevm_type()),
                None => None,
            },
            parent_hash: self.parent_hash.to_zkevm_type(),
            uncles_hash: self.uncles_hash.to_zkevm_type(),
            author: match self.author {
                Some(author) => Some(author.to_zkevm_type()),
                None => None,
            },
            state_root: self.state_root.to_zkevm_type(),
            transactions_root: self.transactions_root.to_zkevm_type(),
            receipts_root: self.receipts_root.to_zkevm_type(),
            number: match self.number {
                Some(number) => Some(number.to_zkevm_type()),
                None => None,
            },
            gas_used: self.gas_used.to_zkevm_type(),
            gas_limit: self.gas_limit.to_zkevm_type(),
            extra_data: self.extra_data.to_zkevm_type(),
            logs_bloom: match self.logs_bloom {
                Some(logs_bloom) => Some(logs_bloom.to_zkevm_type()),
                None => None,
            },
            timestamp: self.timestamp.to_zkevm_type(),
            difficulty: self.difficulty.to_zkevm_type(),
            total_difficulty: match self.total_difficulty {
                Some(total_difficulty) => Some(total_difficulty.to_zkevm_type()),
                None => None,
            },
            seal_fields: self.seal_fields.iter().map(|b| b.to_zkevm_type()).collect(),
            uncles: self.uncles.iter().map(|b| b.to_zkevm_type()).collect(),
            transactions: self
                .transactions
                .iter()
                .map(|b| b.to_zkevm_type())
                .collect(),
            size: match self.size {
                Some(size) => Some(size.to_zkevm_type()),
                None => None,
            },
            mix_hash: match self.mix_hash {
                Some(mix_hash) => Some(mix_hash.to_zkevm_type()),
                None => None,
            },
            nonce: match self.nonce {
                Some(nonce) => Some(nonce.to_zkevm_type()),
                None => None,
            },
            base_fee_per_gas: match self.base_fee_per_gas {
                Some(base_fee_per_gas) => Some(base_fee_per_gas.to_zkevm_type()),
                None => None,
            },
            other: zkevm_types_2::OtherFields::default(),
        }
    }
}

impl Conversion<zkevm_types::GethExecTrace> for anvil_types::GethTrace {
    fn to_zkevm_type(&self) -> zkevm_types::GethExecTrace {
        if let ethers::types::GethTrace::Known(anvil_trace_frame) = self.to_owned() {
            if let ethers::types::GethTraceFrame::Default(anvil_trace) = anvil_trace_frame {
                zkevm_types::GethExecTrace {
                    gas: zkevm_types::evm_types::Gas(anvil_trace.gas.as_u64()),
                    failed: anvil_trace.failed,
                    return_value: hex::encode(anvil_trace.return_value.as_ref()), // TODO see if 0x adjustment is needed
                    struct_logs: anvil_trace
                        .struct_logs
                        .into_iter()
                        .map(|step| {
                            zkevm_types::GethExecStep {
                                pc: zkevm_types::evm_types::ProgramCounter(
                                    usize::try_from(step.pc).expect("error converting pc"),
                                ),
                                op: zkevm_types::evm_types::OpcodeId::from_str(&step.op.as_str())
                                    .unwrap(),
                                gas: zkevm_types::evm_types::Gas(step.gas),
                                gas_cost: zkevm_types::evm_types::GasCost(step.gas_cost),
                                refund: zkevm_types::evm_types::Gas(
                                    step.refund_counter.unwrap_or(0),
                                ),
                                depth: u16::try_from(step.depth).expect("error converting depth"),
                                error: step.error,
                                stack: zkevm_types::evm_types::Stack(
                                    step.stack
                                        .unwrap_or(Vec::new())
                                        .into_iter()
                                        .map(|w| w.to_zkevm_type())
                                        .collect(),
                                ),
                                memory: zkevm_types::evm_types::Memory::default(), // memory is not enabled
                                storage: {
                                    let tree = step.storage.unwrap_or_default();
                                    let mut hash_map =
                                        HashMap::<zkevm_types::Word, zkevm_types::Word>::new();
                                    for (key, value) in &tree {
                                        hash_map.insert(key.to_zkevm_type(), value.to_zkevm_type());
                                    }
                                    zkevm_types::evm_types::Storage(hash_map)
                                },
                            }
                        })
                        .collect(),
                }
            } else {
                panic!("unknown value in trace")
            }
        } else {
            panic!("unknown value in trace")
        }
    }
}
