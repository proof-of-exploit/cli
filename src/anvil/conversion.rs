use std::{collections::HashMap, str::FromStr};

use ethers::{types::BigEndianHash, utils::hex};
use ethers_core::types as zkevm_types_2;

use crate::types::{anvil_types, zkevm_types};

// Conversion from anvil types to zkevm types
pub trait Conversion<T> {
    fn to_zkevm_type(&self) -> T;
}

pub fn convert_option<A: Conversion<Z>, Z>(some_val: Option<A>) -> Option<Z> {
    some_val.map(|val| val.to_zkevm_type())
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

impl Conversion<zkevm_types_2::transaction::eip2930::AccessList> for anvil_types::AccessList {
    fn to_zkevm_type(&self) -> zkevm_types_2::transaction::eip2930::AccessList {
        zkevm_types_2::transaction::eip2930::AccessList(
            self.0
                .iter()
                .map(|item| zkevm_types_2::transaction::eip2930::AccessListItem {
                    address: item.address.to_zkevm_type(),
                    storage_keys: item
                        .storage_keys
                        .iter()
                        .map(|key| key.to_zkevm_type())
                        .collect(),
                })
                .collect(),
        )
    }
}

impl Conversion<zkevm_types::Transaction> for anvil_types::Transaction {
    fn to_zkevm_type(&self) -> zkevm_types_2::Transaction {
        zkevm_types_2::Transaction {
            hash: self.hash.to_zkevm_type(),
            nonce: self.nonce.to_zkevm_type(),
            block_hash: convert_option(self.block_hash),
            block_number: convert_option(self.block_number),
            transaction_index: convert_option(self.transaction_index),
            from: self.from.to_zkevm_type(),
            to: convert_option(self.to),
            value: self.value.to_zkevm_type(),
            gas_price: convert_option(self.gas_price),
            gas: self.gas.to_zkevm_type(),
            input: self.input.to_zkevm_type(),
            v: self.v.to_zkevm_type(),
            r: self.r.to_zkevm_type(),
            s: self.s.to_zkevm_type(),
            transaction_type: convert_option(self.transaction_type),
            access_list: self
                .access_list
                .as_ref()
                .map(|access_list| access_list.to_zkevm_type()),
            max_priority_fee_per_gas: convert_option(self.max_priority_fee_per_gas),
            max_fee_per_gas: convert_option(self.max_fee_per_gas),
            chain_id: convert_option(self.chain_id),
            other: zkevm_types_2::OtherFields::default(),
        }
    }
}

impl<A: Conversion<Z>, Z> Conversion<zkevm_types::Block<Z>> for anvil_types::Block<A> {
    fn to_zkevm_type(&self) -> zkevm_types::Block<Z> {
        zkevm_types::Block {
            hash: convert_option(self.hash),
            parent_hash: self.parent_hash.to_zkevm_type(),
            uncles_hash: self.uncles_hash.to_zkevm_type(),
            author: convert_option(self.author),
            state_root: self.state_root.to_zkevm_type(),
            transactions_root: self.transactions_root.to_zkevm_type(),
            receipts_root: self.receipts_root.to_zkevm_type(),
            number: convert_option(self.number),
            gas_used: self.gas_used.to_zkevm_type(),
            gas_limit: self.gas_limit.to_zkevm_type(),
            extra_data: self.extra_data.to_zkevm_type(),
            logs_bloom: convert_option(self.logs_bloom),
            timestamp: self.timestamp.to_zkevm_type(),
            difficulty: self.difficulty.to_zkevm_type(),
            total_difficulty: convert_option(self.total_difficulty),
            seal_fields: self.seal_fields.iter().map(|b| b.to_zkevm_type()).collect(),
            uncles: self.uncles.iter().map(|b| b.to_zkevm_type()).collect(),
            transactions: self
                .transactions
                .iter()
                .map(|b| b.to_zkevm_type())
                .collect(),
            size: convert_option(self.size),
            mix_hash: convert_option(self.mix_hash),
            nonce: convert_option(self.nonce),
            base_fee_per_gas: convert_option(self.base_fee_per_gas),
            other: zkevm_types_2::OtherFields::default(),
        }
    }
}

impl Conversion<zkevm_types::TransactionReceipt> for anvil_types::TransactionReceipt {
    fn to_zkevm_type(&self) -> zkevm_types::TransactionReceipt {
        zkevm_types_2::TransactionReceipt {
            transaction_hash: self.transaction_hash.to_zkevm_type(),
            transaction_index: self.transaction_index.to_zkevm_type(),
            block_hash: convert_option(self.block_hash),
            block_number: convert_option(self.block_number),
            from: self.from.to_zkevm_type(),
            to: convert_option(self.to),
            cumulative_gas_used: self.cumulative_gas_used.to_zkevm_type(),
            gas_used: convert_option(self.gas_used),
            contract_address: convert_option(self.contract_address),
            logs: self.logs.iter().map(|b| b.to_zkevm_type()).collect(),
            status: convert_option(self.status),
            root: convert_option(self.root),
            logs_bloom: self.logs_bloom.to_zkevm_type(),
            transaction_type: convert_option(self.transaction_type),
            effective_gas_price: convert_option(self.effective_gas_price),
        }
    }
}

impl Conversion<zkevm_types::Log> for anvil_types::Log {
    fn to_zkevm_type(&self) -> zkevm_types::Log {
        zkevm_types::Log {
            address: self.address.to_zkevm_type(),
            topics: self.topics.iter().map(|b| b.to_zkevm_type()).collect(),
            data: self.data.to_zkevm_type(),
            block_hash: convert_option(self.block_hash),
            block_number: convert_option(self.block_number),
            transaction_hash: convert_option(self.transaction_hash),
            transaction_index: convert_option(self.transaction_index),
            log_index: convert_option(self.log_index),
            transaction_log_index: convert_option(self.transaction_log_index),
            log_type: self.log_type.clone(),
            removed: self.removed,
        }
    }
}

impl Conversion<zkevm_types::GethExecTrace> for anvil_types::GethTrace {
    fn to_zkevm_type(&self) -> zkevm_types::GethExecTrace {
        if let ethers::types::GethTrace::Known(ethers::types::GethTraceFrame::Default(
            anvil_trace,
        )) = self.to_owned()
        {
            zkevm_types::GethExecTrace {
                gas: zkevm_types::Gas(anvil_trace.gas.as_u64()),
                failed: anvil_trace.failed,
                return_value: hex::encode(anvil_trace.return_value.as_ref()), // TODO see if 0x adjustment is needed
                struct_logs: anvil_trace
                    .struct_logs
                    .into_iter()
                    .map(|step| {
                        zkevm_types::GethExecStep {
                            pc: zkevm_types::ProgramCounter(
                                usize::try_from(step.pc).expect("error converting pc"),
                            ),
                            op: zkevm_types::OpcodeId::from_str(step.op.as_str()).unwrap(),
                            gas: zkevm_types::Gas(step.gas),
                            gas_cost: zkevm_types::GasCost(step.gas_cost),
                            refund: zkevm_types::Gas(step.refund_counter.unwrap_or(0)),
                            depth: u16::try_from(step.depth).expect("error converting depth"),
                            error: step.error,
                            stack: zkevm_types::Stack(
                                step.stack
                                    .unwrap_or(Vec::new())
                                    .into_iter()
                                    .map(|w| w.to_zkevm_type())
                                    .collect(),
                            ),
                            memory: zkevm_types::Memory::default(), // memory is not enabled
                            storage: {
                                let tree = step.storage.unwrap_or_default();
                                let mut hash_map =
                                    HashMap::<zkevm_types::Word, zkevm_types::Word>::new();
                                for (key, value) in &tree {
                                    hash_map.insert(key.to_zkevm_type(), value.to_zkevm_type());
                                }
                                zkevm_types::Storage(hash_map)
                            },
                        }
                    })
                    .collect(),
            }
        } else {
            panic!("unknown value in trace")
        }
    }
}

impl Conversion<zkevm_types::EIP1186ProofResponse> for anvil_types::EIP1186ProofResponse {
    fn to_zkevm_type(&self) -> zkevm_types::EIP1186ProofResponse {
        zkevm_types::EIP1186ProofResponse {
            address: self.address.to_zkevm_type(),
            balance: self.balance.to_zkevm_type(),
            code_hash: self.code_hash.to_zkevm_type(),
            nonce: zkevm_types::U256::from(self.nonce.as_u64()),
            storage_hash: self.storage_hash.to_zkevm_type(),
            account_proof: self
                .account_proof
                .iter()
                .map(|ap| ap.to_zkevm_type())
                .collect(),
            storage_proof: self
                .storage_proof
                .iter()
                .map(|sp| zkevm_types::StorageProof {
                    key: sp.key.to_zkevm_type(),
                    value: sp.value.to_zkevm_type(),
                    proof: sp.proof.iter().map(|p| p.to_zkevm_type()).collect(),
                })
                .collect(),
        }
    }
}

impl ConversionReverse<anvil_types::EIP1186ProofResponse> for zkevm_types::EIP1186ProofResponse {
    fn to_anvil_type(&self) -> anvil_types::EIP1186ProofResponse {
        anvil_types::EIP1186ProofResponse {
            address: self.address.to_anvil_type(),
            balance: self.balance.to_anvil_type(),
            code_hash: self.code_hash.to_anvil_type(),
            nonce: anvil_types::U64::from(self.nonce.as_u64()),
            storage_hash: self.storage_hash.to_anvil_type(),
            account_proof: self
                .account_proof
                .iter()
                .map(|ap| ap.to_anvil_type())
                .collect(),
            storage_proof: self
                .storage_proof
                .iter()
                .map(|sp| anvil_types::StorageProof {
                    key: sp.key.to_anvil_type(),
                    value: sp.value.to_anvil_type(),
                    proof: sp.proof.iter().map(|p| p.to_anvil_type()).collect(),
                })
                .collect(),
        }
    }
}

// Conversion from zkevm types to anvil types
pub trait ConversionReverse<T> {
    fn to_anvil_type(&self) -> T;
}

pub fn convert_option_reverse<A: ConversionReverse<Z>, Z>(some_val: Option<A>) -> Option<Z> {
    some_val.map(|val| val.to_anvil_type())
}

impl ConversionReverse<anvil_types::H160> for zkevm_types::H160 {
    fn to_anvil_type(&self) -> anvil_types::H160 {
        let mut new = anvil_types::H160::zero();
        new.0 = self.0;
        new
    }
}

impl ConversionReverse<anvil_types::H256> for zkevm_types::H256 {
    fn to_anvil_type(&self) -> anvil_types::H256 {
        let mut new = anvil_types::H256::zero();
        new.0 = self.0;
        new
    }
}

impl ConversionReverse<anvil_types::U64> for zkevm_types::U64 {
    fn to_anvil_type(&self) -> anvil_types::U64 {
        let mut new = anvil_types::U64::zero();
        new.0 = self.0;
        new
    }
}

impl ConversionReverse<anvil_types::U256> for zkevm_types::U256 {
    fn to_anvil_type(&self) -> anvil_types::U256 {
        let mut new = anvil_types::U256::zero();
        new.0 = self.0;
        new
    }
}

impl ConversionReverse<anvil_types::H256> for zkevm_types::U256 {
    fn to_anvil_type(&self) -> anvil_types::H256 {
        anvil_types::H256::from_uint(&self.to_anvil_type())
    }
}

impl ConversionReverse<anvil_types::Bytes> for zkevm_types::Bytes {
    fn to_anvil_type(&self) -> anvil_types::Bytes {
        anvil_types::Bytes::from(self.to_vec())
    }
}
