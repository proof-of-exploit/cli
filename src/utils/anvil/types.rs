pub mod zkevm_types {
    use eth_types::BigEndianHash;
    pub use eth_types::{
        evm_types::{GasCost, Memory, OpcodeId, Stack, Storage},
        Address, Block, Bytes, EIP1186ProofResponse, GethExecStep, GethExecTrace, Hash,
        StorageProof, Transaction, Word, H160, H256, H64, U256, U64,
    };
    pub use ethers::types::GethDebugTracingOptions; // intentionally
    pub use ethers_core::types::{
        transaction::eip2930::{AccessList, AccessListItem},
        BlockNumber, Bloom, Log, OtherFields, TransactionReceipt, Withdrawal,
    };
    pub type EthBlockFull = Block<Transaction>;
    pub type EthBlockHeader = Block<Hash>;

    pub fn h256_to_u256(input: H256) -> U256 {
        U256::from_big_endian(input.as_bytes())
    }

    pub fn u256_to_h256(input: U256) -> H256 {
        H256::from_uint(&input)
    }
}

pub mod anvil_types {
    pub use anvil_core::eth::transaction::EthTransactionRequest;
    pub use ethers::types::{
        transaction::eip2930::AccessList, Address, Block, BlockId, BlockNumber, Bloom, Bytes,
        EIP1186ProofResponse, GethDebugTracingOptions, GethTrace, Log, OtherFields, StorageProof,
        Transaction, TransactionReceipt, TxHash, Withdrawal, H160, H256, H64, U256, U64,
    };
    pub type EthBlockFull = Block<Transaction>;
    pub type EthBlockHeader = Block<TxHash>;
}
