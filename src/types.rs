pub mod zkevm_types {
    pub use eth_types::{
        evm_types::{Gas, GasCost, Memory, OpcodeId, ProgramCounter, Stack, Storage},
        Address, Block, Bytes, EIP1186ProofResponse, GethExecStep, GethExecTrace, Hash,
        StorageProof, Transaction, Word, H160, H256, H64, U256, U64,
    };
    pub use ethers::types::GethDebugTracingOptions;
    pub use ethers_core::types::{
        transaction::eip2930::AccessList, Bloom, Log, TransactionReceipt,
    };
    pub type EthBlockFull = Block<Transaction>;
    pub type EthBlockHeader = Block<Hash>;

    pub fn h256_to_u256(input: H256) -> U256 {
        U256::from_big_endian(input.as_bytes())
    }
}

pub mod anvil_types {
    pub use anvil_core::eth::transaction::EthTransactionRequest;
    pub use ethers::types::{
        transaction::eip2930::AccessList, Address, Block, BlockId, BlockNumber, Bloom, Bytes,
        EIP1186ProofResponse, GethDebugTracingOptions, GethTrace, Log, Transaction,
        TransactionReceipt, TxHash, H160, H256, H64, U256, U64,
    };
    pub type EthBlockFull = Block<Transaction>;
    pub type EthBlockHeader = Block<TxHash>;
}
