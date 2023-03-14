use std::collections::HashMap;

use anvil::eth::EthApi;
use bus_mapping::{
    circuit_input_builder::{
        build_state_code_db, gen_state_access_trace, Access, AccessSet, AccessValue, Block,
        CircuitInputBuilder, CircuitsParams,
    },
    operation::RW,
    state_db::{CodeDB, StateDB},
};
use eth_types as zkevm_types;
use ethers::types as anvil_types;

use crate::{
    conversion::{zkevm_Block, Conversion, ConversionReverse},
    error::Error,
};

#[allow(dead_code)]
pub struct BuilderClient {
    anvil: EthApi,
    chain_id: eth_types::Word,
    circuits_params: CircuitsParams,
}

pub fn get_state_accesses(
    block: &zkevm_Block,
    geth_traces: &[eth_types::GethExecTrace],
) -> Result<AccessSet, Error> {
    let mut block_access_trace = vec![Access::new(
        None,
        RW::WRITE,
        AccessValue::Account {
            address: block
                .author
                .ok_or(Error::InternalError("Incomplete block"))?,
        },
    )];
    for (tx_index, tx) in block.transactions.iter().enumerate() {
        let geth_trace = &geth_traces[tx_index];
        let tx_access_trace = gen_state_access_trace(block, tx, geth_trace)?;
        block_access_trace.extend(tx_access_trace);
    }

    Ok(AccessSet::from(block_access_trace))
}

#[allow(dead_code)]
impl BuilderClient {
    pub fn new(anvil: EthApi, circuits_params: CircuitsParams) -> Result<Self, Error> {
        if let Some(chain_id) = anvil.eth_chain_id()? {
            Ok(Self {
                anvil,
                chain_id: zkevm_types::Word::from(chain_id.as_u64()),
                circuits_params,
            })
        } else {
            Err(Error::InternalError(
                "Unable to get chain id from ETH client",
            ))
        }
    }

    pub async fn gen_inputs(
        &self,
        block_number: zkevm_types::U64,
    ) -> Result<(CircuitInputBuilder, zkevm_Block), Error> {
        let (block, traces, history_hashes, prev_state_root) = self.get_block(block_number).await?;
        let access_set = get_state_accesses(&block, &traces)?;
        let (proofs, codes) = self.get_state(block_number, access_set).await?;
        let (state_db, code_db) = build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state(
            state_db,
            code_db,
            &block,
            &traces,
            history_hashes,
            prev_state_root,
        )?;
        Ok((builder, block))
    }

    pub fn gen_inputs_from_state(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        eth_block: &zkevm_Block,
        geth_traces: &[zkevm_types::GethExecTrace],
        history_hashes: Vec<zkevm_types::Word>,
        prev_state_root: zkevm_types::Word,
    ) -> Result<CircuitInputBuilder, Error> {
        let block = Block::new(
            self.chain_id,
            history_hashes,
            prev_state_root,
            eth_block,
            self.circuits_params,
        )?;
        let mut builder = CircuitInputBuilder::new(sdb, code_db, block);
        builder.handle_block(eth_block, geth_traces)?;
        Ok(builder)
    }

    pub async fn get_block(
        &self,
        block_number: zkevm_types::U64,
    ) -> Result<
        (
            zkevm_Block,
            Vec<zkevm_types::GethExecTrace>,
            Vec<zkevm_types::Word>,
            zkevm_types::Word,
        ),
        Error,
    > {
        let (block, traces) = self.get_block_traces(block_number).await?;

        // fetch up to 256 blocks
        let mut n_blocks = std::cmp::min(256, block_number.as_usize());
        let mut next_hash = block.parent_hash;
        let mut prev_state_root: Option<zkevm_types::Word> = None;
        let mut history_hashes = vec![zkevm_types::Word::default(); n_blocks];
        while n_blocks > 0 {
            n_blocks -= 1;

            // TODO: consider replacing it with `eth_getHeaderByHash`, it's faster
            let header = self
                .anvil
                .block_by_hash(next_hash.to_anvil_type())
                .await?
                .expect("parent block not found");

            // set the previous state root
            if prev_state_root.is_none() {
                prev_state_root = Some(header.state_root.to_zkevm_type());
            }

            // latest block hash is the last item
            let block_hash = header
                .hash
                .ok_or(Error::InternalError("Incomplete block"))?
                .to_zkevm_type();
            history_hashes[n_blocks] = block_hash;

            // continue
            next_hash = header.parent_hash.to_zkevm_type();
        }

        Ok((
            block,
            traces,
            history_hashes,
            prev_state_root.unwrap_or_default(),
        ))
    }

    pub async fn get_block_traces(
        &self,
        block_number: zkevm_types::U64,
    ) -> Result<(zkevm_Block, Vec<zkevm_types::GethExecTrace>), Error> {
        let block = self
            .anvil
            .block_by_number_full(anvil_types::BlockNumber::from(block_number.to_anvil_type()))
            .await?
            .expect("block not found");

        let mut traces = Vec::new();
        for tx in &block.transactions {
            let anvil_trace = self
                .anvil
                .debug_trace_transaction(
                    tx.hash,
                    anvil_types::GethDebugTracingOptions {
                        enable_memory: Some(false),
                        disable_stack: Some(false),
                        disable_storage: Some(false),
                        enable_return_data: Some(true),
                        tracer: None,
                        tracer_config: None,
                        timeout: None,
                    },
                )
                .await?;
            traces.push(anvil_trace.to_zkevm_type());
        }

        Ok((block.to_zkevm_type(), traces))
    }

    pub async fn get_state(
        &self,
        block_num: zkevm_types::U64,
        access_set: AccessSet,
    ) -> Result<
        (
            Vec<zkevm_types::EIP1186ProofResponse>,
            HashMap<zkevm_types::Address, Vec<u8>>,
        ),
        Error,
    > {
        let mut proofs = Vec::new();
        for (address, key_set) in access_set.state {
            let mut keys: Vec<zkevm_types::Word> = key_set.iter().cloned().collect();
            keys.sort();
            let proof = self
                .anvil
                .get_proof(
                    address.to_anvil_type(),
                    keys.iter().map(|k| k.to_anvil_type()).collect(),
                    Some((block_num.to_anvil_type() - 1).into()),
                )
                .await
                .unwrap();
            proofs.push(proof);
        }
        let mut codes: HashMap<zkevm_types::Address, Vec<u8>> = HashMap::new();
        for address in access_set.code {
            let code = self
                .anvil
                .get_code(
                    address.to_anvil_type(),
                    Some((block_num.to_anvil_type() - 1).into()),
                )
                .await
                .unwrap();
            codes.insert(address, code.to_vec());
        }
        Ok((proofs.iter().map(|p| p.to_zkevm_type()).collect(), codes))
    }
}

#[cfg(test)]
mod tests {
    use crate::client;
    use crate::conversion::Conversion;
    use crate::inputs_builder::BuilderClient;
    use anvil_core::eth::transaction::EthTransactionRequest;
    use bus_mapping::circuit_input_builder::CircuitsParams;

    #[tokio::test]
    async fn test() {
        let anvil = client::setup(None, None).await;
        let bc = BuilderClient::new(anvil, CircuitsParams::default()).unwrap();
        assert_eq!(bc.chain_id.as_u64(), 31337);

        let accounts = bc.anvil.accounts().unwrap();
        let hash = bc
            .anvil
            .send_transaction(EthTransactionRequest {
                from: Some(accounts[0]),
                to: None,
                gas_price: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                gas: None,
                value: None,
                data: None,
                nonce: None,
                chain_id: None,
                access_list: None,
                transaction_type: None,
            })
            .await
            .unwrap();

        loop {
            if let Some(tx) = bc.anvil.transaction_by_hash(hash).await.unwrap() {
                if let Some(block_number) = tx.block_number {
                    let (block, traces) = bc
                        .get_block_traces(block_number.to_zkevm_type())
                        .await
                        .unwrap();
                    assert_eq!(block.transactions.len(), 1);
                    assert_eq!(traces.len(), 1);
                    break;
                } else {
                    bc.anvil.mine_one().await;
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            } else {
                panic!("transaction not available");
            }
        }
    }
}
