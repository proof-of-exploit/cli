use std::collections::HashMap;

pub use bus_mapping::{
    circuit_input_builder::{
        build_state_code_db, gen_state_access_trace, Access, AccessSet, AccessValue, Block,
        CircuitInputBuilder, CircuitsParams,
    },
    operation::RW,
    state_db::{CodeDB, StateDB},
};
use ethers::utils::keccak256;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::witness::block_convert;

use futures::future;

use crate::{
    anvil::{
        conversion::{Conversion, ConversionReverse},
        AnvilClient,
    },
    error::Error,
};
use crate::{state_root::state_trie::StateTrie, types::zkevm_types::*};

#[allow(dead_code)]
pub struct BuilderClient {
    pub anvil: AnvilClient,
    pub chain_id: eth_types::Word,
    pub circuits_params: CircuitsParams,
}

pub fn get_state_accesses(
    block: &EthBlockFull,
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
    pub async fn default() -> Result<Self, Error> {
        Self::from_circuits_params(CircuitsParams::default()).await
    }

    pub async fn from_config(
        circuits_params: CircuitsParams,
        eth_rpc_url: Option<String>,
        fork_block_number: Option<usize>,
    ) -> Result<Self, Error> {
        let anvil = AnvilClient::setup(eth_rpc_url, fork_block_number).await;
        Self::new(anvil, circuits_params)
    }

    pub async fn from_circuits_params(circuits_params: CircuitsParams) -> Result<Self, Error> {
        let anvil = AnvilClient::default().await;
        Self::new(anvil, circuits_params)
    }

    pub fn new(anvil: AnvilClient, circuits_params: CircuitsParams) -> Result<Self, Error> {
        if let Some(chain_id) = anvil.eth_chain_id()? {
            Ok(Self {
                anvil,
                chain_id: Word::from(chain_id.as_usize()),
                circuits_params,
            })
        } else {
            Err(Error::InternalError(
                "Unable to get chain id from ETH client",
            ))
        }
    }

    pub async fn gen_witness(
        &self,
        block_number: usize,
    ) -> Result<zkevm_circuits::witness::Block<Fr>, Error> {
        let (circuit_input_builder, _) = self.gen_inputs(block_number).await?;
        Ok(block_convert::<Fr>(
            &circuit_input_builder.block,
            &circuit_input_builder.code_db,
        )?)
    }

    pub async fn gen_inputs(
        &self,
        block_number: usize,
    ) -> Result<(CircuitInputBuilder, EthBlockFull), Error> {
        let (mut block, traces, history_hashes, prev_state_root) =
            self.get_block(block_number).await?;
        let access_set = get_state_accesses(&block, &traces)?;
        let (proofs, codes, new_state_root) = self.get_state(block_number, access_set).await?;
        if block.state_root.is_zero() {
            block.state_root = new_state_root;
        }
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

    fn gen_inputs_from_state(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        eth_block: &EthBlockFull,
        geth_traces: &[GethExecTrace],
        history_hashes: Vec<Word>,
        prev_state_root: Word,
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

    async fn get_block(
        &self,
        block_number: usize,
    ) -> Result<(EthBlockFull, Vec<GethExecTrace>, Vec<Word>, Word), Error> {
        let (block, traces) = self.get_block_traces(block_number).await?;

        // fetch up to 256 blocks
        let n_blocks = std::cmp::min(256, block_number);
        let mut futures = Vec::default();
        for i in 1..n_blocks {
            let header_future = self.anvil.block_by_number(block_number - i);
            futures.push(header_future);
        }

        let mut prev_state_root: Option<Word> = None;
        let mut history_hashes = Vec::default();
        let results = future::join_all(futures).await;
        for result in results {
            let header = result?.expect("parent block not found");

            // set the previous state root
            if prev_state_root.is_none() {
                prev_state_root = Some(h256_to_u256(header.state_root));
            }

            // latest block hash is the last item
            let block_hash = header
                .hash
                .ok_or(Error::InternalError("Incomplete block"))?;
            history_hashes.push(h256_to_u256(block_hash));
        }

        Ok((
            block,
            traces,
            history_hashes,
            prev_state_root.unwrap_or_default(),
        ))
    }

    async fn get_block_traces(
        &self,
        block_number: usize,
    ) -> Result<(EthBlockFull, Vec<GethExecTrace>), Error> {
        let block = self
            .anvil
            .block_by_number_full(block_number)
            .await?
            .expect("block not found");

        let mut traces = Vec::default();
        for tx in &block.transactions {
            let anvil_trace = self
                .anvil
                .debug_trace_transaction(
                    tx.hash,
                    GethDebugTracingOptions {
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
            traces.push(anvil_trace);
        }

        Ok((block, traces))
    }

    async fn get_state(
        &self,
        block_number: usize,
        access_set: AccessSet,
    ) -> Result<(Vec<EIP1186ProofResponse>, HashMap<Address, Vec<u8>>, H256), Error> {
        let mut proofs = Vec::default();
        for (address, key_set) in access_set.state.clone() {
            let mut keys: Vec<Word> = key_set.iter().cloned().collect();
            keys.sort();
            let proof = self
                .anvil
                .get_proof(address, keys, Some(block_number - 1))
                .await
                .unwrap();
            proofs.push(proof);
        }
        let mut codes: HashMap<Address, Vec<u8>> = HashMap::default();
        for address in access_set.code.clone() {
            let code = self
                .anvil
                .get_code(address, Some(block_number - 1))
                .await
                .unwrap();
            codes.insert(address, code.to_vec());
        }

        let new_state_root = self
            .gen_state_root(block_number, access_set, &proofs)
            .await?;
        Ok((proofs, codes, new_state_root))
    }

    async fn gen_state_root(
        &self,
        block_number: usize,
        access_set: AccessSet,
        proofs: &Vec<EIP1186ProofResponse>,
    ) -> Result<H256, Error> {
        let mut trie = StateTrie::default();

        for proof in proofs {
            trie.load_proof(proof.to_anvil_type())?;
        }

        let mut addresses = Vec::<Address>::default();

        for (address, key_set) in access_set.state.clone() {
            for key in key_set {
                let new_value = self
                    .anvil
                    .get_storage_at(address, key, Some(block_number))
                    .await?;
                trie.set_storage_value(
                    address.to_anvil_type(),
                    key.to_anvil_type(),
                    h256_to_u256(new_value).to_anvil_type(),
                )?;
            }
            addresses.push(address);
        }
        for address in access_set.code.clone() {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        for address in addresses {
            let new_code = self
                .anvil
                .get_code(address, Some(block_number))
                .await
                .unwrap();
            let new_code_hash = H256::from(keccak256(new_code));
            let new_balance = self.anvil.get_balance(address, Some(block_number)).await?;
            let new_nonce = self.anvil.get_nonce(address, Some(block_number)).await?;

            let mut account_data = trie
                .account_trie
                .get_account_data(address.to_anvil_type())?;
            account_data.balance = new_balance.to_anvil_type();
            account_data.code_hash = new_code_hash.to_anvil_type();
            account_data.nonce = new_nonce.to_anvil_type();
            trie.account_trie
                .set_account_data(address.to_anvil_type(), account_data)?;
        }

        Ok(trie.root().unwrap().to_zkevm_type())
    }
}

#[cfg(test)]
mod tests {
    use crate::anvil::AnvilClient;
    use crate::inputs_builder::BuilderClient;
    use bus_mapping::circuit_input_builder::CircuitsParams;

    #[tokio::test]
    async fn test() {
        let anvil = AnvilClient::setup(None, None).await;
        let bc = BuilderClient::new(anvil, CircuitsParams::default()).unwrap();
        assert_eq!(bc.chain_id.as_usize(), 31337);

        let hash = bc
            .anvil
            .fund_wallet(
                "0x2CA4c197AE776f675A114FBCB0B03Be845f0316d"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();

        loop {
            if let Some(tx) = bc.anvil.transaction_by_hash(hash).await.unwrap() {
                if let Some(block_number) = tx.block_number {
                    let (block, traces) =
                        bc.get_block_traces(block_number.as_usize()).await.unwrap();
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
