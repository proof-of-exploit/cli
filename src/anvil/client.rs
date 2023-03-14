use crate::{
    anvil::conversion::{convert_option, ConversionReverse},
    error::Error,
    types::{anvil_types, zkevm_types},
};
use anvil::{eth::EthApi, spawn, NodeConfig};
use ethers::utils::parse_ether;

use super::conversion::Conversion;
pub struct AnvilClient {
    eth_api: EthApi,
}

#[allow(dead_code)]
impl AnvilClient {
    pub async fn setup(eth_rpc_url: Option<String>, fork_block_number: Option<usize>) -> Self {
        let node_config = NodeConfig::default()
            .with_eth_rpc_url(eth_rpc_url)
            .with_fork_block_number(fork_block_number.map(|v| v as u64))
            .with_port(8548)
            .silent()
            .with_steps_tracing(true);

        let (eth_api, _) = spawn(node_config).await;
        Self { eth_api }
    }

    pub fn eth_chain_id(&self) -> Result<Option<zkevm_types::Word>, Error> {
        match self.eth_api.eth_chain_id()? {
            Some(chain_id) => Ok(Some(zkevm_types::Word::from(chain_id.as_usize()))),
            None => Ok(None),
        }
    }

    pub fn block_number(&self) -> Result<usize, Error> {
        Ok(self.eth_api.block_number()?.as_usize())
    }

    pub async fn block_by_number_full(
        &self,
        block_number: usize,
    ) -> Result<Option<zkevm_types::EthBlockFull>, Error> {
        match self
            .eth_api
            .block_by_number_full(anvil_types::BlockNumber::Number(anvil_types::U64::from(
                block_number,
            )))
            .await?
        {
            Some(block) => Ok(Some(block.to_zkevm_type())),
            None => Ok(None),
        }
    }

    pub async fn transaction_by_hash(
        &self,
        hash: zkevm_types::H256,
    ) -> Result<Option<zkevm_types::Transaction>, Error> {
        match self
            .eth_api
            .transaction_by_hash(hash.to_anvil_type())
            .await?
        {
            Some(tx) => Ok(Some(tx.to_zkevm_type())),
            None => Ok(None),
        }
    }

    pub async fn get_proof(
        &self,
        address: zkevm_types::Address,
        keys: Vec<zkevm_types::U256>,
        block_number: Option<usize>,
    ) -> Result<zkevm_types::EIP1186ProofResponse, Error> {
        Ok(self
            .eth_api
            .get_proof(
                address.to_anvil_type(),
                keys.iter().map(|key| key.to_anvil_type()).collect(),
                match block_number {
                    Some(_block_number) => Some(anvil_types::BlockId::Number(
                        anvil_types::BlockNumber::Number(anvil_types::U64::from(_block_number)),
                    )),
                    None => None,
                },
            )
            .await?
            .to_zkevm_type())
    }

    pub async fn block_by_hash(
        &self,
        hash: zkevm_types::Hash,
    ) -> Result<Option<zkevm_types::EthBlockHeader>, Error> {
        Ok(convert_option(
            self.eth_api.block_by_hash(hash.to_anvil_type()).await?,
        ))
    }

    pub async fn debug_trace_transaction(
        &self,
        hash: zkevm_types::Hash,
        options: anvil_types::GethDebugTracingOptions,
    ) -> Result<zkevm_types::GethExecTrace, Error> {
        Ok(self
            .eth_api
            .debug_trace_transaction(hash.to_anvil_type(), options)
            .await?
            .to_zkevm_type())
    }

    pub async fn get_code(
        &self,
        address: zkevm_types::Address,
        block_number: Option<usize>,
    ) -> Result<zkevm_types::Bytes, Error> {
        Ok(self
            .eth_api
            .get_code(
                address.to_anvil_type(),
                match block_number {
                    Some(_block_number) => Some(anvil_types::BlockId::Number(
                        anvil_types::BlockNumber::Number(anvil_types::U64::from(_block_number)),
                    )),
                    None => None,
                },
            )
            .await?
            .to_zkevm_type())
    }

    pub async fn send_raw_transaction(
        &self,
        raw_tx: zkevm_types::Bytes,
    ) -> Result<zkevm_types::Hash, Error> {
        Ok(self
            .eth_api
            .send_raw_transaction(raw_tx.to_anvil_type())
            .await?
            .to_zkevm_type())
    }

    pub async fn fund_wallet(
        &self,
        address: zkevm_types::Address,
    ) -> Result<zkevm_types::Hash, Error> {
        let accounts = self.eth_api.accounts().unwrap();
        Ok(self
            .eth_api
            .send_transaction(anvil_types::EthTransactionRequest {
                from: Some(accounts[0]),
                to: Some(address.to_anvil_type()),
                gas_price: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                gas: None,
                value: Some(parse_ether("1").unwrap()),
                data: None,
                nonce: None,
                chain_id: None,
                access_list: None,
                transaction_type: None,
            })
            .await?
            .to_zkevm_type())
    }

    pub async fn mine_one(&self) -> () {
        self.eth_api.mine_one().await;
    }
}

#[cfg(test)]
mod tests {
    use crate::anvil::AnvilClient;

    #[tokio::test]
    async fn test() {
        let cli = AnvilClient::setup(None, None).await;
        let bn = cli.block_number().unwrap();
        assert_eq!(bn, 0);
    }
}
