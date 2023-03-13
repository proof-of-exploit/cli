use anvil::eth::EthApi;
use bus_mapping::circuit_input_builder::CircuitsParams;
use eth_types as zkevm_types;
use ethers::types as anvil_types;

use crate::{conversion::Conversion, error::Error};

#[allow(dead_code)]
pub struct BuilderClient {
    anvil: EthApi,
    chain_id: eth_types::Word,
    circuit_params: CircuitsParams,
}

#[allow(dead_code)]
impl BuilderClient {
    pub fn new(anvil: EthApi, circuit_params: CircuitsParams) -> Result<Self, Error> {
        if let Some(chain_id) = anvil.eth_chain_id()? {
            Ok(Self {
                anvil,
                chain_id: zkevm_types::Word::from(chain_id.as_u64()),
                circuit_params,
            })
        } else {
            Err(Error::InternalError(
                "Unable to get chain id from ETH client",
            ))
        }
    }

    pub async fn get_block_traces(
        &self,
        block_number: anvil_types::U64,
    ) -> Result<
        (
            anvil_types::Block<anvil_types::Transaction>,
            Vec<zkevm_types::GethExecTrace>,
        ),
        Error,
    > {
        let block = self
            .anvil
            .block_by_number_full(anvil_types::BlockNumber::from(block_number))
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

        Ok((block, traces))
    }
}

#[cfg(test)]
mod tests {
    use crate::client;
    use crate::inputs_builder::BuilderClient;
    use anvil_core::eth::transaction::EthTransactionRequest;
    use bus_mapping::circuit_input_builder::CircuitsParams;

    #[tokio::test]
    async fn test() {
        let anvil = client::setup().await;
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
                    let (block, traces) = bc.get_block_traces(block_number).await.unwrap();
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
