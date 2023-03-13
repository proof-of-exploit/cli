use anvil::eth::EthApi;
use bus_mapping::circuit_input_builder::CircuitsParams;
use eth_types;
use ethers::types::{BlockNumber, GethDebugTracingOptions, U64};

use crate::error::Error;

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
                chain_id: eth_types::Word::from(chain_id.as_u64()),
                circuit_params,
            })
        } else {
            Err(Error::InternalError(
                "Unable to get chain id from ETH client",
            ))
        }
    }

    pub async fn get_block_traces(&self, block_number: u64) -> Result<(), Error> {
        let block = self
            .anvil
            .block_by_number_full(BlockNumber::from(U64::from(block_number)))
            .await?
            .expect("block not found");

        let mut traces = Vec::new();
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

        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::client;
    use crate::inputs_builder::BuilderClient;
    use bus_mapping::circuit_input_builder::CircuitsParams;

    #[tokio::test]
    async fn test() {
        let anvil = client::setup().await;
        let bc = BuilderClient::new(anvil, CircuitsParams::default()).unwrap();
        assert_eq!(bc.chain_id.as_u64(), 31337);
    }
}
