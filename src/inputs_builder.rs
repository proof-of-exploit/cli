use anvil::eth::EthApi;
use bus_mapping::circuit_input_builder::CircuitsParams;
use eth_types;

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
        if let Some(chain_id) = anvil.eth_chain_id().unwrap() {
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
