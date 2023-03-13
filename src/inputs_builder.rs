use anvil::eth::EthApi;
use bus_mapping::circuit_input_builder::CircuitsParams;
use eth_types;

pub struct BuilderClient {
    anvil: EthApi,
    chain_id: eth_types::Word,
    circuit_params: CircuitsParams,
}

impl BuilderClient {
    pub fn new(anvil: EthApi, circuit_params: CircuitsParams) -> Self {
        if let Some(chain_id) = anvil.eth_chain_id().unwrap() {
            Self {
                anvil,
                chain_id: eth_types::Word::from(chain_id.as_u64()),
                circuit_params,
            }
        } else {
            panic!("Unable to get chain id from ETH client")
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
        let bc = BuilderClient::new(anvil, CircuitsParams::default());
        assert_eq!(bc.chain_id.as_u64(), 31337);
    }
}
