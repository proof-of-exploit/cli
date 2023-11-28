use super::{anvil::conversion::ConversionReverse, helpers::hashmap};
use crate::error::Error;
use anvil_core::eth::transaction::EthTransactionRequest;
use bus_mapping::{POX_CHALLENGE_ADDRESS, POX_EXPLOIT_ADDRESS};
use eth_types::{Bytes, GethExecTrace, Transaction, U256, U64};
use ethers::{
    providers::{Http, Provider},
    utils::hex,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone)]
pub struct GethClient {
    provider: Provider<Http>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GethDebugTracingOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_storage: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_stack: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_memory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_return_data: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_overrides: Option<HashMap<String, StateOverrides>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StateOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
}

impl GethClient {
    pub fn new(url: String) -> Self {
        GethClient {
            provider: Provider::<Http>::try_from(&url).unwrap(),
        }
    }

    pub async fn simulate_exploit(
        &self,
        tx: &Transaction,
        challenge_bytecode: Bytes,
        exploit_bytecode: Bytes,
        exploit_balance: U256,
    ) -> Result<GethExecTrace, Error> {
        Ok(self
            .provider
            .request::<_, GethExecTrace>(
                "debug_traceCall",
                [
                    serde_json::to_value(EthTransactionRequest {
                        from: Some(tx.from),
                        to: Some(POX_CHALLENGE_ADDRESS),
                        gas_price: tx.gas_price,
                        max_fee_per_gas: tx.max_fee_per_gas,
                        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
                        gas: Some(tx.gas),
                        value: Some(tx.value),
                        data: Some(tx.input.to_anvil_type()),
                        nonce: Some(tx.nonce),
                        chain_id: tx.chain_id.map(|c| U64::from(c.as_u64())),
                        access_list: None, // TODO tx.access_list,
                        transaction_type: tx.transaction_type.map(|c| U256::from(c.as_u64())),
                    })
                    .unwrap(),
                    Value::String("latest".to_string()), // node not support archive trace - Value::String(format!("0x{block_number:x}")),
                    serde_json::to_value(GethDebugTracingOptions {
                        enable_memory: None,
                        disable_stack: None,
                        disable_storage: None,
                        enable_return_data: None,
                        timeout: None,
                        state_overrides: Some(hashmap![
                            format!("{POX_CHALLENGE_ADDRESS:?}") => StateOverrides {
                                code: Some(hex::encode_prefixed(challenge_bytecode)),
                                balance: None,
                            },
                            format!("{POX_EXPLOIT_ADDRESS:?}") => StateOverrides {
                                code: Some(hex::encode_prefixed(exploit_bytecode)),
                                balance: Some(format!("0x{exploit_balance:x}")),
                            }
                        ]),
                    })
                    .unwrap(),
                ],
            )
            .await?)
    }
}
