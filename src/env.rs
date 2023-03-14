use dotenv::dotenv;
use ethers::types::U64;
use std::env;

#[allow(dead_code)]
pub struct Env {
    pub eth_rpc_url: Option<String>,
    pub fork_block_number: Option<usize>,
}

#[allow(dead_code)]
impl Env {
    pub fn load() -> Env {
        dotenv().ok();
        let eth_rpc_url = match env::var("ETH_RPC_URL") {
            Ok(val) => Some(val),
            Err(_) => None,
        };
        let fork_block_number = match env::var("FORK_BLOCK_NUMBER") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };

        Env {
            eth_rpc_url,
            fork_block_number,
        }
    }
}
