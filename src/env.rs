use dotenv::dotenv;
use ethers::types::U64;
use std::env;

#[allow(dead_code)]
pub struct Env {
    pub eth_rpc_url: Option<String>,
    pub fork_block_number: Option<usize>,
    pub geth_rpc_url: Option<String>,
    pub challenge_path: Option<String>,
    pub exploit_path: Option<String>,
    pub exploit_balance: Option<String>,
    pub srs_path: Option<String>,
    pub max_rws: Option<usize>,
    pub max_copy_rows: Option<usize>,
    pub max_exp_steps: Option<usize>,
    pub max_bytecode: Option<usize>,
    pub max_evm_rows: Option<usize>,
    pub max_keccak_rows: Option<usize>,
}

#[allow(dead_code)]
impl Env {
    pub fn load() -> Env {
        dotenv().ok();
        // TODO refactor - remove duplicate code

        // anvil params
        let eth_rpc_url = match env::var("ETH_RPC_URL") {
            Ok(val) => Some(val),
            Err(_) => None,
        };
        let fork_block_number = match env::var("FORK_BLOCK_NUMBER") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };

        // temp params
        let geth_rpc_url = match env::var("GETH_RPC_URL") {
            Ok(val) => Some(val),
            Err(_) => None,
        };

        // PoX params
        let challenge_path = match env::var("CHALLENGE") {
            Ok(val) => Some(val),
            Err(_) => match env::var("CHALLENGE_PATH") {
                Ok(val) => Some(val),
                Err(_) => None,
            },
        };
        let exploit_path = match env::var("EXPLOIT") {
            Ok(val) => Some(val),
            Err(_) => match env::var("EXPLOIT_PATH") {
                Ok(val) => Some(val),
                Err(_) => None,
            },
        };
        let exploit_balance = match env::var("EXPLOIT_BALANCE") {
            Ok(val) => Some(val),
            Err(_) => None,
        };

        // zkEVM params
        let srs_path = match env::var("SRS") {
            Ok(val) => Some(val),
            Err(_) => match env::var("SRS_PATH") {
                Ok(val) => Some(val),
                Err(_) => None,
            },
        };
        let max_rws = match env::var("MAX_ROWS") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };
        let max_copy_rows = match env::var("MAX_COPY_ROWS") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };
        let max_exp_steps = match env::var("MAX_EXP_ROWS") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };
        let max_bytecode = match env::var("MAX_BYTECODE") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };
        let max_evm_rows = match env::var("MAX_EVM_ROWS") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };
        let max_keccak_rows = match env::var("MAX_KECCAK_ROWS") {
            Ok(val) => Some(U64::from_str_radix(&val, 10).unwrap().as_usize()),
            Err(_) => None,
        };

        Env {
            eth_rpc_url,
            fork_block_number,
            geth_rpc_url,
            challenge_path,
            exploit_path,
            exploit_balance,
            srs_path,
            max_rws,
            max_copy_rows,
            max_exp_steps,
            max_bytecode,
            max_evm_rows,
            max_keccak_rows,
        }
    }
}
