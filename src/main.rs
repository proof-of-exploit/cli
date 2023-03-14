use zk_proof_of_evm_exploit::{client, env::Env};

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let env = Env::load();
    let cli = client::setup(env.eth_rpc_url, env.fork_block_number).await;
    let bn = cli.block_number().unwrap().as_u64();
    println!("block {}", bn);
}
