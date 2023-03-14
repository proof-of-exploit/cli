use anvil::{eth::EthApi, spawn, NodeConfig};

#[allow(dead_code)]
pub async fn setup(eth_rpc_url: Option<String>, fork_block_number: Option<u64>) -> EthApi {
    let node_config = NodeConfig::default()
        .with_eth_rpc_url(eth_rpc_url)
        .with_fork_block_number(fork_block_number)
        .with_port(8548)
        .silent()
        .with_steps_tracing(true);

    let (api, _) = spawn(node_config).await;
    api
}

#[cfg(test)]
mod tests {
    use crate::client::setup;

    #[tokio::test]
    async fn test() {
        let cli = setup(None, None).await;
        let bn = cli.block_number().unwrap().as_u64();
        assert_eq!(bn, 0);
    }
}
