use anvil::{eth::EthApi, spawn, NodeConfig};

pub async fn setup() -> EthApi {
    let mut nc = NodeConfig::default();
    nc.port = 8548;
    nc.silent = true;
    nc.enable_steps_tracing = true;
    let (api, _) = spawn(nc).await;
    api
}

#[cfg(test)]
mod tests {
    use crate::client::setup;

    #[tokio::test]
    async fn test() {
        let cli = setup().await;
        let bn = cli.block_number().unwrap().as_u64();
        assert_eq!(bn, 0);
    }
}
