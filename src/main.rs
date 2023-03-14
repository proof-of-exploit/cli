use zk_proof_of_evm_exploit::BuilderClient;

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let builder = BuilderClient::default().await.unwrap();

    builder
        .anvil
        .fund_wallet(
            "0x2CA4c197AE776f675A114FBCB0B03Be845f0316d"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    let (circuit_input_builder, block) = builder
        .gen_inputs(builder.anvil.block_number().unwrap())
        .await
        .unwrap();
    // println!("block {}", bn);
}
