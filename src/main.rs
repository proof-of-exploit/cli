use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use zk_proof_of_evm_exploit::{BuilderClient, ExploitCircuit};
use zkevm_circuits::util::{log2_ceil, SubCircuit};
#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let builder = BuilderClient::default().await.unwrap();

    let chain_id = builder.anvil.eth_chain_id().unwrap().unwrap();
    let block_number = builder.anvil.block_number().unwrap();
    println!("chain_id: {:?}, block_number: {:?}", chain_id, block_number);

    let raw_tx = "0x01f88d83aa36a70184ee6b28008301388094df03add8bc8046df3b74a538c57c130cefb89b8680a46057361d0000000000000000000000000000000000000000000000000000000000000001c080a0c555cc61abbe8af27dc54279c25f70d6883841de257f13c56a770b8d07e7d065a06dbaf6fafad5e1735ad3f47af1210b742df31e35c68b8b9eedabdd9e6234291a";
    let hash = builder
        .anvil
        .send_raw_transaction(raw_tx.parse().unwrap())
        .await
        .unwrap();
    builder.anvil.mine_one().await;

    let tx = builder
        .anvil
        .transaction_by_hash(hash)
        .await
        .unwrap()
        .unwrap();

    println!("tx: {:?}", tx);

    println!("inputs generated");

    let witness = builder
        .gen_witness(tx.block_number.unwrap().as_usize())
        .await
        .unwrap();
    let circuit = ExploitCircuit::<Fr, 1, 256, 0x100>::new_from_block(&witness);
    let (_, rows_needed) = ExploitCircuit::<Fr, 1, 256, 0x100>::min_num_rows_block(&witness);
    let k = log2_ceil(64 + rows_needed);
    let instance = circuit.instance();

    println!("proving");
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    println!("proving done, now verifying");
    let _res = prover.verify_par();
    println!("verifying done");
}
