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

    let raw_tx = "0xf88c8084ee6b28008301388094df03add8bc8046df3b74a538c57c130cefb89b8680a46057361d00000000000000000000000000000000000000000000000000000000000000018401546d72a0f5b7e54553deeb044429b394595581501209a627beef020e764426aa0955e93aa00927cb7de78c15d2715de9a5cbde171c7202755864656cd4726ac43c76a9000a";
    let hash = builder
        .anvil
        .send_raw_transaction(raw_tx.parse().unwrap())
        .await
        .unwrap();

    builder.anvil.wait_for_transaction(hash).await.unwrap();

    let tx = builder
        .anvil
        .transaction_by_hash(hash)
        .await
        .unwrap()
        .unwrap();

    let witness = builder
        .gen_witness(tx.block_number.unwrap().as_usize())
        .await
        .unwrap();
    println!("witness {:#?}", witness);
    let circuit = ExploitCircuit::<Fr, 1, 256, 0x100>::new_from_block(&witness);
    let (_, rows_needed) = ExploitCircuit::<Fr, 1, 256, 0x100>::min_num_rows_block(&witness);
    let k = log2_ceil(64 + rows_needed);
    let instance = circuit.instance();
    println!("instance {:#?}", instance);

    println!("proving");
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    println!("proving done, now verifying");
    let _res = prover.verify_par().unwrap();
    println!("verifying done");
}
