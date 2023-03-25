/// Usage:
/// ./target/release/prove
///     --mock
///     --rpc-url https://eth-sepolia.g.alchemy.com/v2/<api_key>
///     --fork-block 3147881
///     --challenge-address 0xdf03add8bc8046df3b74a538c57c130cefb89b86
///     --challenge-slot 0
///     --raw-tx 0xf88c8084ee6b28008301388094df03add8bc8046df3b74a538c57c130cefb89b8680a46057361d00000000000000000000000000000000000000000000000000000000000000018401546d72a0f5b7e54553deeb044429b394595581501209a627beef020e764426aa0955e93aa00927cb7de78c15d2715de9a5cbde171c7202755864656cd4726ac43c76a9000a
///
use clap::Parser;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use zk_proof_of_evm_exploit::{types::zkevm_types::*, BuilderClient, CircuitsParams};
use zkevm_circuits::{
    super_circuit::SuperCircuit,
    table::RwTableTag,
    util::{log2_ceil, SubCircuit},
    witness::Rw,
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    // required args
    #[arg(long = "rpc-url", help = "Archive node for mainnet fork [required]")]
    eth_rpc_url: String,
    #[arg(long = "fork-block", help = "Block number for mainnet fork [required]")]
    fork_block_number: usize,
    #[arg(
        long,
        help = "Address of contract containing challenge slot [required]"
    )]
    challenge_address: Address,
    #[arg(
        long,
        help = "Storage slot that should be flipped by a correct solution [required]"
    )]
    challenge_slot: U256,
    #[arg(long, help = "Witness tx, which should solve the challenge [required]")]
    raw_tx: String,

    // optional args
    #[arg(
        long,
        default_value_t = false,
        help = "Use MockProver for fast constraint verification [default: false]"
    )]
    mock: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Print witness and public inputs that has been provided to zkevm circuits [default: false]"
    )]
    print: bool,
    #[arg(long, default_value_t = 1000)]
    max_rws: usize,
    #[arg(long, default_value_t = 1000)]
    max_copy_rows: usize,
    #[arg(long, default_value_t = 1000)]
    max_exp_steps: usize,
    #[arg(long, default_value_t = 512)]
    max_bytecode: usize,
    #[arg(long, default_value_t = 1000)]
    max_evm_rows: usize,
    #[arg(long, default_value_t = 1000)]
    max_keccak_rows: usize,
}

#[tokio::main]
async fn main() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 256;
    const RANDOMNESS: u64 = 0x100;

    let args = Args::parse();

    let builder = BuilderClient::from_config(
        CircuitsParams {
            max_rws: args.max_rws,
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_copy_rows: args.max_copy_rows,
            max_exp_steps: args.max_exp_steps,
            max_bytecode: args.max_bytecode,
            max_evm_rows: args.max_evm_rows,
            max_keccak_rows: args.max_keccak_rows,
        },
        Some(args.eth_rpc_url),
        Some(args.fork_block_number),
    )
    .await
    .unwrap();

    let chain_id = builder.anvil.eth_chain_id().unwrap().unwrap();
    let block_number = builder.anvil.block_number().unwrap();
    println!("chain_id: {:?}, block_number: {:?}", chain_id, block_number);

    let hash = builder
        .anvil
        .send_raw_transaction(args.raw_tx.parse().unwrap())
        .await
        .unwrap();

    builder.anvil.wait_for_transaction(hash).await.unwrap();

    println!("tx confirmed on anvil");

    let tx = builder
        .anvil
        .transaction_by_hash(hash)
        .await
        .unwrap()
        .unwrap();

    let mut witness = builder
        .gen_witness(tx.block_number.unwrap().as_usize())
        .await
        .unwrap();
    witness.randomness = Fr::from(RANDOMNESS);

    println!("witness generated");

    let account_storage_rws = witness.rws[RwTableTag::AccountStorage].clone();

    for (i, rw) in account_storage_rws.iter().enumerate() {
        match rw {
            Rw::AccountStorage {
                rw_counter: _,
                is_write: _,
                account_address,
                storage_key,
                value: _,
                value_prev: _,
                tx_id: _,
                committed_value: _,
            } => {
                if account_address.to_owned() == args.challenge_address
                    && storage_key.to_owned() == args.challenge_slot
                {
                    witness.challenge_rw_index = Some(i);
                    break;
                }
            }
            _ => unreachable!(),
        }
    }

    if witness.challenge_rw_index.is_none() {
        panic!("challenge is not solved, please pass a valid solution");
    }

    let (_, rows_needed) =
        SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, RANDOMNESS>::min_num_rows_block(&witness);
    let circuit = SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, RANDOMNESS>::new_from_block(&witness);
    let k = log2_ceil(64 + rows_needed);
    let instance = circuit.instance();
    if args.print {
        println!("block witness: {:#?}", witness);
        println!("instance: {:#?}", instance);
    }

    if args.mock {
        println!("running MockProver");
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        println!("verifying constraints");
        prover.verify_par().unwrap();
        println!("success");
    } else {
        unimplemented!("real prover not implemented yet");
    }
}
