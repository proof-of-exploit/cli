use crate::{
    constants::{MAX_CALLDATA, MAX_TXS, RANDOMNESS},
    env::Env,
    real_prover::{Proof, RealVerifier},
    types::{anvil_types, zkevm_types::Bytes},
    utils::{compile_huff, ipfs, solc},
    BuilderClient, RealProver,
};
use bus_mapping::{
    circuit_input_builder::{FixedCParams, PoxInputs},
    POX_CHALLENGE_ADDRESS, POX_EXPLOIT_ADDRESS,
};
use clap::{arg, ArgMatches};
use core::slice::SlicePattern;
use eth_types::{keccak256, Fr, U256, U64};
use ethers::utils::{hex, parse_ether};
use halo2_proofs::dev::MockProver;
use semver::Version;
use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    process,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use zkevm_circuits::{
    super_circuit::SuperCircuit,
    util::{log2_ceil, SubCircuit},
};

pub struct ProveArgs {
    pub rpc: String,
    pub geth_rpc: Option<String>,
    pub block: Option<usize>,
    pub challenge_artifact: solc::Artifact,
    pub exploit_bytecode: Bytes,
    pub exploit_balance: U256,
    pub tx: Bytes,
    pub srs_path: PathBuf,
    pub ipfs: bool,
    pub max_rws: usize,
    pub max_copy_rows: usize,
    pub max_exp_steps: usize,
    pub max_bytecode: usize,
    pub max_evm_rows: usize,
    pub max_keccak_rows: usize,
}

impl ProveArgs {
    pub fn apply(c: clap::Command) -> clap::Command {
        c.arg(arg!(--rpc <URL> "Enter ethereum archive node RPC url" ))
            .arg(arg!(--"geth-rpc" <URL> "Use geth node for generating traces" ))
            .arg(arg!(--block <NUMBER> "Enter the fork block number" ))
            .arg(arg!(--challenge <CONTRACT> "Enter hex bytecode or file path" ))
            .arg(arg!(--exploit <CONTRACT> "Enter hex bytecode or file path" ))
            .arg(arg!(--"exploit-balance" <NUMBER> "Enter ether amount to fund 0xbada55 address" ))
            .arg(arg!(--tx <HEX> "Enter the tx" ))
            .arg(arg!(--srs <PATH> "Enter the dir for srs params" ))
            .arg(arg!(--ipfs "Publish the proof to IPFS" ))
            .arg(arg!(--"max-rws" <NUMBER>))
            .arg(arg!(--"max-copy-rows" <NUMBER>))
            .arg(arg!(--"max-exp-steps" <NUMBER>))
            .arg(arg!(--"max-bytecode" <NUMBER>))
            .arg(arg!(--"max-evm-rows" <NUMBER>))
            .arg(arg!(--"max-keccak-rows" <NUMBER>))
    }

    pub fn from(arg_matches: Option<&ArgMatches>, env: Env) -> Self {
        let arg_matches = arg_matches.unwrap();
        let rpc = parse_optional(arg_matches, "rpc")
            .or(env.eth_rpc_url)
            .expect("please provide --rpc or ETH_RPC_URL");
        let geth_rpc = parse_optional(arg_matches, "geth-rpc");
        let block = parse_optional(arg_matches, "block").or(env.fork_block_number);
        let challenge_input = parse_optional(arg_matches, "challenge")
            .or(env.challenge_path)
            .unwrap_or("./src/Challenge.sol".to_string());
        let challenge_artifact = solc::Artifact::from_source(challenge_input);
        let exploit_input = parse_optional(arg_matches, "exploit")
            .or(env.exploit_path)
            .unwrap_or("./src/Exploit.huff".to_string());
        let exploit_bytecode = compile_huff(exploit_input);
        let exploit_balance =
            parse_ether(parse_optional(arg_matches, "exploit-balance").unwrap_or("0".to_string()))
                .expect("please provide ether amount correctly for --exploit-balance");
        let tx = parse_optional(arg_matches, "tx").unwrap_or(Bytes::from_str("0xf86c8084ee6b2800830249f094feedc0de000000000000000000000000000000008084b0d691fe8401546d72a01e8eb2b20f4b86774c885aaf14686a3c3f42843ce12b838e74cb5f87c5c4ca01a045dae624463186e4c7d4866fc72c1740e59de8b5d5295dc4e8c5393a4c4c02e1").unwrap());
        let srs_path = parse_srs_path(arg_matches);
        let ipfs = arg_matches.get_flag("ipfs");
        let max_rws = parse_optional(arg_matches, "max-rws").unwrap_or(env.max_rws.unwrap_or(1000));
        let max_copy_rows = parse_optional(arg_matches, "max-copy-rows")
            .unwrap_or(env.max_copy_rows.unwrap_or(1000));
        let max_exp_steps = parse_optional(arg_matches, "max-exp-steps")
            .unwrap_or(env.max_exp_steps.unwrap_or(1000));
        let max_bytecode =
            parse_optional(arg_matches, "max-bytecode").unwrap_or(env.max_bytecode.unwrap_or(512));
        let max_evm_rows =
            parse_optional(arg_matches, "max-evm-rows").unwrap_or(env.max_evm_rows.unwrap_or(1000));
        let max_keccak_rows = parse_optional(arg_matches, "max-keccak-rows")
            .unwrap_or(env.max_keccak_rows.unwrap_or(1000));

        Self {
            rpc,
            geth_rpc,
            block,
            challenge_artifact,
            exploit_bytecode,
            exploit_balance,
            tx,
            srs_path,
            ipfs,
            max_rws,
            max_copy_rows,
            max_exp_steps,
            max_bytecode,
            max_evm_rows,
            max_keccak_rows,
        }
    }
}

pub struct VerifyArgs {
    pub srs_path: PathBuf,
    pub proof: Proof,
    pub unpack_dir: Option<String>,
}

impl VerifyArgs {
    pub fn apply(c: clap::Command) -> clap::Command {
        c.arg(arg!(--srs <PATH> "Enter the proof path for rw" ))
            .arg(arg!(--proof <PATH> "Enter the proof path for rw" ))
            .arg(arg!(--unpack <PATH> "Enter path to unpack challenge solidity code" ))
    }

    pub async fn from(arg_matches: Option<&ArgMatches>) -> Self {
        let arg_matches = arg_matches.unwrap();
        let srs_path = parse_srs_path(arg_matches);

        let proof_input: String = parse_optional(arg_matches, "proof")
            .expect("please provide the path to proof json file using --proof");
        let proof = if let Ok(proof) =
            Proof::read_from_file(&PathBuf::from_str(proof_input.as_str()).unwrap())
        {
            proof
        } else {
            ipfs::get(proof_input).await.unwrap()
        };

        let unpack_dir: Option<String> = parse_optional(arg_matches, "unpack");

        Self {
            srs_path,
            proof,
            unpack_dir,
        }
    }
}

fn parse_srs_path(arg_matches: &ArgMatches) -> PathBuf {
    let srs_input: String =
        parse_optional(arg_matches, "srs").expect("please provide --srs or SRS_PATH");
    // TODO add default SRS path
    let mut srs_path = PathBuf::from_str(".").unwrap();
    if !srs_input.is_empty() {
        srs_path = srs_path.join(srs_input);
    }
    create_dir_all(srs_path.clone()).unwrap();
    srs_path
}

fn parse_optional<T: FromStr>(am: &ArgMatches, id: &str) -> Option<T>
where
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    am.get_one::<String>(id).map(|val| val.parse().unwrap())
}

pub struct Witness {
    k: u32,
    instance: Vec<Vec<Fr>>,
    circuit: SuperCircuit<Fr>,
}

impl Witness {
    pub async fn gen(args: &ProveArgs) -> Witness {
        let challenge_bytecode = args
            .challenge_artifact
            .get_deployed_bytecode("Challenge".to_string())
            .unwrap();

        let builder = BuilderClient::from_config(
            FixedCParams {
                max_rws: args.max_rws,
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                max_copy_rows: args.max_copy_rows,
                max_exp_steps: args.max_exp_steps,
                max_bytecode: args.max_bytecode,
                max_evm_rows: args.max_evm_rows,
                max_keccak_rows: args.max_keccak_rows,
            },
            Some(args.rpc.clone()),
            args.geth_rpc.clone(),
            args.block,
        )
        .await
        .unwrap();

        let chain_id = builder.anvil.eth_chain_id().unwrap().unwrap();
        let block_number = builder.anvil.block_number().unwrap();
        println!("Anvil initialized - chain_id: {chain_id:?}, block_number: {block_number:?}");

        // updating challenge bytecode in local mainnet fork chain
        builder
            .anvil
            .set_code(POX_CHALLENGE_ADDRESS, challenge_bytecode.clone())
            .await
            .unwrap();
        // updating exploit bytecode in local mainnet fork chain
        builder
            .anvil
            .set_code(POX_EXPLOIT_ADDRESS, args.exploit_bytecode.clone())
            .await
            .unwrap();

        let exploit_balance_before = builder
            .anvil
            .get_balance(POX_EXPLOIT_ADDRESS, args.block)
            .await
            .unwrap();
        builder
            .anvil
            .set_balance(POX_EXPLOIT_ADDRESS, args.exploit_balance)
            .await
            .unwrap();

        // check for reverts and panic out
        builder
            .anvil
            .estimate_gas(
                anvil_types::EthTransactionRequest {
                    from: None,
                    to: Some(POX_CHALLENGE_ADDRESS),
                    gas_price: Some(U256::zero()),
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    gas: Some(U256::from(1_000_000)),
                    value: Some(U256::zero()),
                    data: Some(anvil_types::Bytes::from_str("0xb0d691fe").unwrap()),
                    nonce: None,
                    chain_id: None,
                    access_list: None,
                    transaction_type: None,
                },
                None,
            )
            .await
            .unwrap();

        // confirm the tx on the local block
        let hash = builder
            .anvil
            .send_raw_transaction(args.tx.clone())
            .await
            .unwrap();
        builder.anvil.wait_for_transaction(hash).await.unwrap();

        let rc = builder
            .anvil
            .transaction_receipt(hash)
            .await
            .unwrap()
            .unwrap();

        println!("transaction gas: {}", rc.gas_used.unwrap());
        // println!("transaction success: {}", rc.status.unwrap());
        if rc.status.unwrap() != U64::from(1) {
            // TODO make sure that storage is also updated and not just tx is successful
            // TODO make sure that storage update with reversion does not pass the lookup check
            // TODO also add a --traces option to print helpful info to debug this for user
            println!("error: exploit transaction is not successful.");
            process::exit(1);
        }

        println!("tx confirmed on anvil, hash: {}", hex::encode(hash));

        let tx = builder
            .anvil
            .transaction_by_hash(hash)
            .await
            .unwrap()
            .unwrap();

        let mut witness = builder
            .gen_witness(
                tx.block_number.unwrap().as_usize(),
                PoxInputs {
                    challenge_codehash: keccak256(challenge_bytecode.as_slice()).into(),
                    challenge_bytecode,
                    exploit_codehash: keccak256(args.exploit_bytecode.as_slice()).into(),
                    exploit_bytecode: args.exploit_bytecode.clone(),
                    exploit_balance: args.exploit_balance,
                    exploit_balance_before,
                },
                args.geth_rpc.is_some(),
            )
            .await
            .unwrap();
        witness.randomness = Fr::from(RANDOMNESS);

        println!("Witness generated");

        let (_, rows_needed) = SuperCircuit::<Fr>::min_num_rows_block(&witness);
        let circuit = SuperCircuit::<Fr>::new_from_block(&witness);
        let k = log2_ceil(64 + rows_needed);
        let instance = circuit.instance();

        println!("Instances: {instance:#?}");

        Witness {
            k,
            instance,
            circuit,
        }
    }

    pub fn assert(self) {
        println!("Running MockProver");
        let prover = MockProver::run(self.k, &self.circuit, self.instance).unwrap();
        println!("Verifying constraints");
        prover.assert_satisfied_par();
        println!("Success!");
    }

    pub async fn prove(self, args: ProveArgs) {
        println!("Running RealProver");
        let mut prover = RealProver::from(self.circuit, self.k, Some(args.srs_path.clone()));

        println!("Generating proof...");
        let mut proof = prover.prove().unwrap();
        proof.challenge_artifact = Some(args.challenge_artifact);

        // TODO don't write to SRS directory
        let proof_path = args.srs_path.join(Path::new(&format!(
            "proof_{}_{}.json",
            self.k,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )));
        println!("Writing proof to {}", proof_path.display());
        proof.write_to_file(&proof_path).unwrap();
        println!("Success!");

        // sanity check
        let verifier = prover.verifier();
        verifier.verify(&proof).await.unwrap();

        if args.ipfs {
            let hash = ipfs::publish(&proof).await.unwrap();
            println!("Published proof to ipfs: {}", hash);
        }
    }
}

pub async fn handle_verify(args: VerifyArgs) {
    let my_version = Version::from_str(env!("CARGO_PKG_VERSION")).unwrap();
    if my_version < args.proof.version {
        println!(
            "This proof was generated using a newer version of Proof of Exploit. Please upgrade to version v{} or latest if you are facing issues.\n",
            args.proof.version
        );
    }

    println!("Verifying proof...");
    let verifier = RealVerifier::load_srs(args.srs_path, &args.proof);
    if let Err(error) = verifier.verify(&args.proof).await {
        println!("Proof verification failed: {:?}", error);
        process::exit(1);
    } else {
        println!("Success!");
    }

    if let Some(unpack_dir) = args.unpack_dir {
        if let Some(challenge_artifact) = args.proof.challenge_artifact {
            println!("\nUnpacking challenge source code...");
            challenge_artifact.unpack(unpack_dir);
            println!("Done!");
        } else {
            println!("\nError: Proof does not contain challenge source code to unpack.");
        }
    } else {
        println!("\nTo view challenge source code, use --unpack flag.");
    }
}
