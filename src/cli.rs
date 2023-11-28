use crate::{
    env::Env,
    utils::{
        anvil::types::zkevm_types::Bytes,
        huff::compile_huff,
        ipfs,
        real_prover::{Proof, RealVerifier},
        solidity,
    },
};
use clap::{arg, command, ArgMatches, Command};
use eth_types::U256;
use ethers::utils::parse_ether;
use semver::Version;
use std::{fs::create_dir_all, path::PathBuf, process, str::FromStr};

pub const EXPLOIT: &str = "exploit";
pub const TEST: &str = "test";
pub const PROVE: &str = "prove";
pub const VERIFY: &str = "verify";
pub const SCAFFOLD: &str = "scaffold";

pub fn exploit_command() -> Command {
    command!(EXPLOIT)
        .name("Proof of Exploit")
        .about("Generate and verify zk proof of exploits for ethereum smart contracts")
        .version("v0.1.0")
        .after_help("Find more information at https://github.com/zemse/proof-of-exploit")
        .subcommands([
            ProveArgs::apply(command!(TEST)).about("Test the exploit using MockProver (~15G RAM)"),
            ProveArgs::apply(command!(PROVE)).about("Generate proof using RealProver (200G+ RAM)"),
            VerifyArgs::apply(command!(VERIFY)).about("Verify zk proofs"),
            ScaffoldArgs::apply(command!(SCAFFOLD))
                .about("Scaffold new project for writing exploit"),
        ])
        .subcommand_required(true)
}

pub struct ProveArgs {
    pub rpc: String,
    pub geth_rpc: Option<String>,
    pub block: Option<usize>,
    pub challenge_artifact: solidity::Artifact,
    pub exploit_bytecode: Bytes,
    pub exploit_balance: U256,
    pub gas: Option<usize>,
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
            .arg(arg!(--gas <NUMBER> "Enter amount of gas for exploit tx" ))
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
        let challenge_artifact = solidity::Artifact::from_source(challenge_input);
        let exploit_input = parse_optional(arg_matches, "exploit")
            .or(env.exploit_path)
            .unwrap_or("./src/Exploit.huff".to_string());
        let exploit_bytecode = compile_huff(exploit_input);
        let exploit_balance =
            parse_ether(parse_optional(arg_matches, "exploit-balance").unwrap_or("0".to_string()))
                .expect("please provide ether amount correctly for --exploit-balance");
        let gas = parse_optional(arg_matches, "gas");
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
            gas,
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
        c.arg(arg!(--srs <PATH> "Enter the path for storing SRS parameters" ))
            .arg(arg!(--proof <PATH> "Enter the proof path or IPFS hash" ))
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

pub struct ScaffoldArgs {
    pub project_name: String,
}

impl ScaffoldArgs {
    pub fn apply(c: clap::Command) -> clap::Command {
        c.arg(arg!(--name <NAME> "Enter project name"))
            .arg_required_else_help(true)
    }

    pub fn from(arg_matches: Option<&ArgMatches>) -> Self {
        let arg_matches = arg_matches.unwrap();
        let project_name =
            parse_optional(arg_matches, "name").expect("please provide project name using --name");
        Self { project_name }
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

pub fn parse_optional<T: FromStr>(am: &ArgMatches, id: &str) -> Option<T>
where
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    am.get_one::<String>(id).map(|val| val.parse().unwrap())
}
