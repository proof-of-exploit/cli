use bus_mapping::circuit_input_builder::FixedCParams;
use clap::Parser;
use eth_types::Fr;
use ethers_core::utils::hex;
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    SerdeFormat,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaChaRng};
use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};
use zk_proof_of_evm_exploit::{error::Error, types::zkevm_types::*, BuilderClient};
use zkevm_circuits::{
    super_circuit::SuperCircuit,
    util::{log2_ceil, SubCircuit},
};

/// Usage:
/// ./target/release/prove
///     --mock
///     --rpc-url https://eth-sepolia.g.alchemy.com/v2/<api_key>
///     --fork-block 3147881
///     --challenge-address 0xdf03add8bc8046df3b74a538c57c130cefb89b86
///     --challenge-slot 0
///     --raw-tx 0xf88c8084ee6b28008301388094df03add8bc8046df3b74a538c57c130cefb89b8680a46057361d00000000000000000000000000000000000000000000000000000000000000018401546d72a0f5b7e54553deeb044429b394595581501209a627beef020e764426aa0955e93aa00927cb7de78c15d2715de9a5cbde171c7202755864656cd4726ac43c76a9000a
///

const MAX_TXS: usize = 1;
const MAX_CALLDATA: usize = 256;
const RANDOMNESS: u64 = 0x100;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    // required args
    #[arg(long = "rpc-url", help = "Archive node for mainnet fork [required]")]
    eth_rpc_url: String,
    #[arg(long = "fork-block", help = "Block number for mainnet fork [required]")]
    fork_block_number: usize,
    #[arg(long, help = "Challenge bytecode [required]")]
    challenge_bytecode: Bytes,
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
    #[arg(
        long,
        default_value_t = String::new(),
        help = "Directory for reading and writing [default: false]"
    )]
    dir: String,
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
    #[arg(long, default_value_t = 10000)]
    max_keccak_rows: usize,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

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
        Some(args.eth_rpc_url),
        Some(args.fork_block_number),
    )
    .await
    .unwrap();

    let chain_id = builder.anvil.eth_chain_id().unwrap().unwrap();
    let block_number = builder.anvil.block_number().unwrap();
    println!("chain_id: {chain_id:?}, block_number: {block_number:?}");

    // updating challenge bytecode in local mainnet fork chain
    builder
        .anvil
        .set_code(
            bus_mapping::POX_CHALLENGE_ADDRESS,
            args.challenge_bytecode.clone(),
        )
        .await
        .unwrap();

    let hash = builder
        .anvil
        .send_raw_transaction(args.raw_tx.parse().unwrap())
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

    println!("tx confirmed on anvil, hash: {}", hex::encode(hash));

    let tx = builder
        .anvil
        .transaction_by_hash(hash)
        .await
        .unwrap()
        .unwrap();

    let mut witness = builder
        .gen_witness(tx.block_number.unwrap().as_usize(), args.challenge_bytecode)
        .await
        .unwrap();
    witness.randomness = Fr::from(RANDOMNESS);

    println!("witness generated");
    // println!("rws: {:#?}", witness.rws);

    // let account_storage_rws = witness.rws[Target::Storage].clone();

    // for (i, rw) in account_storage_rws.iter().enumerate() {
    //     match rw {
    //         witness::Rw::AccountStorage {
    //             rw_counter: _,
    //             is_write: _,
    //             account_address,
    //             storage_key,
    //             value: _,
    //             value_prev: _,
    //             tx_id: _,
    //             committed_value: _,
    //         } => {
    //             if *account_address == args.challenge_address && *storage_key == args.challenge_slot
    //             {
    //                 witness.challenge_rw_index = Some(i);
    //                 break;
    //             }
    //         }
    //         _ => unreachable!(),
    //     }
    // }

    // if witness.challenge_rw_index.is_none() {
    //     panic!("challenge is not solved, please pass a valid solution");
    // }

    let (_, rows_needed) = SuperCircuit::<Fr>::min_num_rows_block(&witness);
    let circuit = SuperCircuit::<Fr>::new_from_block(&witness);
    let k = log2_ceil(64 + rows_needed);
    let instance = circuit.instance();
    if args.print {
        println!("block witness: {witness:#?}");
        println!("instance: {instance:#?}");
    }

    if args.mock {
        println!("running MockProver");
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        println!("verifying constraints");
        prover.assert_satisfied_par();
        println!("success");
    } else {
        let mut dir_path = PathBuf::from_str(".").unwrap();
        if !args.dir.is_empty() {
            dir_path = dir_path.join(args.dir)
        }
        create_dir_all(dir_path.clone()).unwrap();

        println!("running RealProver");
        let mut prover = RealProver::init(k, dir_path.clone());
        prover.setup_global().unwrap();
        prover.setup_circuit(circuit.clone()).unwrap();

        println!("generating proof");
        let proof = prover.prove(circuit, instance).unwrap();
        let proof_path = dir_path.join(Path::new(&format!(
            "proof_{}_{}",
            prover.degree,
            hex::encode(hash)
        )));
        println!("writing proof to {}", proof_path.display());
        let mut file = File::create(proof_path).unwrap();
        file.write_all(proof.as_slice()).unwrap();
        println!("success");
    }
}

struct RealProver {
    degree: u32,
    dir_path: PathBuf,
    serde_format: SerdeFormat,
    rng: Option<ChaCha20Rng>,
    general_params: Option<ParamsKZG<Bn256>>,
    verifier_params: Option<ParamsKZG<Bn256>>,
    circuit_proving_key: Option<ProvingKey<G1Affine>>,
    circuit_verifying_key: Option<VerifyingKey<G1Affine>>,
}

impl RealProver {
    fn init(degree: u32, dir_path: PathBuf) -> Self {
        Self {
            degree,
            dir_path,
            serde_format: SerdeFormat::RawBytes,
            rng: None,
            general_params: None,
            verifier_params: None,
            circuit_proving_key: None,
            circuit_verifying_key: None,
        }
    }

    fn setup_global(&mut self) -> Result<(), Error> {
        self.setup_general_params()?;
        self.setup_verifier_params()?;
        Ok(())
    }

    fn prove(
        &mut self,
        circuit: SuperCircuit<Fr>,
        instance: Vec<Vec<Fr>>,
    ) -> Result<Vec<u8>, Error> {
        let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            ChaChaRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(
            self.general_params.as_mut().unwrap(),
            self.circuit_proving_key.as_mut().unwrap(),
            &[circuit],
            &[&instance_refs],
            self.rng.to_owned().unwrap(),
            &mut transcript,
        )
        .unwrap();
        Ok(transcript.finalize())
    }

    fn setup_general_params(&mut self) -> Result<(), Error> {
        self.rng = Some(ChaChaRng::seed_from_u64(2));
        let path = self
            .dir_path
            .join(Path::new(&format!("kzg_general_params_{}", self.degree)));
        match File::open(path.clone()) {
            Ok(mut file) => {
                println!("reading {}", path.display());
                self.general_params = Some(ParamsKZG::<Bn256>::read_custom(
                    &mut file,
                    self.serde_format,
                )?);
            }
            Err(_) => {
                println!("setting up general params");
                let general_params =
                    ParamsKZG::<Bn256>::setup(self.degree, self.rng.as_mut().unwrap());
                println!("writing {}", path.display());
                let mut file = File::create(path)?;
                general_params.write_custom(&mut file, self.serde_format)?;
                self.general_params = Some(general_params);
            }
        };
        Ok(())
    }

    fn setup_verifier_params(&mut self) -> Result<(), Error> {
        let path = self
            .dir_path
            .join(Path::new(&format!("kzg_verifier_params_{}", self.degree)));
        match File::open(path.clone()) {
            Ok(mut file) => {
                println!("reading {}", path.display());
                self.verifier_params = Some(ParamsKZG::<Bn256>::read_custom(
                    &mut file,
                    self.serde_format,
                )?);
            }
            Err(_) => {
                println!("setting up verifier params");
                let general_params = self.general_params.clone().unwrap();
                let verifier_params = general_params.verifier_params().to_owned();
                println!("writing {}", path.display());
                let mut file = File::create(path)?;
                verifier_params.write_custom(&mut file, self.serde_format)?;
                self.verifier_params = Some(verifier_params);
            }
        };
        Ok(())
    }

    fn setup_circuit(&mut self, circuit: SuperCircuit<Fr>) -> Result<(), Error> {
        let verifying_key_path = self
            .dir_path
            .join(Path::new(&format!("circuit_verifying_key_{}", self.degree)));
        match File::open(verifying_key_path.clone()) {
            Ok(mut file) => {
                println!("reading {}", verifying_key_path.display());
                self.circuit_verifying_key = Some(
                    VerifyingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                        &mut file,
                        self.serde_format,
                        circuit.params(),
                    )
                    .unwrap(),
                );
            }
            Err(_) => {
                println!("setting up verifying key");
                let vk = keygen_vk(self.general_params.as_mut().unwrap(), &circuit)
                    .expect("keygen_vk should not fail");
                println!("writing {}", verifying_key_path.display());
                let mut file = File::create(verifying_key_path)?;
                vk.write(&mut file, self.serde_format)?;
                self.circuit_verifying_key = Some(vk);
            }
        };

        let proving_key_path = self
            .dir_path
            .join(Path::new(&format!("circuit_proving_key_{}", self.degree)));
        match File::open(proving_key_path.clone()) {
            Ok(mut file) => {
                println!("reading {}", proving_key_path.display());
                self.circuit_proving_key = Some(
                    ProvingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                        &mut file,
                        self.serde_format,
                        circuit.params(),
                    )
                    .unwrap(),
                );
            }
            Err(_) => {
                println!("setting up proving key");
                let pk = keygen_pk(
                    self.general_params.as_mut().unwrap(),
                    self.circuit_verifying_key.clone().unwrap(),
                    &circuit,
                )
                .expect("keygen_pk should not fail");
                println!("writing {}", proving_key_path.display());
                let mut file = File::create(proving_key_path)?;
                pk.write(&mut file, self.serde_format)?;
                self.circuit_proving_key = Some(pk);
            }
        };
        Ok(())
    }
}
