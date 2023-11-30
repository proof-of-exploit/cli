use crate::{error::Error, utils::ipfs};
use bus_mapping::circuit_input_builder::FixedCParams;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::{
    fs::{remove_file, File},
    path::PathBuf,
};
use zkevm_circuits::super_circuit::{SuperCircuit, SuperCircuitParams};

const SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

#[derive(Clone)]
pub struct SRS {
    pub general_params: ParamsKZG<Bn256>,
    pub verifier_params: ParamsKZG<Bn256>,
    pub circuit_verifying_key: VerifyingKey<G1Affine>,
    pub circuit_proving_key: ProvingKey<G1Affine>,
}

impl SRS {
    pub fn load(circuit: &SuperCircuit<Fr>, degree: u32, srs_path: PathBuf) -> Self {
        let general_params = load_general_params(srs_path.clone(), degree);
        let verifier_params = load_verifier_params(srs_path.clone(), degree, &general_params);
        let circuit_verifying_key =
            load_circuit_verifying_key(srs_path.clone(), degree, circuit, &general_params);
        let circuit_proving_key = load_circuit_proving_key(
            srs_path,
            degree,
            circuit,
            &general_params,
            &circuit_verifying_key,
        );
        Self {
            general_params,
            verifier_params,
            circuit_verifying_key,
            circuit_proving_key,
        }
    }
}

pub struct VerifierSRS {
    pub general_params: ParamsKZG<Bn256>,
    pub verifier_params: ParamsKZG<Bn256>,
    pub circuit_verifying_key: VerifyingKey<G1Affine>,
}

impl VerifierSRS {
    pub async fn load(
        srs_path: PathBuf,
        degree: u32,
        circuit_params: SuperCircuitParams<Fr>,
        fcp: FixedCParams,
    ) -> Self {
        let general_params = read(
            srs_path.clone(),
            general_params_file_name(degree),
            |mut file| Ok(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?),
        )
        .await
        .unwrap();
        let verifier_params = read(
            srs_path.clone(),
            verifier_params_file_name(degree),
            |mut file| Ok(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?),
        )
        .await
        .unwrap();
        let circuit_verifying_key = read(
            srs_path,
            circuit_verifying_key_file_name(degree, fcp),
            |file| {
                Ok(VerifyingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                    file,
                    SERDE_FORMAT,
                    circuit_params.clone(),
                )?)
            },
        )
        .await
        .unwrap();
        Self {
            general_params,
            verifier_params,
            circuit_verifying_key,
        }
    }
}

fn general_params_file_name(degree: u32) -> String {
    format!("kzg_general_params_{}", degree)
}

fn verifier_params_file_name(degree: u32) -> String {
    format!("kzg_verifier_params_{}", degree)
}

fn circuit_verifying_key_file_name(degree: u32, fcp: FixedCParams) -> String {
    format!("PoX_verifying_key_{}_{}", degree, circuit_params_str(fcp))
}

fn circuit_proving_key_file_name(degree: u32, fcp: FixedCParams) -> String {
    format!("PoX_proving_key_{}_{}", degree, circuit_params_str(fcp),)
}

fn load_general_params(srs_path: PathBuf, degree: u32) -> ParamsKZG<Bn256> {
    read_or_gen(
        "general params",
        srs_path.join(general_params_file_name(degree)),
        |mut file| Ok(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?),
        |mut file| {
            let rng = ChaChaRng::seed_from_u64(2);
            let general_params = ParamsKZG::<Bn256>::setup(degree, rng);
            general_params.write_custom(&mut file, SERDE_FORMAT)?;
            Ok(general_params)
        },
    )
    .expect("load_general_params should not fail")
}

fn load_verifier_params(
    srs_path: PathBuf,
    degree: u32,
    general_params: &ParamsKZG<Bn256>,
) -> ParamsKZG<Bn256> {
    read_or_gen(
        "verifier params",
        srs_path.join(verifier_params_file_name(degree)),
        |mut file| Ok(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?),
        |mut file| {
            let verifier_params = general_params.verifier_params().to_owned();
            verifier_params.write_custom(&mut file, SERDE_FORMAT)?;
            Ok(verifier_params)
        },
    )
    .expect("load_verifier_params should not fail")
}

fn load_circuit_verifying_key(
    srs_path: PathBuf,
    degree: u32,
    circuit: &SuperCircuit<Fr>,
    general_params: &ParamsKZG<Bn256>,
) -> VerifyingKey<G1Affine> {
    read_or_gen(
        "circuit verifying key",
        srs_path.join(circuit_verifying_key_file_name(
            degree,
            circuit.circuits_params,
        )),
        |file| {
            Ok(VerifyingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                file,
                SERDE_FORMAT,
                circuit.params(),
            )?)
        },
        |mut file| {
            let cvk = keygen_vk(&general_params.clone(), circuit)?;
            cvk.write(&mut file, SERDE_FORMAT)?;
            Ok(cvk)
        },
    )
    .expect("load_circuit_verifying_key should not fail")
}

fn load_circuit_proving_key(
    srs_path: PathBuf,
    degree: u32,
    circuit: &SuperCircuit<Fr>,
    general_params: &ParamsKZG<Bn256>,
    circuit_verifying_key: &VerifyingKey<G1Affine>,
) -> ProvingKey<G1Affine> {
    read_or_gen(
        "circuit proving key",
        srs_path.join(circuit_proving_key_file_name(
            degree,
            circuit.circuits_params,
        )),
        |file| {
            Ok(ProvingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                file,
                SERDE_FORMAT,
                circuit.params(),
            )?)
        },
        |mut file| {
            let cpk = keygen_pk(general_params, circuit_verifying_key.clone(), circuit)?;
            cpk.write(&mut file, SERDE_FORMAT)?;
            Ok(cpk)
        },
    )
    .expect("load_circuit_proving_key should not fail")
}

async fn read<T, F>(srs_path: PathBuf, file_name: String, mut read: F) -> Result<T, Error>
where
    F: FnMut(&mut File) -> Result<T, Error>,
{
    let path = srs_path.join(file_name.clone());
    if !path.exists() {
        if let Some(ipfs_hash) = get_ipfs_hash(file_name.clone()) {
            println!("Downloading {file_name} from IPFS...");
            ipfs::download_file(ipfs_hash, path.to_string_lossy().to_string()).await
        }
    }
    let mut file = File::open(path)?;
    read(&mut file)
}

fn read_or_gen<T, F1, F2>(label: &str, path: PathBuf, mut read: F1, mut gen: F2) -> Result<T, Error>
where
    F1: FnMut(&mut File) -> Result<T, Error>,
    F2: FnMut(&mut File) -> Result<T, Error>,
{
    let file = File::open(path.clone());
    if let Ok(mut file) = file {
        println!("Reading {label}...");
        match read(&mut file) {
            Ok(result) => {
                return Ok(result);
            }
            Err(e) => {
                // Remove file and freshly create it in next step
                println!("Failed {e:?}");
                remove_file(path.clone())
                    .unwrap_or_else(|_| panic!("Failed to remove file: {}", path.display()));
            }
        }
    }

    println!("Generating {label}...");
    let result = gen(&mut File::create(path)?)?;
    Ok(result)
}

fn circuit_params_str(fcp: FixedCParams) -> String {
    format!(
        "{}_{}_{}_{}_{}_{}_{}_{}",
        fcp.max_rws,
        fcp.max_txs,
        fcp.max_calldata,
        fcp.max_copy_rows,
        fcp.max_exp_steps,
        fcp.max_bytecode,
        fcp.max_evm_rows,
        fcp.max_keccak_rows,
    )
}

fn get_ipfs_hash(file_name: String) -> Option<String> {
    // TODO improve this code
    if file_name == *"kzg_general_params_19" || file_name == *"kzg_verifier_params_19".to_string() {
        Some("QmeJngu5KuP4NjCimnkZjoGHt5xUY2eSmoADiZTf6WUwHG".to_string())
    } else if file_name
        == *"PoX_verifying_key_19_40000_1_256_40000_40000_10000_20000_50000".to_string()
    {
        Some("QmWGqxjCWrReL3WQy86g56dJ1hKY9miB91rnjLzHeeGivo".to_string())
    } else {
        None
    }
}
