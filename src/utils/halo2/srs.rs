use crate::error::Error;
use bus_mapping::circuit_input_builder::FixedCParams;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::{fs::File, path::PathBuf};
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
    pub fn load(
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
        .unwrap();
        let verifier_params = read(
            srs_path.clone(),
            verifier_params_file_name(degree),
            |mut file| Ok(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?),
        )
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
        srs_path,
        general_params_file_name(degree),
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
        srs_path,
        verifier_params_file_name(degree),
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
        srs_path,
        circuit_verifying_key_file_name(degree, circuit.circuits_params),
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
        srs_path,
        circuit_proving_key_file_name(degree, circuit.circuits_params),
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

fn read<T, F>(srs_path: PathBuf, file_name: String, mut read: F) -> Result<T, Error>
where
    F: FnMut(&mut File) -> Result<T, Error>,
{
    let path = srs_path.join(file_name);
    let mut file = File::open(path)?;
    read(&mut file)
}

fn read_or_gen<T, F1, F2>(
    srs_path: PathBuf,
    file_name: String,
    mut read: F1,
    mut gen: F2,
) -> Result<T, Error>
where
    F1: FnMut(&mut File) -> Result<T, Error>,
    F2: FnMut(&mut File) -> Result<T, Error>,
{
    let path = srs_path.join(file_name);
    match File::open(path.clone()) {
        Ok(mut file) => {
            // file exists, read it
            read(&mut file)
        }
        Err(_) => {
            // file does not exist, generate and write it
            gen(&mut File::create(path).unwrap())
        }
    }
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
