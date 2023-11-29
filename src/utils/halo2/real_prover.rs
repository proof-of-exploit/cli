use super::{helpers::derive_circuit_name, proof::Proof, real_verifier::RealVerifier};
use crate::error::Error;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
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
use std::{fs::File, path::PathBuf};
use zkevm_circuits::{
    instance::public_data_convert, super_circuit::SuperCircuit, util::SubCircuit,
};

const SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

#[derive(Clone)]
pub struct RealProver {
    circuit: SuperCircuit<Fr>,
    circuit_name: String,
    degree: u32,
    srs_path: PathBuf,
    rng: ChaCha20Rng,
    general_params: Option<ParamsKZG<Bn256>>,
    verifier_params: Option<ParamsKZG<Bn256>>,
    circuit_verifying_key: Option<VerifyingKey<G1Affine>>,
    circuit_proving_key: Option<ProvingKey<G1Affine>>,
}

impl RealProver {
    pub fn from(circuit: SuperCircuit<Fr>, k: u32, srs_path: PathBuf) -> Self {
        let circuit_name = derive_circuit_name(&circuit);
        Self {
            circuit,
            circuit_name,
            degree: k,
            srs_path,
            rng: ChaChaRng::seed_from_u64(2),
            general_params: None,
            verifier_params: None,
            circuit_verifying_key: None,
            circuit_proving_key: None,
        }
    }

    pub fn load(&mut self) {
        self.load_general_params();
        self.load_verifier_params();
        self.load_circuit_verifying_key();
        self.load_circuit_proving_key();
    }

    pub fn prove(&mut self) -> Result<Proof, Error> {
        self.load();
        let public_data = public_data_convert(&self.circuit.evm_circuit.block.clone().unwrap());
        let instances = self.circuit.instance();
        let instances_refs_intermediate = instances.iter().map(|v| &v[..]).collect::<Vec<&[Fr]>>();
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
            &[self.circuit.clone()],
            &[&instances_refs_intermediate],
            self.rng.to_owned(),
            &mut transcript,
        )
        .unwrap();

        let proof = transcript.finalize();
        Ok(Proof::from(
            self.degree,
            proof,
            instances,
            self.circuit_name.clone(),
            self.circuit.params(),
            public_data,
            None,
        ))
    }

    pub fn verifier(&mut self) -> RealVerifier {
        self.load_general_params();
        self.load_verifier_params();
        self.load_circuit_verifying_key();
        RealVerifier {
            general_params: self.general_params.clone().unwrap(),
            verifier_params: self.verifier_params.clone().unwrap(),
            circuit_verifying_key: self.circuit_verifying_key.clone().unwrap(),
        }
    }

    fn load_general_params(&mut self) {
        if self.general_params.is_none() {
            self.general_params = self
                .read_or_gen(
                    format!("kzg_general_params_{}", self.degree),
                    |mut file| Ok(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?),
                    |mut file| {
                        let general_params =
                            ParamsKZG::<Bn256>::setup(self.degree, self.rng.clone());
                        general_params.write_custom(&mut file, SERDE_FORMAT)?;
                        Ok(general_params)
                    },
                )
                .ok();
        }
    }

    fn load_verifier_params(&mut self) {
        if self.verifier_params.is_none() {
            self.verifier_params = self
                .read_or_gen(
                    format!("kzg_verifier_params_{}", self.degree),
                    |mut file| Ok(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?),
                    |mut file| {
                        // TODO

                        let general_params = self.general_params.clone().unwrap();
                        let verifier_params = general_params.verifier_params().to_owned();

                        verifier_params.write_custom(&mut file, SERDE_FORMAT)?;
                        Ok(verifier_params)
                    },
                )
                .ok();
        }
    }

    fn load_circuit_verifying_key(&mut self) {
        if self.circuit_verifying_key.is_none() {
            self.circuit_verifying_key = self
                .read_or_gen(
                    format!(
                        "{}_verifying_key_{}",
                        derive_circuit_name(&self.circuit),
                        self.degree
                    ),
                    |file| {
                        Ok(VerifyingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                            file,
                            SERDE_FORMAT,
                            self.circuit.params(),
                        )?)
                    },
                    |mut file| {
                        let cvk = keygen_vk(&self.general_params.clone().unwrap(), &self.circuit)
                            .expect("keygen_vk should not fail");
                        cvk.write(&mut file, SERDE_FORMAT)?;
                        Ok(cvk)
                    },
                )
                .ok();
        }
    }

    fn load_circuit_proving_key(&mut self) {
        if self.circuit_proving_key.is_none() {
            self.circuit_proving_key = self
                .read_or_gen(
                    format!(
                        "{}_proving_key_{}",
                        derive_circuit_name(&self.circuit),
                        self.degree
                    ),
                    |file| {
                        Ok(ProvingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                            file,
                            SERDE_FORMAT,
                            self.circuit.params(),
                        )?)
                    },
                    |mut file| {
                        let cpk = keygen_pk(
                            &self.general_params.clone().unwrap(),
                            self.circuit_verifying_key.clone().unwrap(),
                            &self.circuit,
                        )
                        .expect("keygen_pk should not fail");
                        cpk.write(&mut file, SERDE_FORMAT)?;
                        Ok(cpk)
                    },
                )
                .ok();
        }
    }

    fn read_or_gen<T, F1, F2>(
        &self,
        file_name: String,
        mut read: F1,
        mut gen: F2,
    ) -> Result<T, Error>
    where
        F1: FnMut(&mut File) -> Result<T, Error>,
        F2: FnMut(&mut File) -> Result<T, Error>,
    {
        let path = self.srs_path.join(file_name);
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
}
