use eth_types::keccak256;
use ethers::types::Bytes;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaChaRng};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use zkevm_circuits::{
    instance::{public_data_convert, PublicData},
    super_circuit::{SuperCircuit, SuperCircuitParams},
    util::SubCircuit,
};

use crate::{
    error::Error,
    utils::{derive_circuit_name, FrWrapper, Version},
};

// use crate::{derive_circuit_name, derive_k, CircuitExt};

// type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

const SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

#[derive(Clone)]
pub struct RealProver {
    circuit: SuperCircuit<Fr>,
    degree: u32,
    dir_path: PathBuf,
    rng: ChaCha20Rng,
    pub general_params: Option<ParamsKZG<Bn256>>,
    pub verifier_params: Option<ParamsKZG<Bn256>>,
    pub circuit_proving_key: Option<ProvingKey<G1Affine>>,
    pub circuit_verifying_key: Option<VerifyingKey<G1Affine>>,
}

impl RealProver {
    pub fn from(circuit: SuperCircuit<Fr>, k: u32, dir_path: Option<PathBuf>) -> Self {
        Self {
            circuit,
            degree: k,
            dir_path: dir_path.unwrap_or(PathBuf::from_str("./out").unwrap()),
            rng: ChaChaRng::seed_from_u64(2),
            general_params: None,
            verifier_params: None,
            circuit_proving_key: None,
            circuit_verifying_key: None,
        }
    }

    pub fn load(&mut self) -> Result<&Self, Error> {
        self.set_general_params(None)?;
        self.set_verifier_params(None)?;
        self.set_circuit_params(None, None)?;
        Ok(self)
    }

    pub fn run(&mut self, write_to_file: bool) -> Result<Proof, Error> {
        self.load()?;
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

        let circuit_name = derive_circuit_name(&self.circuit);
        let proof = transcript.finalize();
        if write_to_file {
            let proof_path = self.dir_path.join(Path::new(&format!(
                "{}_proof", // TODO add timestamp
                derive_circuit_name(&self.circuit)
            )));

            let mut file = File::create(proof_path)?;
            file.write_all(proof.as_slice())?;
        }
        Ok(Proof::from(
            self.degree,
            proof,
            instances,
            circuit_name,
            self.circuit.params(),
            public_data,
        ))
    }

    pub fn verifier(&self) -> RealVerifier {
        RealVerifier {
            general_params: self
                .general_params
                .clone()
                .ok_or("params not available, please execute prover.load() first")
                .unwrap(),
            verifier_params: self.verifier_params.clone().unwrap(),
            circuit_verifying_key: self.circuit_verifying_key.clone().unwrap(),
        }
    }

    pub fn degree(mut self, k: u32) -> Self {
        self.degree = k;
        self
    }

    fn set_general_params(
        &mut self,
        params_override: Option<ParamsKZG<Bn256>>,
    ) -> Result<(), Error> {
        if params_override.is_some() {
            self.general_params = params_override;
            return Ok(());
        }

        if self.general_params.is_some() {
            return Ok(());
        }

        self.ensure_dir_exists();

        let path = self
            .dir_path
            .join(Path::new(&format!("kzg_general_params_{}", self.degree)));
        match File::open(path.clone()) {
            Ok(mut file) => {
                self.general_params =
                    Some(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?);
            }
            Err(_) => {
                let general_params = ParamsKZG::<Bn256>::setup(self.degree, self.rng.clone());
                let mut file = File::create(path)?;
                general_params.write_custom(&mut file, SERDE_FORMAT)?;
                self.general_params = Some(general_params);
            }
        };
        Ok(())
    }

    fn set_verifier_params(
        &mut self,
        params_override: Option<ParamsKZG<Bn256>>,
    ) -> Result<(), Error> {
        if params_override.is_some() {
            self.verifier_params = params_override;
            return Ok(());
        }

        if self.verifier_params.is_some() {
            return Ok(());
        }

        self.ensure_dir_exists();

        let path = self
            .dir_path
            .join(Path::new(&format!("kzg_verifier_params_{}", self.degree)));
        match File::open(path.clone()) {
            Ok(mut file) => {
                self.verifier_params =
                    Some(ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT)?);
            }
            Err(_) => {
                let general_params = self.general_params.clone().unwrap();
                let verifier_params = general_params.verifier_params().to_owned();
                let mut file = File::create(path)?;
                verifier_params.write_custom(&mut file, SERDE_FORMAT)?;
                self.verifier_params = Some(verifier_params);
            }
        };
        Ok(())
    }

    pub fn set_circuit_params(
        &mut self,
        circuit_proving_key_override: Option<ProvingKey<G1Affine>>,
        circuit_verifying_key_override: Option<VerifyingKey<G1Affine>>,
    ) -> Result<(), Error> {
        if self.circuit_proving_key.is_some() && self.circuit_verifying_key.is_some() {
            return Ok(());
        }

        if circuit_proving_key_override.is_some() && circuit_verifying_key_override.is_some() {
            self.circuit_proving_key = circuit_proving_key_override;
            self.circuit_verifying_key = circuit_verifying_key_override;
            return Ok(());
        }

        let verifying_key_path = self.dir_path.join(Path::new(&format!(
            "{}_verifying_key_{}",
            derive_circuit_name(&self.circuit),
            self.degree
        )));

        if verifying_key_path.exists() && let Ok(mut file) = File::open(verifying_key_path.clone()) {
            self.circuit_verifying_key = Some(
                VerifyingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                    &mut file,
                    SERDE_FORMAT,
                    self.circuit.params(),
                ).unwrap(),
            );
        } else {
            let vk = keygen_vk(self.general_params.as_mut().unwrap(), &self.circuit).expect("keygen_vk should not fail");
            let mut file = File::create(verifying_key_path)?;
            vk.write(&mut file, SERDE_FORMAT)?;
            println!(
                "circuit_verifying_key hash {:?}",
                keccak256(format!("{:?}", vk).as_bytes())
            );
            self.circuit_verifying_key = Some(vk);
        }

        self.ensure_dir_exists();

        let proving_key_path = self.dir_path.join(Path::new(&format!(
            "{}_proving_key_{}",
            derive_circuit_name(&self.circuit),
            self.degree
        )));
        // TODO make PK gen code similar to VK
        match File::open(proving_key_path.clone()) {
            Ok(mut file) => {
                self.circuit_proving_key = Some(
                    ProvingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
                        &mut file,
                        SERDE_FORMAT,
                        self.circuit.params(),
                    )
                    .unwrap(),
                );
            }
            Err(_) => {
                let pk = keygen_pk(
                    self.general_params.as_mut().unwrap(),
                    self.circuit_verifying_key.clone().unwrap(),
                    &self.circuit,
                )
                .expect("keygen_pk should not fail");
                println!(
                    "circuit_proving_key hash {:?}",
                    keccak256(format!("{:?}", pk).as_bytes())
                );
                // Skip writing proving key to file because it takes lot of time
                // TODO put this under a flag
                let mut file = File::create(proving_key_path)?;
                pk.write(&mut file, SERDE_FORMAT)?;
                self.circuit_proving_key = Some(pk);
            }
        };
        Ok(())
    }

    fn ensure_dir_exists(&self) {
        create_dir_all(self.dir_path.clone()).unwrap();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuperCircuitParamsWrapper {
    pub mock_randomness: FrWrapper,
}

impl SuperCircuitParamsWrapper {
    pub fn wrap(value: SuperCircuitParams<Fr>) -> Self {
        Self {
            mock_randomness: FrWrapper(value.mock_randomness),
        }
    }
    pub fn unwrap(self) -> SuperCircuitParams<Fr> {
        SuperCircuitParams {
            mock_randomness: self.mock_randomness.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    #[serde(default)]
    pub version: Version,
    pub degree: u32,
    pub data: Bytes,
    instances: Vec<Vec<FrWrapper>>,
    pub circuit_name: String,
    circuit_params: SuperCircuitParamsWrapper, // TODO generalize later
    public_data: PublicData,
}

impl Proof {
    pub fn from(
        degree: u32,
        proof: Vec<u8>,
        instances: Vec<Vec<Fr>>,
        circuit_name: String,
        circuit_params: SuperCircuitParams<Fr>,
        public_data: PublicData,
    ) -> Self {
        Self {
            version: Version::from(env!("CARGO_PKG_VERSION").to_string()),
            degree,
            data: Bytes::from(proof),
            instances: instances
                .iter()
                .map(|column| column.iter().map(|element| FrWrapper(*element)).collect())
                .collect(),
            circuit_params: SuperCircuitParamsWrapper::wrap(circuit_params),
            circuit_name,
            public_data,
        }
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        self.instances
            .iter()
            .map(|column| column.iter().map(|element| element.0).collect())
            .collect()
    }

    pub fn num_instances(&self) -> Vec<usize> {
        self.instances.iter().map(|column| column.len()).collect()
    }

    pub fn circuit_params(&self) -> SuperCircuitParams<Fr> {
        self.circuit_params.clone().unwrap()
    }

    pub fn unpack(
        &self,
    ) -> (
        u32,
        Bytes,
        Vec<Vec<Fr>>,
        PublicData,
        String,
        SuperCircuitParams<Fr>,
    ) {
        let instances = self.instances();
        let circuit_params = self.circuit_params();
        (
            self.degree,
            self.data.clone(),
            instances,
            self.public_data.clone(),
            self.circuit_name.clone(),
            circuit_params,
        )
    }

    pub fn write_to_file(&self, path: &PathBuf) -> Result<(), Error> {
        let mut file = File::create(path)?;
        file.write_all(serde_json::to_string(self)?.as_bytes())
            .unwrap();
        Ok(())
    }

    pub fn read_from_file(path: &PathBuf) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(serde_json::from_str(&contents)?)
    }
}

pub struct RealVerifier {
    pub general_params: ParamsKZG<Bn256>,
    pub verifier_params: ParamsKZG<Bn256>,
    pub circuit_verifying_key: VerifyingKey<G1Affine>,
}

impl RealVerifier {
    pub fn load_srs(srs_path: PathBuf, proof: &Proof) -> Self {
        let path = srs_path.join(Path::new(&format!("kzg_general_params_{}", proof.degree)));
        let mut file = File::open(path).unwrap();
        let general_params = ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT).unwrap();

        let path = srs_path.join(Path::new(&format!("kzg_verifier_params_{}", proof.degree)));
        let mut file = File::open(path).unwrap();
        let verifier_params = ParamsKZG::<Bn256>::read_custom(&mut file, SERDE_FORMAT).unwrap();

        let verifying_key_path = srs_path.join(Path::new(&format!(
            "{}_verifying_key_{}",
            proof.circuit_name, proof.degree
        )));
        let mut file = File::open(verifying_key_path).unwrap();
        let circuit_verifying_key = VerifyingKey::<G1Affine>::read::<File, SuperCircuit<Fr>>(
            &mut file,
            SERDE_FORMAT,
            proof.circuit_params.clone().unwrap(),
        )
        .unwrap();

        Self {
            general_params,
            verifier_params,
            circuit_verifying_key,
        }
    }

    pub fn verify(&self, proof: &Proof) -> Result<(), Error> {
        let (_, proof_data, instances, public_data, _, _) = proof.unpack();
        let strategy = SingleStrategy::new(&self.general_params);
        let instance_refs_intermediate = instances.iter().map(|v| &v[..]).collect::<Vec<&[Fr]>>();
        let mut verifier_transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_data[..]);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &self.verifier_params,
            &self.circuit_verifying_key,
            strategy,
            &[&instance_refs_intermediate],
            &mut verifier_transcript,
        )?;

        let digest = public_data.get_rpi_digest_word::<Fr>();
        if !(instances[0][0] == digest.lo() && instances[0][1] == digest.hi()) {
            return Err(Error::InternalError("digest mismatch"));
        }

        Ok(())
    }

    // pub fn generate_yul(&self, write_to_file: bool) -> Result<String, Error> {
    //     let protocol = compile(
    //         &self.verifier_params,
    //         &self.circuit_verifying_key,
    //         Config::kzg().with_num_instance(self.num_instance.clone()),
    //     );
    //     let vk: KzgDecidingKey<Bn256> = (
    //         self.verifier_params.get_g()[0],
    //         self.verifier_params.g2(),
    //         self.verifier_params.s_g2(),
    //     )
    //         .into();

    //     let loader = EvmLoader::new::<Fq, Fr>();
    //     let protocol = protocol.loaded(&loader);
    //     let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    //     let instances = transcript.load_instances(self.num_instance.clone());
    //     let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    //     PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    //     let source = loader.solidity_code();
    //     if write_to_file {
    //         let proof_path = self
    //             .dir_path
    //             .join(Path::new(&format!("{}_verifier.yul", self.circuit_name)));

    //         let mut file = File::create(proof_path)?;
    //         file.write_all(source.as_bytes())?;
    //     }
    //     Ok(source)
    // }
}
