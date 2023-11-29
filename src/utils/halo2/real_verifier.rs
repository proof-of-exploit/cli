use super::proof::Proof;
use crate::error::Error;
use core::slice::SlicePattern;
use eth_types::{keccak256, H256};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{verify_proof, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::VerifierSHPLONK,
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
    SerdeFormat,
};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use zkevm_circuits::super_circuit::SuperCircuit;

// use crate::{derive_circuit_name, derive_k, CircuitExt};

// type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

const SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

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

    pub async fn verify(&self, proof: &Proof) -> Result<(), Error> {
        let (_, proof_data, instances, public_data, _, _) = proof.unpack();
        let strategy = SingleStrategy::new(&self.general_params);
        let instance_refs_intermediate = instances.iter().map(|v| &v[..]).collect::<Vec<&[Fr]>>();
        let mut verifier_transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_data[..]);

        // verify zk proof
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
        println!("- ZK proof verifies");

        // verify public data to be image of instance
        let digest = public_data.get_rpi_digest_word::<Fr>();
        if !(instances[0][0] == digest.lo() && instances[0][1] == digest.hi()) {
            return Err(Error::InternalError("digest mismatch"));
        }
        // println!("- Public inputs digest matches with instance");

        if let Some(challenge_artifact) = proof.challenge_artifact.clone() {
            // verify compilation
            challenge_artifact.verify_compilation().await?;
            // println!("- Challenge contract compiles to POX codehash in public inputs");

            // ensure that challenge codehash is same as the codehash in public inputs
            let bytecode = challenge_artifact
                .get_deployed_bytecode("Challenge".to_string())
                .unwrap();
            let compiled_codehash = H256::from(keccak256(bytecode.as_slice()));
            if compiled_codehash != proof.public_data.pox_challenge_codehash {
                return Err(Error::InternalError(
                    "compiled codehash does not match public inputs",
                ));
            }
            // println!("- Compiled codehash verified with public inputs");
            println!("- Challenge codehash in public inputs");
        } else {
            println!("Warning: Challenge artifact is not present in the proof");
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
