use super::{proof::Proof, srs::VerifierSRS};
use crate::error::Error;
use core::slice::SlicePattern;
use eth_types::{keccak256, H256};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::verify_proof,
    poly::kzg::{
        commitment::KZGCommitmentScheme, multiopen::VerifierSHPLONK, strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
};
use std::path::PathBuf;

// type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

pub struct RealVerifier {
    pub srs: VerifierSRS,
}

impl RealVerifier {
    pub async fn load_srs(srs_path: PathBuf, proof: &Proof) -> Self {
        Self {
            srs: VerifierSRS::load(
                srs_path,
                proof.degree,
                proof.circuit_params(),
                proof.fixed_circuit_params,
            )
            .await,
        }
    }

    pub async fn verify(&self, proof: &Proof) -> Result<(), Error> {
        let (_, proof_data, instances, public_data, _) = proof.unpack();
        let strategy = SingleStrategy::new(&self.srs.general_params);
        let instance_refs_intermediate = instances.iter().map(|v| &v[..]).collect::<Vec<&[Fr]>>();
        let mut verifier_transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_data[..]);

        println!("Verifying proof...");
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &self.srs.verifier_params,
            &self.srs.circuit_verifying_key,
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
