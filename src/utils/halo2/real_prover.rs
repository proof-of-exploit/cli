use super::{
    proof::Proof,
    real_verifier::RealVerifier,
    srs::{VerifierSRS, SRS},
};
use crate::error::Error;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, Circuit},
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::path::PathBuf;
use zkevm_circuits::{
    instance::public_data_convert, super_circuit::SuperCircuit, util::SubCircuit,
};

#[derive(Clone)]
pub struct RealProver {
    circuit: SuperCircuit<Fr>,
    degree: u32,
    srs: SRS,
}

impl RealProver {
    pub fn from(circuit: SuperCircuit<Fr>, degree: u32, srs_path: PathBuf) -> Self {
        let srs = SRS::load(&circuit, degree, srs_path);
        Self {
            circuit,
            degree,
            srs,
        }
    }

    pub fn prove(&mut self) -> Result<Proof, Error> {
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
            &self.srs.general_params,
            &self.srs.circuit_proving_key,
            &[self.circuit.clone()],
            &[&instances_refs_intermediate],
            ChaChaRng::seed_from_u64(2),
            &mut transcript,
        )
        .unwrap();

        let proof = transcript.finalize();
        Ok(Proof::from(
            self.degree,
            proof,
            instances,
            self.circuit.params(),
            self.circuit.circuits_params,
            public_data,
            None,
        ))
    }

    pub fn verifier(&mut self) -> RealVerifier {
        RealVerifier {
            srs: VerifierSRS {
                general_params: self.srs.general_params.clone(),
                verifier_params: self.srs.verifier_params.clone(),
                circuit_verifying_key: self.srs.circuit_verifying_key.clone(),
            },
        }
    }
}
