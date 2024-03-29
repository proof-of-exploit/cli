use super::{super::solidity::Artifact, helpers::FrWrapper, helpers::SuperCircuitParamsWrapper};
use crate::error::Error;
use bus_mapping::circuit_input_builder::FixedCParams;
use ethers::types::Bytes;
use halo2_proofs::halo2curves::bn256::Fr;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    str::FromStr,
};
use zkevm_circuits::{instance::PublicData, super_circuit::SuperCircuitParams};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub version: Version,
    pub degree: u32,
    pub data: Bytes,
    instances: Vec<Vec<FrWrapper>>,
    circuit_params: SuperCircuitParamsWrapper,
    pub fixed_circuit_params: FixedCParams,
    pub public_data: PublicData,
    pub challenge_artifact: Option<Artifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl Proof {
    #[allow(clippy::too_many_arguments)]
    pub fn from(
        degree: u32,
        proof: Vec<u8>,
        instances: Vec<Vec<Fr>>,
        circuit_params: SuperCircuitParams<Fr>,
        fixed_circuit_params: FixedCParams,
        public_data: PublicData,
        challenge_artifact: Option<Artifact>,
        summary: Option<String>,
    ) -> Self {
        Self {
            version: Version::from_str(env!("CARGO_PKG_VERSION")).unwrap(),
            degree,
            data: Bytes::from(proof),
            instances: instances
                .iter()
                .map(|column| column.iter().map(|element| FrWrapper(*element)).collect())
                .collect(),
            circuit_params: SuperCircuitParamsWrapper::wrap(circuit_params),
            fixed_circuit_params,
            public_data,
            challenge_artifact,
            summary,
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

    pub fn unpack(&self) -> (u32, Bytes, Vec<Vec<Fr>>, PublicData, SuperCircuitParams<Fr>) {
        let instances = self.instances();
        let circuit_params = self.circuit_params();
        (
            self.degree,
            self.data.clone(),
            instances,
            self.public_data.clone(),
            circuit_params,
        )
    }

    pub fn write_to_file(&self, path: &PathBuf) -> Result<(), Error> {
        // TODO ensure that parent dir exists
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
