use super::{super::solidity::Artifact, helpers::FrWrapper, helpers::SuperCircuitParamsWrapper};
use crate::error::Error;
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
    pub circuit_name: String,
    circuit_params: SuperCircuitParamsWrapper,
    pub public_data: PublicData,
    pub challenge_artifact: Option<Artifact>,
}

impl Proof {
    pub fn from(
        degree: u32,
        proof: Vec<u8>,
        instances: Vec<Vec<Fr>>,
        circuit_name: String,
        circuit_params: SuperCircuitParams<Fr>,
        public_data: PublicData,
        challenge_artifact: Option<Artifact>,
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
            circuit_name,
            public_data,
            challenge_artifact,
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
