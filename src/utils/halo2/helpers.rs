use eth_types::{Fr, H256};
use ethers::utils::hex;
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};
use std::{
    fmt::{self, Debug, Formatter},
    str::FromStr,
};
use zkevm_circuits::super_circuit::SuperCircuitParams;

pub fn derive_circuit_name<ConcreteCircuit>(circuit: ConcreteCircuit) -> String
where
    ConcreteCircuit: Debug,
{
    let mut circuit_format = format!("{:?}", circuit);
    if let Some(index) = circuit_format.find(' ') {
        circuit_format.truncate(index);
        circuit_format
    } else {
        panic!("no space found in '{}'", circuit_format);
    }
}

#[derive(Clone, Debug)]
pub struct FrWrapper(pub Fr);

impl Serialize for FrWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = self.0.to_bytes();
        bytes.reverse();
        serializer.serialize_str(hex::encode_prefixed(bytes).as_str())
    }
}

impl<'de> Deserialize<'de> for FrWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FrVisitor)
    }
}

pub struct FrVisitor;

impl<'de> Visitor<'de> for FrVisitor {
    type Value = FrWrapper;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("str")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = H256::from_str(v).unwrap();
        let mut bytes = bytes.as_fixed_bytes().to_owned();
        bytes.reverse();
        Ok(FrWrapper(Fr::from_bytes(&bytes).unwrap()))
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
