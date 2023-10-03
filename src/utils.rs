use core::fmt;
use eth_types::{Fr, H256};
use ethers::utils::hex;
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};
use std::{fmt::Debug, str::FromStr};

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

#[derive(Debug)]
pub struct FrWrapper(pub Fr);

impl Serialize for FrWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.to_bytes();
        serializer.serialize_str(hex::encode(bytes).as_str())
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

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("str")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(FrWrapper(
            Fr::from_bytes(H256::from_str(v).unwrap().as_fixed_bytes()).unwrap(),
        ))
    }
}
