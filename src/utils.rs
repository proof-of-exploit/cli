use core::fmt;
use eth_types::{Bytes, Fr, H256};
use ethers::utils::hex;
use regex::Regex;
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};
use serde_json::Value;
use std::{fmt::Debug, process, str::FromStr};

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

pub fn compile_huff(source_path_string: String) -> Bytes {
    let mut cmd = process::Command::new("huffc");
    cmd.arg(source_path_string);
    cmd.arg("-r");
    let output = cmd.output().unwrap();
    if !output.stderr.is_empty() {
        println!(
            "huffc error: {:?}",
            String::from_utf8(output.stderr).unwrap()
        );
        process::exit(1);
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    Bytes::from_str(stdout.as_str()).unwrap()
}

pub fn compile_solidity(source_path_string: String, match_contract_name: &str) -> Bytes {
    let mut cmd = process::Command::new("solc");
    cmd.arg(source_path_string);
    cmd.arg("--combined-json");
    cmd.arg("bin-runtime");
    let output = cmd.output().unwrap();
    let output = if !output.stdout.is_empty() {
        String::from_utf8(output.stdout).unwrap()
    } else {
        String::from_utf8(output.stderr).unwrap()
    };
    let solc_json_output: Value = serde_json::from_str(output.as_str()).unwrap_or_else(|_| {
        println!("solc error: {output}");
        process::exit(1);
    });
    let compiled_bytecode = 'cb: {
        let regx = Regex::new(r"(?m)^([^:]+):(.+)$").unwrap();
        for (key, val) in solc_json_output
            .as_object()
            .unwrap()
            .get("contracts")
            .unwrap()
            .as_object()
            .unwrap()
        {
            let contract_name = regx
                .captures(key.as_str())
                .unwrap()
                .get(2)
                .unwrap()
                .as_str();
            if contract_name == match_contract_name {
                break 'cb val
                    .as_object()
                    .unwrap()
                    .get("bin-runtime")
                    .unwrap()
                    .as_str()
                    .unwrap();
            }
        }
        println!("Could not find a Challenge solidity contract");
        process::exit(1);
    };
    Bytes::from_str(compiled_bytecode).unwrap()
}
