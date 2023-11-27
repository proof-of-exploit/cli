#![allow(clippy::derive_ord_xor_partial_ord)]
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

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

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

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
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

pub mod solc {
    use eth_types::Bytes;
    use semver::Version;
    use serde::{Deserialize, Serialize};

    use crate::error::Error;
    use std::{
        collections::HashMap,
        fs,
        io::Write,
        path::Path,
        process::{Command, Stdio},
    };

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct Input {
        language: String,
        sources: HashMap<String, InputSource>,
        settings: InputSettings,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct InputSettings {
        optimizer: InputSettingsOptimizer,
        #[serde(rename = "evmVersion")]
        evm_version: EvmVersion,
        #[serde(rename = "outputSelection")]
        output_selection: HashMap<String, HashMap<String, Vec<String>>>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct InputSettingsOptimizer {
        enabled: bool,
        runs: usize,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct InputSource {
        content: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum EvmVersion {
        Homestead,
        TangerineWhistle,
        SpuriousDragon,
        Byzantium,
        Constantinople,
        Petersburg,
        Istanbul,
        Berlin,
        London,
        Paris,
        Shanghai,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Output {
        contracts: HashMap<String, HashMap<String, OutputContract>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct OutputContract {
        evm: OutputContractEvm,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct OutputContractEvm {
        bytecode: OutputBytecode,
        #[serde(rename = "deployedBytecode")]
        deployed_bytecode: OutputBytecode,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct OutputBytecode {
        object: Bytes,
    }

    fn file_to_artifact(source_path_string: String) -> Result<Input, Error> {
        Ok(Input {
            language: "Solidity".to_string(),
            sources: hashmap![source_path_string.clone() => InputSource {
                content: fs::read_to_string(source_path_string)?,
            }],
            settings: InputSettings {
                optimizer: InputSettingsOptimizer {
                    enabled: true,
                    runs: 200,
                },
                evm_version: EvmVersion::Paris,
                output_selection: hashmap![ "*".into() => hashmap!["*".into() => vec!["evm.bytecode.object".into(), "evm.deployedBytecode.object".into()]]],
            },
        })
    }

    fn compile_artifact(input: &Input) -> Result<Output, Error> {
        let mut solc = Command::new("solc")
            .args(["--standard-json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = solc.stdin.take() {
            let input = serde_json::to_string(&input)?;
            stdin.write_all(input.as_bytes())?;
        }

        let output = solc.wait_with_output()?;
        let output: Output = serde_json::from_str(std::str::from_utf8(&output.stdout).unwrap())?;
        Ok(output)
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Artifact {
        solc_version: Version,
        input: Input,
        output: Output,
    }

    impl Artifact {
        pub fn from_source(source_path_string: String) -> Self {
            let solc_version = svm_lib::current_version().unwrap().unwrap();
            let input = file_to_artifact(source_path_string).unwrap();
            let output = compile_artifact(&input).unwrap();
            Artifact {
                solc_version,
                input,
                output,
            }
        }

        pub async fn verify_compilation(&self) -> Result<(), Error> {
            let user_version = svm_lib::current_version().unwrap().unwrap();
            if user_version != self.solc_version {
                let installed_versions = svm_lib::installed_versions().unwrap();
                if !installed_versions.contains(&self.solc_version) {
                    println!("Installing solc version {}...", self.solc_version);
                    svm_lib::install(&self.solc_version).await.unwrap();
                }
                // switch solc to proof's solc version
                svm_lib::use_version(&self.solc_version).unwrap();
            }
            let fresh_compilation_output = compile_artifact(&self.input)?;
            if user_version != self.solc_version {
                // switch solc to user's original solc version
                svm_lib::use_version(&user_version).unwrap();
            }
            if fresh_compilation_output != self.output {
                return Err(Error::InternalError("compilation not matching"));
            }
            Ok(())
        }

        pub fn get_creation_bytecode(&self, search_contract_name: String) -> Result<Bytes, Error> {
            for (_, contracts) in self.output.contracts.iter() {
                for (contract_name, contract) in contracts.iter() {
                    if &search_contract_name == contract_name {
                        return Ok(contract.evm.bytecode.object.clone());
                    }
                }
            }
            Err(Error::InternalError("could not find contract"))
        }

        pub fn get_deployed_bytecode(&self, search_contract_name: String) -> Result<Bytes, Error> {
            for (_, contracts) in self.output.contracts.iter() {
                for (contract_name, contract) in contracts.iter() {
                    if &search_contract_name == contract_name {
                        return Ok(contract.evm.deployed_bytecode.object.clone());
                    }
                }
            }
            Err(Error::InternalError("could not find contract"))
        }

        pub fn unpack(&self, unpack_dir: String) {
            for (path, source) in self.input.sources.iter() {
                let prefix = Path::new(&unpack_dir);
                let path = Path::new(path);
                let path = prefix.join(path);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                let mut file = fs::File::create(path).unwrap();
                file.write_all(source.content.as_bytes()).unwrap();
            }
        }
    }
}

pub mod ipfs {
    use crate::{error::Error, real_prover::Proof};
    use pinata_sdk::{PinByJson, PinataApi};
    use reqwest;

    pub async fn publish(proof: &Proof) -> Result<String, Error> {
        let api = PinataApi::new(
            // temp api key only allows pinning json, TODO allow passing own api key
            "81ff4f65264d2a866926",
            "0f20f80d89da0d99071b59be83a88797f9d6c803ebd966ca3e401fec5a081030",
        )
        .unwrap();

        let pinned_object = api.pin_json(PinByJson::new(proof)).await?;
        Ok(pinned_object.ipfs_hash)
    }

    pub async fn get(hash: String) -> Result<Proof, Error> {
        let gateway = "https://gateway.pinata.cloud/ipfs/";

        let client = reqwest::Client::new();
        let res = client
            .get(gateway.to_owned() + hash.as_str())
            .send()
            .await
            .unwrap();

        let str = res.text().await.unwrap();
        Ok(serde_json::from_str(str.as_str())?)
    }
}

pub mod geth {
    use crate::anvil::conversion::ConversionReverse;
    use crate::error::Error;
    use anvil_core::eth::transaction::EthTransactionRequest;
    use bus_mapping::{POX_CHALLENGE_ADDRESS, POX_EXPLOIT_ADDRESS};
    use eth_types::{Bytes, GethExecTrace, U256};
    use ethers::providers::{Http, Provider};
    use ethers::utils::hex;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::{collections::HashMap, str::FromStr};

    #[derive(Clone)]
    pub struct GethClient {
        provider: Provider<Http>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    pub struct GethDebugTracingOptions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disable_storage: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disable_stack: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enable_memory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enable_return_data: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state_overrides: Option<HashMap<String, StateOverrides>>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct StateOverrides {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        balance: Option<String>,
    }

    impl GethClient {
        pub fn new(url: String) -> Self {
            GethClient {
                provider: Provider::<Http>::try_from(&url).unwrap(),
            }
        }

        pub async fn simulate_exploit(
            &self,
            _block_number: usize,
            challenge_bytecode: Bytes,
            exploit_bytecode: Bytes,
            exploit_balance: U256,
        ) -> Result<GethExecTrace, Error> {
            let base_tx = EthTransactionRequest {
                from: None,
                to: Some(POX_CHALLENGE_ADDRESS),
                gas_price: Some(U256::zero()),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                gas: Some(U256::from(1_000_000)),
                value: Some(U256::zero()),
                data: Some(Bytes::from_str("0xb0d691fe").unwrap().to_anvil_type()),
                nonce: None,
                chain_id: None,
                access_list: None,
                transaction_type: None,
            };

            Ok(self
                .provider
                .request::<_, GethExecTrace>(
                    "debug_traceCall",
                    [
                        serde_json::to_value(base_tx).unwrap(),
                        Value::String("latest".to_string()), // node not support archive trace - Value::String(format!("0x{block_number:x}")),
                        serde_json::to_value(GethDebugTracingOptions {
                            enable_memory: None,
                            disable_stack: None,
                            disable_storage: None,
                            enable_return_data: None,
                            timeout: None,
                            state_overrides: Some(hashmap![
                                format!("{POX_CHALLENGE_ADDRESS:?}") => StateOverrides {
                                    code: Some(hex::encode_prefixed(challenge_bytecode)),
                                    balance: None,
                                },
                                format!("{POX_EXPLOIT_ADDRESS:?}") => StateOverrides {
                                    code: Some(hex::encode_prefixed(exploit_bytecode)),
                                    balance: Some(format!("0x{exploit_balance:x}")),
                                }
                            ]),
                        })
                        .unwrap(),
                    ],
                )
                .await?)
        }
    }
}
