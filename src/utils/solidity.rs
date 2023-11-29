use crate::error::Error;
use eth_types::Bytes;
use regex::Regex;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    str::FromStr,
};

use super::helpers::hashmap;

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
    #[serde(rename = "deployedBytecode")]
    deployed_bytecode: OutputBytecode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OutputBytecode {
    object: Bytes,
}

// TODO support multiple files
fn file_to_artifact(source_path_string: String) -> Result<Input, Error> {
    // TODO when there are multiple files, find the common initial path and strip it
    // For a single file, the stripped path is the file name itself
    let path = PathBuf::from(source_path_string.clone());
    let stripped_path = path
        .file_name()
        .expect("solidity input should be a file")
        .to_string_lossy()
        .to_string();

    Ok(Input {
        language: "Solidity".to_string(),
        sources: hashmap![stripped_path => InputSource {
            content: fs::read_to_string(source_path_string)?,
        }],
        settings: InputSettings {
            optimizer: InputSettingsOptimizer {
                enabled: true,
                runs: 200,
            },
            evm_version: EvmVersion::Paris,
            output_selection: hashmap!["*".into() => hashmap!["*".into() => vec!["evm.deployedBytecode.object".into()]]],
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
