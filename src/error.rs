use anvil::eth::error::BlockchainError;
use ethers_core::utils::rlp;
use halo2_proofs::plonk;
use partial_mpt;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    AnvilError(Box<BlockchainError>),
    RlpDecoderError(Box<rlp::DecoderError>),
    BusMappingError(Box<bus_mapping::Error>),
    Halo2Error(Box<plonk::Error>),
    StdError(Box<std::io::Error>),
    PartialMptError(Box<partial_mpt::Error>),
    SerdeJsonError(Box<serde_json::Error>),
    PinataError(Box<pinata_sdk::ApiError>),
    EthersProviderError(Box<ethers::providers::ProviderError>),
    InternalError(&'static str),
}

impl From<BlockchainError> for Error {
    fn from(err: BlockchainError) -> Self {
        Error::AnvilError(Box::new(err))
    }
}

impl From<bus_mapping::Error> for Error {
    fn from(err: bus_mapping::Error) -> Self {
        Error::BusMappingError(Box::new(err))
    }
}

impl From<rlp::DecoderError> for Error {
    fn from(err: rlp::DecoderError) -> Self {
        Error::RlpDecoderError(Box::new(err))
    }
}

impl From<plonk::Error> for Error {
    fn from(err: plonk::Error) -> Self {
        Error::Halo2Error(Box::new(err))
    }
}

impl From<partial_mpt::Error> for Error {
    fn from(err: partial_mpt::Error) -> Self {
        Error::PartialMptError(Box::new(err))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::StdError(Box::new(err))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerdeJsonError(Box::new(err))
    }
}

impl From<ethers::providers::ProviderError> for Error {
    fn from(err: ethers::providers::ProviderError) -> Self {
        Error::EthersProviderError(Box::new(err))
    }
}

impl From<pinata_sdk::ApiError> for Error {
    fn from(err: pinata_sdk::ApiError) -> Self {
        Error::PinataError(Box::new(err))
    }
}
