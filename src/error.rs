use anvil::eth::error::BlockchainError;
use ethers_core::utils::rlp;
use halo2_proofs::plonk;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    AnvilError(BlockchainError),
    RlpDecoderError(rlp::DecoderError),
    BusMappingError(bus_mapping::Error),
    Halo2Error(plonk::Error),
    StdError(std::io::Error),
    InternalError(&'static str),
}

impl From<BlockchainError> for Error {
    fn from(err: BlockchainError) -> Self {
        Error::AnvilError(err)
    }
}

impl From<bus_mapping::Error> for Error {
    fn from(err: bus_mapping::Error) -> Self {
        Error::BusMappingError(err)
    }
}

impl From<rlp::DecoderError> for Error {
    fn from(err: rlp::DecoderError) -> Self {
        Error::RlpDecoderError(err)
    }
}

impl From<plonk::Error> for Error {
    fn from(err: plonk::Error) -> Self {
        Error::Halo2Error(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::StdError(err)
    }
}
