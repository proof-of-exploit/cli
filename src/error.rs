use anvil::eth::error::BlockchainError;
use ethers_core::utils::rlp;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    // error coming from anvil
    AnvilError(BlockchainError),
    // rlp decoding error
    RlpDecoderError(rlp::DecoderError),
    // error coming from bus-mapping crate
    BusMappingError(bus_mapping::Error),
    // some issue described in string
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
