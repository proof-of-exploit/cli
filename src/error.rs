use anvil::eth::error::BlockchainError;

#[derive(Debug)]
pub enum Error {
    // error coming from anvil
    AnvilError(BlockchainError),
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
