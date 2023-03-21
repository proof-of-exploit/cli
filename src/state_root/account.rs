use super::trie::Trie;
use crate::error::Error;
use ethers::{
    types::{Bytes, H256, U256},
    utils::rlp::{Rlp, RlpStream},
};

#[derive(Debug, Clone)]
pub struct AccountTrie(Trie);

#[derive(Debug, Clone)]
pub struct AccountData {
    nonce: U256,
    balance: U256,
    code_hash: H256,
    storage_root: H256,
}

impl AccountData {
    pub fn from_raw_rlp(raw: Bytes) -> Result<Self, Error> {
        let rlp = Rlp::new(&raw);
        Ok(Self {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            code_hash: rlp.val_at(2)?,
            storage_root: rlp.val_at(3)?,
        })
    }

    pub fn to_raw_rlp(&self) -> Result<Bytes, Error> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(4);
        rlp_stream.append(&self.nonce);
        rlp_stream.append(&self.balance);
        rlp_stream.append(&self.code_hash);
        rlp_stream.append(&self.storage_root);
        Ok(Bytes::from(rlp_stream.out().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountData, U256};
    use ethers::utils::parse_ether;
    use ethers_core::utils::hex;

    #[test]
    pub fn test_account_data_raw_rlp_1() {
        let raw_rlp = "f84c8088016345785d8a0000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        let account = AccountData::from_raw_rlp(raw_rlp.parse().unwrap()).unwrap();

        // decode
        assert_eq!(account.nonce, U256::from(0));
        assert_eq!(account.balance, parse_ether("0.1").unwrap());
        assert_eq!(
            hex::encode(account.code_hash),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        assert_eq!(
            hex::encode(account.storage_root),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );

        // encode
        assert_eq!(hex::encode(account.to_raw_rlp().unwrap()), raw_rlp);

        println!("{:?}", account);
    }
}
