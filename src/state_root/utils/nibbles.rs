use std::fmt;

use ethers::{
    types::{Address, BigEndianHash, Bytes, H256, U256},
    utils::keccak256,
};

use crate::error::Error;

#[derive(Clone, PartialEq)]
pub struct Nibbles(Vec<u8>);

fn u8_to_u4_vec(u8_vec: Vec<u8>) -> Vec<u8> {
    let mut u4_vec = Vec::new();
    for byte in u8_vec.iter() {
        u4_vec.push(*byte >> 4);
        u4_vec.push(*byte & 0xF);
    }
    u4_vec
}

impl Nibbles {
    pub fn from_address(address: Address) -> Result<Nibbles, Error> {
        Ok(Self::from_raw_path(Bytes::from(
            H256::from(keccak256(address)).as_bytes().to_vec(),
        )))
    }

    pub fn from_uint(uint: U256) -> Result<Nibbles, Error> {
        Ok(Self::from_raw_path(Bytes::from(
            H256::from(keccak256(Bytes::from(
                H256::from_uint(&uint).as_bytes().to_vec(),
            )))
            .as_bytes()
            .to_vec(),
        )))
    }

    pub fn from_raw_path_str(str: &str) -> Self {
        Self::from_raw_path(str.parse::<Bytes>().unwrap())
    }

    pub fn from_encoded_path_str(str: &str) -> Result<Self, Error> {
        Self::from_encoded_path(str.parse::<Bytes>().unwrap())
    }

    pub fn from_raw_path(bytes: Bytes) -> Self {
        Self(u8_to_u4_vec(bytes.to_vec()))
    }

    pub fn from_u4_vec(nibbles: Vec<u8>) -> Result<Self, Error> {
        for nibble in nibbles.iter() {
            if *nibble > 0xF {
                return Err(Error::InternalError("cannot be more than 4 bits"));
            }
        }
        Ok(Self(nibbles))
    }

    pub fn from_encoded_path(bytes: Bytes) -> Result<Self, Error> {
        let (val, _) = Self::from_encoded_path_with_terminator(bytes)?;
        Ok(val)
    }
    pub fn from_encoded_path_with_terminator(bytes: Bytes) -> Result<(Self, bool), Error> {
        let mut u4_vec = u8_to_u4_vec(bytes.to_vec());

        let first = u4_vec[0];
        let second = u4_vec[1];
        if first == 1 || first == 3 {
            u4_vec.remove(0);
        } else if first == 0 || first == 2 {
            if second != 0 {
                return Err(Error::InternalError("bad second nibble"));
            }
            u4_vec.remove(1);
            u4_vec.remove(0);
        } else {
            return Err(Error::InternalError("bad first nibble"));
        }
        Ok((Self(u4_vec), first >= 2))
    }

    // adds zero to left if necessary
    pub fn to_raw_path(&self) -> Bytes {
        let mut temp = self.0.clone();
        if temp.len() % 2 == 1 {
            temp.insert(0, 0);
        }

        let mut bytes_vec = Vec::new();
        for (i, nibble) in temp.iter().enumerate() {
            if i % 2 == 0 {
                bytes_vec.push(*nibble << 4);
            } else {
                bytes_vec[i >> 1] += *nibble;
            }
        }

        Bytes::from(bytes_vec)
    }

    pub fn to_u4_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn encode_path(&self, terminator: bool) -> Bytes {
        let mut bytes_vec = self.to_raw_path().to_vec();
        if self.0.len() % 2 != 0 {
            // odd length
            bytes_vec[0] += 1 << 4;
        } else {
            bytes_vec.insert(0, 0);
        }
        if terminator {
            bytes_vec[0] += 2 << 4;
        }
        Bytes::from(bytes_vec)
    }

    pub fn slice(&self, from: usize) -> Result<Self, Error> {
        if self.0.len() < from {
            return Err(Error::InternalError("slice from is larger than len"));
        }
        let mut nibbles_vec = Vec::new();
        for i in from..self.0.len() {
            nibbles_vec.push(self.0[i]);
        }
        Ok(Self(nibbles_vec))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for Nibbles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Nibbles({})",
            self.0
                .iter()
                .map(|nibble| format!("{}", nibble))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Bytes, Nibbles};
    use ethers::types::U256;
    use ethers_core::utils::hex;

    #[test]
    pub fn test_raw_path_1() {
        let nibbles = Nibbles::from_raw_path("123456".parse().unwrap());
        assert_eq!(nibbles.0, vec![0x1, 0x2, 0x3, 0x4, 0x5, 0x6]);
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            hex::encode(vec![0x12, 0x34, 0x56])
        );
    }

    #[test]
    pub fn test_raw_path_2() {
        let nibbles = Nibbles::from_raw_path("000456".parse().unwrap());
        assert_eq!(nibbles.0, vec![0, 0, 0, 0x4, 0x5, 0x6]);
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            hex::encode(vec![0, 0x04, 0x56])
        );
    }

    #[test]
    pub fn test_raw_path_3_odd_length() {
        let nibbles = Nibbles(vec![0x4, 0x5, 0x6]);
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            hex::encode(vec![0x04, 0x56])
        );
    }

    #[test]
    pub fn test_encode_path_1() {
        let nibbles = Nibbles::from_raw_path(vec![0x12, 0x34, 0x56].into());
        assert_eq!(
            hex::encode(nibbles.encode_path(true)),
            hex::encode(vec![0x20, 0x12, 0x34, 0x56])
        );
    }

    #[test]
    pub fn test_encode_path_2() {
        let nibbles = Nibbles::from_raw_path(vec![0x12, 0x34, 0x56].into());
        assert_eq!(
            hex::encode(nibbles.encode_path(false)),
            hex::encode(vec![0x00, 0x12, 0x34, 0x56])
        );
    }

    #[test]
    pub fn test_encode_path_3() {
        let nibbles = Nibbles::from_u4_vec(vec![0x1, 0x2, 0x3]).unwrap();
        assert_eq!(
            hex::encode(nibbles.encode_path(true)),
            hex::encode(vec![0x31, 0x23])
        );
    }

    #[test]
    pub fn test_encode_path_4() {
        let nibbles = Nibbles::from_u4_vec(vec![0x1, 0x2, 0x3]).unwrap();
        assert_eq!(
            hex::encode(nibbles.encode_path(false)),
            hex::encode(vec![0x11, 0x23])
        );
    }

    #[test]
    pub fn test_decode_path_1() {
        let (nibbles, terminator) =
            Nibbles::from_encoded_path_with_terminator(vec![0x20, 0x12, 0x34, 0x56].into())
                .unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            hex::encode(vec![0x12, 0x34, 0x56])
        );
        assert_eq!(terminator, true);
    }

    #[test]
    pub fn test_decode_path_2() {
        let (nibbles, terminator) =
            Nibbles::from_encoded_path_with_terminator(vec![0x00, 0x12, 0x34, 0x56].into())
                .unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            hex::encode(Bytes::from(vec![0x12, 0x34, 0x56]))
        );
        assert_eq!(terminator, false);
    }

    #[test]
    pub fn test_decode_path_3() {
        let (nibbles, terminator) =
            Nibbles::from_encoded_path_with_terminator(vec![0x12, 0x34, 0x56].into()).unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            hex::encode(Bytes::from(vec![0x02, 0x34, 0x56]))
        );
        assert_eq!(nibbles.to_u4_vec(), vec![2, 3, 4, 5, 6]);
        assert_eq!(terminator, false);
    }

    #[test]
    pub fn test_decode_path_4() {
        let (nibbles, terminator) =
            Nibbles::from_encoded_path_with_terminator(vec![0x32, 0x34, 0x56].into()).unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            hex::encode(Bytes::from(vec![0x02, 0x34, 0x56]))
        );
        assert_eq!(nibbles.to_u4_vec(), vec![2, 3, 4, 5, 6]);
        assert_eq!(terminator, true);
    }

    #[test]
    pub fn test_decode_bad_path_1() {
        assert!(Nibbles::from_encoded_path(vec![0x22, 0x34, 0x56].into()).is_err());
        assert!(Nibbles::from_encoded_path(vec![0x42, 0x34, 0x56].into()).is_err());
        assert!(Nibbles::from_encoded_path(vec![0x52, 0x34, 0x56].into()).is_err());
    }

    #[test]
    pub fn test_slice_1() {
        let nibbles = Nibbles::from_raw_path("123456".parse().unwrap());
        assert_eq!(
            hex::encode(nibbles.slice(1).unwrap().to_raw_path()),
            hex::encode(vec![0x02, 0x34, 0x56])
        );
        assert_eq!(
            hex::encode(nibbles.slice(1).unwrap().encode_path(true)),
            hex::encode(vec![0x32, 0x34, 0x56])
        );
        assert_eq!(
            hex::encode(nibbles.slice(1).unwrap().encode_path(false)),
            hex::encode(vec![0x12, 0x34, 0x56])
        );
    }

    #[test]
    pub fn test_slice_2() {
        let nibbles = Nibbles::from_raw_path("123456".parse().unwrap());
        assert_eq!(
            hex::encode(nibbles.slice(2).unwrap().to_raw_path()),
            hex::encode(vec![0x34, 0x56])
        );
        assert_eq!(
            hex::encode(nibbles.slice(2).unwrap().encode_path(true)),
            hex::encode(vec![0x20, 0x34, 0x56])
        );
        assert_eq!(
            hex::encode(nibbles.slice(2).unwrap().encode_path(false)),
            hex::encode(vec![0x00, 0x34, 0x56])
        );
    }

    #[test]
    pub fn test_from_address_1() {
        let nibbles = Nibbles::from_address(
            "0x0000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            "5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"
        );
    }

    #[test]
    pub fn test_from_address_2() {
        let nibbles = Nibbles::from_address(
            "0xB85e2cCa665D14A2C221F6975042c8d94D3847F8"
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            "42dbef1b0a69a4c3d7a0551f30a6e7afb9c3a123c7d8c646df72249db3ea19be"
        );
    }

    #[test]
    pub fn test_from_uint_1() {
        let nibbles = Nibbles::from_uint(U256::from(0)).unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
        );
    }

    #[test]
    pub fn test_from_uint_2() {
        let nibbles = Nibbles::from_uint(U256::from(2)).unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            "405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"
        );
    }
}
