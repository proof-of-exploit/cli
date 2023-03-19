use crate::{error::Error, types::zkevm_types::Bytes};
pub struct Key(Bytes);

impl Key {
    pub fn from_bytes_without_prefix(raw: Bytes) -> Self {
        let mut vec = raw.to_vec();
        while vec[0] == 0 {
            vec.remove(0);
        }
        Key(Bytes::from(vec))
    }

    pub fn from_bytes_with_prefix(raw: Bytes) -> (Self, bool) {
        // Key(Bytes::from(raw))
        let mut vec = raw.to_vec();
        let first_nibble = vec[0] >> 4;
        if first_nibble % 2 != 0 {
            vec[0] = 0xF & vec[0]; // remove first nibble
        } else {
            vec.remove(0);
        }
        (Key(Bytes::from(vec)), first_nibble >= 2)
    }

    pub fn with_prefix(&self, terminator: bool) -> Bytes {
        let mut vec = self.0.to_vec();
        let first_nibble = vec[0] >> 4; // first nibble only if not zero
        if first_nibble == 0 {
            // odd length
            vec[0] += 1 << 4;
        } else {
            // even length
            vec.insert(0, 0);
        }
        if terminator {
            vec[0] += 2 << 4;
        }
        Bytes::from(vec)
    }

    pub fn without_prefix(&self) -> Bytes {
        self.0.clone()
    }

    pub fn nibble_len(&self) -> usize {
        let len = self.0.len();
        let first_nibble = self.without_prefix()[0] >> 4;
        if first_nibble == 0 {
            2 * len - 1
        } else {
            2 * len
        }
    }

    pub fn get_nibble(&self, index: usize) -> Result<u8, Error> {
        if index >= self.nibble_len() {
            return Err(Error::InternalError("Nibble index out of bounds"));
        }
        let val = self.without_prefix()[index >> 1];
        Ok(if index & 1 == 0 { val >> 4 } else { val & 0x0F })
    }

    pub fn without_prefix_skip_nibbles(&self, mut nibbles: usize) -> Result<Bytes, Error> {
        if nibbles > self.nibble_len() {
            return Err(Error::InternalError("Cannot skip more than nibbles"));
        }

        let mut vec = self.without_prefix().to_vec();
        if vec[0] & 0xF0 == 0 {
            // if 4 bits are zero, it's not considered as nibble so adjust that
            nibbles += 1;
        }

        let bytes_to_remove = nibbles >> 1;
        for _i in 0..bytes_to_remove {
            vec.remove(0);
        }
        if nibbles % 2 != 0 {
            vec[0] = 0xF & vec[0]; // remove first nibble
        }

        Ok(Bytes::from(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::Key;
    use crate::types::zkevm_types::Bytes;
    use ethers_core::utils::hex;

    #[test]
    pub fn test_add_prefix_1() {
        let key = Key::from_bytes_without_prefix(
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                .parse()
                .unwrap(),
        );
        let prefixed_key = key.with_prefix(true);
        assert_eq!(prefixed_key.len(), 33);
        assert_eq!(
            hex::encode(prefixed_key),
            "20290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563",
        );
    }

    #[test]
    pub fn test_add_prefix_2() {
        let key = Key::from_bytes_without_prefix(
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                .parse()
                .unwrap(),
        );
        let prefixed_key = key.with_prefix(false);
        assert_eq!(prefixed_key.len(), 33);
        assert_eq!(
            hex::encode(prefixed_key),
            "00290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563",
        );
    }

    #[test]
    pub fn test_add_prefix_3() {
        let key = Key::from_bytes_without_prefix(
            "036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
                .parse()
                .unwrap(),
        );
        let prefixed_key = key.with_prefix(true);
        assert_eq!(prefixed_key.len(), 32);
        assert_eq!(
            hex::encode(prefixed_key),
            "336b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0",
        );
    }

    #[test]
    pub fn test_add_prefix_4() {
        let key = Key::from_bytes_without_prefix(
            "036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
                .parse()
                .unwrap(),
        );
        let prefixed_key = key.with_prefix(false);
        assert_eq!(prefixed_key.len(), 32);
        assert_eq!(
            hex::encode(prefixed_key),
            "136b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0",
        );
    }

    #[test]
    pub fn test_remove_prefix_1() {
        let (key, terminator) = Key::from_bytes_with_prefix(
            "20290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                .parse()
                .unwrap(),
        );
        assert_eq!(key.without_prefix().len(), 32);
        assert_eq!(
            hex::encode(key.without_prefix()),
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563",
        );
        assert_eq!(terminator, true);
    }

    #[test]
    pub fn test_remove_prefix_2() {
        let (key, terminator) = Key::from_bytes_with_prefix(
            "00290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                .parse()
                .unwrap(),
        );
        assert_eq!(key.without_prefix().len(), 32);
        assert_eq!(
            hex::encode(key.without_prefix()),
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563",
        );
        assert_eq!(terminator, false);
    }

    #[test]
    pub fn test_remove_prefix_3() {
        let (key, terminator) = Key::from_bytes_with_prefix(
            "336b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
                .parse()
                .unwrap(),
        );
        assert_eq!(key.without_prefix().len(), 32);
        assert_eq!(
            hex::encode(key.without_prefix()),
            "036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0",
        );
        assert_eq!(terminator, true);
    }

    #[test]
    pub fn test_remove_prefix_4() {
        let (key, terminator) = Key::from_bytes_with_prefix(
            "136b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
                .parse()
                .unwrap(),
        );

        assert_eq!(key.without_prefix().len(), 32);
        assert_eq!(
            hex::encode(key.without_prefix()),
            "036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0",
        );
        assert_eq!(terminator, false);
    }

    #[test]
    pub fn test_nibble_len_1() {
        let key = Key::from_bytes_without_prefix(
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                .parse()
                .unwrap(),
        );

        assert_eq!(key.nibble_len(), 64);
    }

    #[test]
    pub fn test_nibble_len_2() {
        let key = Key::from_bytes_without_prefix("1234".parse().unwrap());

        assert_eq!(key.nibble_len(), 4);
    }

    #[test]
    pub fn test_nibble_len_3() {
        let key = Key::from_bytes_without_prefix("00001234".parse().unwrap());

        assert_eq!(key.nibble_len(), 4);
    }

    #[test]
    pub fn test_nibble_len_4() {
        let key = Key::from_bytes_without_prefix("0000123400".parse().unwrap());

        assert_eq!(key.nibble_len(), 6);
    }

    #[test]
    pub fn test_get_nibble_1() {
        let key = Key::from_bytes_without_prefix("0000123400".parse().unwrap());

        assert_eq!(key.get_nibble(0).unwrap(), 1);
        assert_eq!(key.get_nibble(1).unwrap(), 2);
        assert_eq!(key.get_nibble(2).unwrap(), 3);
        assert_eq!(key.get_nibble(3).unwrap(), 4);
        assert_eq!(key.get_nibble(4).unwrap(), 0);
        assert_eq!(key.get_nibble(5).unwrap(), 0);
        assert!(key.get_nibble(7).is_err());
    }

    #[test]
    pub fn test_ignore_starting_zeros_1() {
        let key = Key::from_bytes_without_prefix(Bytes::from(vec![0, 0, 0, 0, 0x12, 0x34, 0]));
        assert_eq!(key.without_prefix().len(), 3);
        assert_eq!(hex::encode(key.without_prefix()), "123400");
    }

    #[test]
    pub fn test_skip_nibbles_1() {
        let key = Key::from_bytes_without_prefix("0000123400".parse().unwrap());

        assert_eq!(
            key.without_prefix_skip_nibbles(0).unwrap(),
            "123400".parse::<Bytes>().unwrap()
        );
        assert_eq!(
            key.without_prefix_skip_nibbles(1).unwrap(),
            "023400".parse::<Bytes>().unwrap()
        );
        assert_eq!(
            key.without_prefix_skip_nibbles(2).unwrap(),
            "3400".parse::<Bytes>().unwrap()
        );
        assert_eq!(
            key.without_prefix_skip_nibbles(3).unwrap(),
            "0400".parse::<Bytes>().unwrap()
        );
        assert_eq!(
            key.without_prefix_skip_nibbles(4).unwrap(),
            "00".parse::<Bytes>().unwrap()
        );
        assert_eq!(
            key.without_prefix_skip_nibbles(5).unwrap(),
            "00".parse::<Bytes>().unwrap()
        );
        assert_eq!(
            key.without_prefix_skip_nibbles(6).unwrap(),
            "".parse::<Bytes>().unwrap()
        );
    }
}
