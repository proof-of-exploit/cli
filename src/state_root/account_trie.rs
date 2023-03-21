use super::utils::{Nibbles, Trie};
use crate::error::Error;
use ethers::{
    prelude::EthDisplay,
    types::{Bytes, H256, U256},
    utils::rlp::{Rlp, RlpStream},
};

#[derive(Debug, Clone, EthDisplay, PartialEq)]
pub struct AccountTrie(Trie);

impl AccountTrie {
    pub fn new() -> Self {
        AccountTrie(Trie::new())
    }

    pub fn from_root(root: H256) -> Self {
        AccountTrie(Trie::from_root(root))
    }

    pub fn set_root(&mut self, root: H256) -> Result<(), Error> {
        self.0.set_root(root)
    }

    pub fn root(&self) -> Option<H256> {
        self.0.root
    }

    pub fn get_account_data(&self, path: Nibbles) -> Result<AccountData, Error> {
        let raw_account = self.0.get_value(path)?;
        AccountData::from_raw_rlp(raw_account)
    }

    pub fn set_account_data(&mut self, path: Nibbles, new_value: AccountData) -> Result<(), Error> {
        self.0.set_value(path, new_value.to_raw_rlp()?)
    }

    pub fn set_nonce(&mut self, path: Nibbles, new_nonce: U256) -> Result<(), Error> {
        let mut data = self.get_account_data(path.clone())?;
        data.nonce = new_nonce;
        self.0.set_value(path, data.to_raw_rlp()?)
    }
    pub fn set_balance(&mut self, path: Nibbles, new_balance: U256) -> Result<(), Error> {
        let mut data = self.get_account_data(path.clone())?;
        data.balance = new_balance;
        self.0.set_value(path, data.to_raw_rlp()?)
    }

    pub fn load_proof(
        &mut self,
        key: Nibbles,
        value: AccountData,
        proof: Vec<Bytes>,
    ) -> Result<(), Error> {
        self.0.load_proof(key, value.to_raw_rlp()?, proof)
    }
}

#[derive(Debug, Clone)]
pub struct AccountData {
    pub nonce: U256,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

impl AccountData {
    pub fn from_raw_rlp(raw: Bytes) -> Result<Self, Error> {
        let rlp = Rlp::new(&raw);
        Ok(Self {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            storage_root: rlp.val_at(2)?,
            code_hash: rlp.val_at(3)?,
        })
    }

    pub fn to_raw_rlp(&self) -> Result<Bytes, Error> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(4);
        rlp_stream.append(&self.nonce);
        rlp_stream.append(&self.balance);
        rlp_stream.append(&self.storage_root);
        rlp_stream.append(&self.code_hash);
        Ok(Bytes::from(rlp_stream.out().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountData, AccountTrie, Nibbles, U256};
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
            hex::encode(account.storage_root),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        assert_eq!(
            hex::encode(account.code_hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );

        // encode
        assert_eq!(hex::encode(account.to_raw_rlp().unwrap()), raw_rlp);

        println!("{:?}", account);
    }

    #[test]
    pub fn test_account_trie_updates_1() {
        // This test uses block 1000008 on ethereum mainnet which just has 1 simple ether transfer tx
        // https://etherscan.io/txs?block=1000008

        // loading proof for accounts whose account was changed: sender, receiver and miner
        let mut trie = AccountTrie::new();
        let sender = Nibbles::from_address(
            "0x2a65Aca4D5fC5B5C859090a6c34d164135398226"
                .parse()
                .unwrap(),
        )
        .unwrap();
        let receiver = Nibbles::from_address(
            "0xb6046a76bD03474b16aD52B1fC581CD5a2465Bd3"
                .parse()
                .unwrap(),
        )
        .unwrap();
        let miner = Nibbles::from_address(
            "0x68795C4AA09D6f4Ed3E5DeDDf8c2AD3049A601da"
                .parse()
                .unwrap(),
        )
        .unwrap();

        trie.load_proof(
            sender.clone(),
            AccountData {
                nonce: U256::from("0x2a127"),
                balance: U256::from("0xb5248f2ebf8f5db4ef"),
                storage_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                    .parse()
                    .unwrap(),
                code_hash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                    .parse()
                    .unwrap(),
            },
            vec![
                "0xf90211a0b872db6acc7578d800933b3feccc45efef5f2da00785fca59f289b34eb57ebbba08f76ef15b477fd42f2ca04c26cf29c83951abe5fb1fa1a60720168b714edb7cea0e3e790cd7cd981889d1e6e4cf63a3b30dc000f1691d45710b3909dedc0937e34a01420a38afb3f20254769a0fd30df5491335cea49c7987bd6d0def3f57a31d808a0c57482cbb52a96ee1fef320372d955a7a26bc63c8764cf8ccb174668669b441ba009a695239c731388ed07d5d6b72539f9417e6f0e52e0183b26d1f128abf8087ca02733233b16bfdb1dad2a36ef4a5a89e19775fffe59e32bd9dfffe9bcf3192d54a07cb5b5554f33dd6a9945762f2309e810784decf1d20b1b5ce2ea566950d47ebea08b98b75aed32960445816529bce7a6eae46f5d4acdd9eefb96c1d5454abe9ca9a09c74e85958f9fc02f811a2f2183fdbcf45348cc7f22d9b0b0016f02b671a5869a0e1a824538b465ee676365108f9ab960fcf8209c0ecf898f24e5cf4b6ffe19667a08ea30f24c5cbbe29eedf29518e601fe597f4ead30b6e7c6d206187df08d118a4a0daf637f97661b524ee658b44e5c775b1d15393a4d9e6fd697b3201b014d7a8cea0067eeff1881be674d5cbfc21385f16e99283e93d70f8becb7cbbccf814c26e33a04c755ff43db496e3ac08605a91129bb3acf31fb3cc6fa49ea3355e95f32f422ca0931ea32e24b1747103be9909335432fe7315b23ecad64224ced0c5c948e6db8a80".parse().unwrap(),
                "0xf90211a010f66c3b4927794bcd52fd5ab9d144222570a11976638728d5c3e22404c90620a03badab572f50547670e913274b364d1a8c893e65cea9c97eb7f0baf5c18d3b76a017b7c25ab4fc30922bb7fed1fb17e44d85c99b169bcca9b3fc8e2d216682e0d6a04e0f3aeff0ec0fc45a3cc09e05ba0dabbf915f52a08ec40747368fcbeaa3c3b5a048ac208cb706afbf0e2d2e65fdd694acaa54a24cb332c58bbc76c08f1575f05ba00bffc6afbafddae64da64e3724cc26ef1f7a99c689b16919e70b25170acdc110a0c9b7ec1d01e4cab026b7dd1d3ebb952d258d952b9a75d42db82120b38b44489da058fc085756fd0364e19d7ad49ec312570691369a89c4e0a03817784ae4475c20a023f44d98ea1a51265bd0681aec943243ce5d1e5af54416956b7bfd024a984131a0fded887737a482b93f820600233f09c4c05ae75f2d8ea304a7b9b988bbfa920ca034086886808e90a6ead5220693ad58a547a71dcf5a35a514fd6d304165df2626a08df064d29c49f810116576236bbc39c48ea534e3e967f0080cbc911c17d3aa57a0415428e4a52c38874c1c4623c46cc137d612ed059ac954acb999e576a7621552a08e45dbae86e83149d90c8a05e222431a4a5ff6c7a586e084d6964e023374641ba05dbaf83911ba5aacdd4f349c2fdc22b3428ed984503cc699b09fb7be3e32fd1ea0f64997d5eb20087d49f58ee7a052947b8c6605481651f72bc8280efafd4a76ab80".parse().unwrap(),
                "0xf90211a0b0912bb4a5e6a6fbcc91e115cd9407428eb4d0fcd9dbe500ebd30c8fc5297208a0a662bf0295ca5b28e7e75bbcb1bf79799afc81cfecf0888861f2ae70e471638fa0f0b8b3f425106f5adfc5b84c30fc8c3ee9fbb046525aa516132a0f59e27830eaa046a0b90af97fb574b7b8d07eff5c8799861e1a9c80a228c8f96052eb48c614f7a01b24a0e3d61e54f7b7ed906157533f3f7c4c3b1824d583234704dde049db6374a054e74d8291f182b204b0e66b6b612712a9d776f5fc0b52cf1a1f0c8996a2d339a02794c5e4cab0d1c6918c05950c3f49c1a1aed3559aaff365d100f17f1f3d3f8ea0ecaaa25a2a93a40fa328918c8462bb0a1cfbfdb3fb43265ff0ca34c120e40699a098c35ab29f8a5aea2525b42aa1ea66741cb8084112cd3160f27308f72b299d4fa0da752e8e516dfbe90c90ca184080007cce5ebb8c6e955d07050e19388ce8924da0662cb27779400b28fb4c1018c3e4d58c6eef922c99cc09d41e8ac788c7e8edc0a0eff4bfb18dc77e59f76ca860e70398930c40d46acd4cc3aee8d3432619e4d0fba05010634bc99847258ca11b5e1fa129485110bc0da2110199337bca5347148c55a0fa9f321f1656f36af93cd948935c22fb084c8f7a3813208dc88bfc2ad069bc49a0a6ffca74cb5e3a3f169da4ca2e2e72f29ca04b860e6eb6e1dcae50bc93d75667a0d1ade98e2a688e113fef7a134da184b9fb5d3468b93344c42bc3c94c36d3421580".parse().unwrap(),
                "0xf9015180a0cde5a13328c0a23d05e2e53425bd29c1a458f0672bc219743e23d3b40a44fa92a0b6fc717bbe9933d0946fcf64963dd498ab3d170f04546df74da2ac670fbc893da078880340efbcaa89389eda6001d8641a3b8552404ab99bb23341b3629d573943a0bd3c92402c5625075debdf628adece64158654903c815b773f251ca7a76a9afa80a05fb53cd46de99a950a122a48a02f1aa7bd2b842c0428f44789f0bb10401ce318a013e949433bf2df98633ddd978a5facedcd9915c634129c86a62b5ec0c27304c8a044f2924f833ae869e19e57fd2ceb29d4716c6141c0dacc1e589aa0665ba153faa0d20db76335360a3ee8b4eb7bd3d97683e8063eed144c107aef5fc621f27f46dd808080a07a17418d527d6dc388e464c51cc89b53db8f461a8711a9504adb153868e89bac80a0c54b6f527b97380535f9434a43cdd1f6f9a822e8d1ba8f8d48944fa63ed2704780".parse().unwrap(),
                "0xf8749f20d22c718c78d005078a67495f59893d2948fe4f8796794437901123e3e90db852f8508302a12789b5248f2ebf8f5db4efa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".parse().unwrap(),
            ],
        )
        .unwrap();

        trie.load_proof(
            receiver.clone(),
            AccountData {
                nonce: U256::from("0x20d"),
                balance: U256::from("0x175a0778"),
                storage_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                    .parse()
                    .unwrap(),
                code_hash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                    .parse()
                    .unwrap(),
            },
            vec![
                "0xf90211a0b872db6acc7578d800933b3feccc45efef5f2da00785fca59f289b34eb57ebbba08f76ef15b477fd42f2ca04c26cf29c83951abe5fb1fa1a60720168b714edb7cea0e3e790cd7cd981889d1e6e4cf63a3b30dc000f1691d45710b3909dedc0937e34a01420a38afb3f20254769a0fd30df5491335cea49c7987bd6d0def3f57a31d808a0c57482cbb52a96ee1fef320372d955a7a26bc63c8764cf8ccb174668669b441ba009a695239c731388ed07d5d6b72539f9417e6f0e52e0183b26d1f128abf8087ca02733233b16bfdb1dad2a36ef4a5a89e19775fffe59e32bd9dfffe9bcf3192d54a07cb5b5554f33dd6a9945762f2309e810784decf1d20b1b5ce2ea566950d47ebea08b98b75aed32960445816529bce7a6eae46f5d4acdd9eefb96c1d5454abe9ca9a09c74e85958f9fc02f811a2f2183fdbcf45348cc7f22d9b0b0016f02b671a5869a0e1a824538b465ee676365108f9ab960fcf8209c0ecf898f24e5cf4b6ffe19667a08ea30f24c5cbbe29eedf29518e601fe597f4ead30b6e7c6d206187df08d118a4a0daf637f97661b524ee658b44e5c775b1d15393a4d9e6fd697b3201b014d7a8cea0067eeff1881be674d5cbfc21385f16e99283e93d70f8becb7cbbccf814c26e33a04c755ff43db496e3ac08605a91129bb3acf31fb3cc6fa49ea3355e95f32f422ca0931ea32e24b1747103be9909335432fe7315b23ecad64224ced0c5c948e6db8a80".parse().unwrap(),
                "0xf90211a0dfdc8f9b6bba57326c08e4f954f78afe609f85ec5db9dd79b1a44c386bdb9f67a0e82b85371d413d58d75043f762100e77f2db7189142d19de182909192ee22a02a0005d0442af65e4904fb408da1ba433129b3793d6e15bdfcaee478720dbdbc514a0ebf191e685f6b48aef3026a497282edc9d5000c8a060472653b24ba54d5f7e40a0e506e33c46efd03b768f80e0ebff5517a49fc9e0294feda712334cc192d1766da04d3b04327f4450be779d58e67f5d6eb30c490e6910bcc5dca8ef19b82bb6abbea0d0b8a5724c610897451fa76b4859335dc947d0cd7ed06a6677d7394461080c5ea05bd02c0a20e4a9b57c2f0b322ea75ecba87403354d6c1f149c1ef74af78f3a92a05bc0b6fc02b306fad85da2c64611ee335813e8181a7860e2d980e572b6894444a010dc1fa8b7cdbbb80470132ee0a4586ec540fbfc9e2a3a9cbf217cf4f3754422a0655afc7eb40d9db73b483c6a5bfde28aeaf91d00a55cd5d0d7e65c2608af71eea0a89f6568903e591c321d24956406636b719b2edf2f83c1034e6fd0a9c96c0ff4a03611f8d09126a2ebd7a05e23ee3016b74a5fc6075ae6ff830c8590619ce7ee03a0838a9854c5a6ae2d316053e31e4d730bafdd300e038758e7dd9344eff79f1469a046f8afc9fbcb1178bcc1f97497af0748e0a6d0a1356b72ffaa16e672093597c6a062d717a124acd57db60980420fc3e4abccb28c551989b86a897b8eabde7f463f80".parse().unwrap(),
                "0xf90211a05a726dc7588e2cbdf2b6eb2d24171b3884bb4a8d1e439e89de791b664fcb43efa0475e4a086e10dc482864a03b0dbdc55c93fe25a61100d69f4ca6830f571a0f0da0c4c3bb06574e819c5b5ca02492a1044543c3752ea67cff8877b411c4f64e9f63a0ff539b72d28a2a3f5c9917d1d2e1f0cb5f06ca4b387298681657db25273170dfa05e85836b0f0994d2f0fca003f15d7fbf61c002a1e82a97be324ebe297f8ef3bca05eb089284c66511a84a6bb7a5003073bb86c6835d4cefea3759651c2e2a92aefa0a3ba888570cef1cf8bc4029b121550bb8f7a03f564633919c9e9aafb295d6f01a005132c0bbea671df7502ddc14bc59bcbc3aa6cf34d67bb78c2f28d5d2122cca7a0a59595ff4ce21603a88491ee643b9fd81b06dd14a5a6969170651a01dad3041ba042e6d4e0d85b90fe15d8c6ef4309ba6c1b3bdc4eebe0cb2097a9c9826e6999bda0911a8d3ee4c4d37f77316a1d0c1d2a856bc84bd686b5ff88c331a84b7abceb94a0f454f270496d856a40f5fa37b0ef2a2233ea4190ca2b464ad8c5a8fc1d2e1c42a07755a7b53c87a08134f769d54d31dbdefd779f35ef40b9d912f0295edb5c5fbba0ee85a21388c438e5d21cd4814af3c1866e64e59a4e636ec2d1718138412cf576a0d7163c1a0cac540f37ccdb8d53a491c058a5e0dd9aa051efd1db587573633d90a05bca2a496b44818e95f035acd18482156ecaf02f3e77856b3633d6751394989580".parse().unwrap(),
                "0xf901b1a05b4e748a87674e2923690a105a0ae8fb156312c7078f0e89228a49fda115a5d3a050ce0bceb4eecd749e6b9884cee78bfee439c9d1ca6534da423a2b8dfb7a7ad4a09079bef092b9dea521ac4b47dfe498d95b47dfc0f219a0a4d6adafdfb7ed59e7a0a6b0cf56e1f19f82c8b7890d8fa92108fc5d89117c2c5306822d351b8a540c7580a09c990b48512616f0679f2d92423be76c18813c35b60215b41a3568902a0dd61da0040ac301625bdc482419d3f675c6f967613f01a2637aab53103e1e878b2c8d1da0972b23c87cbc9604394022ef8f305477b9db0bf4cabc1f1709db52520d5ad5fea0689541bd7e9ee8185482f3645579c7097bab241238353c3b052d943f05998dc1a05670080765a2c98c4f39377f16f1bc16e035932e05a655993ecbdb6e8dedb10ba04ac85b26bf933c516a20f934b2b14be17d330975d3e0ec918915d90aac203c4fa09ce675b446906d30cf81a487fd08e66face220b37263b7031a2f4fa2616aeb22a0416e79146039ce0184df455e9c69604f69890579a0cac110663a6746b72b7e7ca03e13c4d520d415ea0c7304e2cae20261f6c992bf401661191c606758b25872c1808080".parse().unwrap(),
                "0xf85180808080a006cc1b75bac86bcda8f9636f8ae83b9d74d24fce7f71167839ae31e7fa623e65808080808080808080a0c72294ea56bff58992c8a51b405b17ec3f46da0d3f8b02db1af2e2d42d4101f98080".parse().unwrap(),
                "0xf86d9e329824df982cb95ef9ccb666bff18501f405be7e41fd6019306074b748e5b84cf84a82020d84175a0778a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".parse().unwrap(),
            ],
        )
        .unwrap();

        trie.load_proof(
            miner.clone(),
            AccountData {
                nonce: U256::from("0x2651"),
                balance: U256::from("0x43cc248fcad9b3f3b0"),
                storage_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                    .parse()
                    .unwrap(),
                code_hash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                    .parse()
                    .unwrap(),
            },
            vec![
                "0xf90211a0b872db6acc7578d800933b3feccc45efef5f2da00785fca59f289b34eb57ebbba08f76ef15b477fd42f2ca04c26cf29c83951abe5fb1fa1a60720168b714edb7cea0e3e790cd7cd981889d1e6e4cf63a3b30dc000f1691d45710b3909dedc0937e34a01420a38afb3f20254769a0fd30df5491335cea49c7987bd6d0def3f57a31d808a0c57482cbb52a96ee1fef320372d955a7a26bc63c8764cf8ccb174668669b441ba009a695239c731388ed07d5d6b72539f9417e6f0e52e0183b26d1f128abf8087ca02733233b16bfdb1dad2a36ef4a5a89e19775fffe59e32bd9dfffe9bcf3192d54a07cb5b5554f33dd6a9945762f2309e810784decf1d20b1b5ce2ea566950d47ebea08b98b75aed32960445816529bce7a6eae46f5d4acdd9eefb96c1d5454abe9ca9a09c74e85958f9fc02f811a2f2183fdbcf45348cc7f22d9b0b0016f02b671a5869a0e1a824538b465ee676365108f9ab960fcf8209c0ecf898f24e5cf4b6ffe19667a08ea30f24c5cbbe29eedf29518e601fe597f4ead30b6e7c6d206187df08d118a4a0daf637f97661b524ee658b44e5c775b1d15393a4d9e6fd697b3201b014d7a8cea0067eeff1881be674d5cbfc21385f16e99283e93d70f8becb7cbbccf814c26e33a04c755ff43db496e3ac08605a91129bb3acf31fb3cc6fa49ea3355e95f32f422ca0931ea32e24b1747103be9909335432fe7315b23ecad64224ced0c5c948e6db8a80".parse().unwrap(),
                "0xf90211a0de271ba132d76b9b2dcb4902dd6d60e2a5f5f5b8940aaaa9f4247de59e0d11d8a0c9ea34ecfc215ea585c2d2406e0a37d3a8f425d939d4d8a02e203511bd0cb441a0567922bb7ec715149b98a8694582465a043170a6290bd95e073922c6898152bba08da889ceff439d5b30b7345356681a5e0b0c1bc63a05dbb24953b8f153285b74a0babc5be8b325cf09d3c68f4019169d4aad7fc164607ea50ca326f2199b6dec0fa0c1e38871208b8db6f5abad76ad137005a744e20dd6b6b19c85e5d8a4ad6c9d6aa05734cf6f86cb25c21426a69de38118dcebd9658068253a49cedf207395b1790da0b1ba26d1448f34650e44bae0afcae13692f256ca5a0038e4a92004ae6f4c7c67a02a25d5235fdd489e1f5005701029ba4d07e9ec9a99e348eadd98ca3941a5438ea07ed1544c9338fa1da5a6e01e5a8c9d2724eadff7c1bfaa7bc41b270a358b824ea0a8375595bf68d019548f82d2caea8e8ebd8bad5ae1f077acf6595bc7871829fda06f5b3ef28701baf58acbd75944f376f069f300d45c12f2f82e89c447d6e252f6a0dde558667d38db084dd4a0ee114f6d6aaa7a17f6a4d3e5565fac2c2512cb9e97a0e89d28942e43e3d1f7a5c31e4bfcc244d6502c29e0fc080fbb78ee884385b2d1a0931d4567231f3c1ecbf5e149793afd226dc6bd39594a7b93e0d7810d83d3f8b7a0464c8f00d5f972b8dd12f7cfb700dcb2676d008fa2238dc06b60a7270d0036d880".parse().unwrap(),
                "0xf90211a0bf7af7ef8b01370fcfb4332b122977259ab9e320dc248bad1abd9dddd4af8d77a0c5d4402195ec9bb50b1dffb55800ff1de2f8d49b7fb101c7a31aa1c214a97f30a0609035cad167407e9ec283187a7f2955c17115cccef18a90178704c45dc72570a01c9c1ea845dc7df3e03f365587100b26832de1b92d4798c403be7454f918c125a07d941b4d1d0ff5231a4a72a3715bb2751d60c297066c7561a1beb35815ede8dda01af440c3d4b8760f8f10173fcfc4bf5c82473545c4c56293d70bdae835bd6e2ba020c8aefed89c2f55abe99963a76d6b00b0299514278897a9ceffdb9980d53245a010e46dfd4562947971f0ba2bce055f624446f3f2e2a1ffb9a33d46c6cff161f8a042210d39fa4a90dddfb16fb007028b15f0887c522ba290ddb6e1d333a18ac9bba09f0478bca97fa032f8acfe242e5fc0e17989370625f4ad0858b4007a059f5dd0a023e5b91046545d785132e5c21094da173e9b8aba264d019b7e586f199f0c68e6a04cccc8a69b8d08cd6a87b2448d24ef8a3d11991585cc1515149843a842d16c53a052e4e615f4262fefd0ef1070ee22ad31a7b20ce00aade7128f2e0df496c21e6fa00dbdedc03a8567d79086d1102adc6620faf55587ec85352f6cf7ea3629b8726ea07b517118c661d6f7d72e1f1f487de10bd1bc41cba9ff4e195beb93d626ac3dc8a08409760e09425f1704ca40c7383053107d2bc5636a5aeedb9747036c81cae7ac80".parse().unwrap(),
                "0xf9017180a02f03be719ef165fa85134f5dc3eb0ee6fd979d0a07487d3c1e9cef9e9211d5e6a04b7fbcbe6ccc262a45d04c95771111d33e31088f0d0d0d20d6a6a82ee65af2b0a06f0174fadbdc8dc392790822db2b4059d6fa2d8ea6b0c6843dd921bb891709afa0cb0cfe404b67a65de084e9985d97936f080a6cb5869784d705f9a57c4706cc8e80a0f20ea6fd2dd9105eb38744371997867e6e219a44247552e182f314b9e43d8a8ea05083e08af8a912e129ae8a5e12004df0686738426164a33bd7b157eca1365c7880a0d47b197d6bac05e149a5a14dcbadd42fc9173b0f20ef8c64c429ab7707712536a02283844c683e719684870fdb21fb089b0849ae38c8c29363883efda7eeb15bb4a0f78e9313403382d55d3d53d0d92dfd60a3e954d8e8088ee776d85c1fcb99a266a0f10e554bd3062c35d307a3b86063bf449e256e1fd54888fcd1163960c96ccf058080a0985aada1f63c189ad62ca48c52f7f99afeb61274ef667ba6f9c7a567748ad6b680".parse().unwrap(),
                "0xf8739f206d7cb0b08bd946b092932a54ff1d07bd2c46a751df96693e0e637c4d953fb851f84f8226518943cc248fcad9b3f3b0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".parse().unwrap(),
            ],
        )
        .unwrap();

        // state root on mainnet block 1000007
        assert_eq!(
            hex::encode(trie.root().unwrap()),
            "3d30cf33487586dc69cc29227e031519b9196b0f6f62f5432d56a949eaf41deb"
        );

        // performing the state transition
        trie.set_balance(sender.clone(), U256::from("0xb51619b5e016ea68ef"))
            .unwrap();
        trie.set_nonce(sender, U256::from("0x2a128")).unwrap();
        trie.set_balance(receiver, U256::from("0xe71bde762c9b378"))
            .unwrap();
        trie.set_balance(miner, U256::from("0x44118bdc454bab93b0"))
            .unwrap();

        // state root on mainnet block 1000008
        assert_eq!(
            hex::encode(trie.root().unwrap()),
            "8da9a5b0d31d90c6aee4d3a29f80f026425ab967bb50b3a75b363ffde1c9c882"
        );
    }
}
