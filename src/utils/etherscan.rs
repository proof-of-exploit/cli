pub fn block_url(chain_id: u64, block_number: u64) -> String {
    if chain_id == 11155111 {
        format!("https://sepolia.etherscan.io/block/{}", block_number)
    } else {
        String::new()
    }
}
