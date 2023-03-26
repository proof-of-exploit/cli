# zk-proof-of-evm-execution

This is a PoC developed at [hackathon](https://ethglobal.com/showcase/proof-of-evm-execution-ix960) that enables a user to prove that they know some calldata that can solve a challenge on EVM.

## Demo

Clone the repo and build.

```sh
cargo build --release
```

This creates a binary:

```sh
./target/release/prove  --help
Usage: prove [OPTIONS] --rpc-url <ETH_RPC_URL> --fork-block <FORK_BLOCK_NUMBER> --challenge-address <CHALLENGE_ADDRESS> --challenge-slot <CHALLENGE_SLOT> --raw-tx <RAW_TX>

Options:
      --rpc-url <ETH_RPC_URL>                  Archive node for mainnet fork [required]
      --fork-block <FORK_BLOCK_NUMBER>         Block number for mainnet fork [required]
      --challenge-address <CHALLENGE_ADDRESS>  Address of contract containing challenge slot [required]
      --challenge-slot <CHALLENGE_SLOT>        Storage slot that should be flipped by a correct solution [required]
      --raw-tx <RAW_TX>                        Witness tx, which should solve the challenge [required]
      --mock                                   Use MockProver for fast constraint verification [default: false]
      --print                                  Print witness and public inputs that has been provided to zkevm circuits [default: false]
      --dir <DIR>                              Directory for reading and writing [default: false] [default: ]
  -h, --help                                   Print help
  -V, --version                                Print version

```

Currently using real prover has a lot of system requires, mock prover consumes less resources:

```sh
./target/release/prove     
  --mock      
  --rpc-url https://eth-sepolia.g.alchemy.com/v2/<api-key>      
  --fork-block 3147881      
  --challenge-address 0xdf03add8bc8046df3b74a538c57c130cefb89b87      
  --challenge-slot 0      
  --raw-tx 0xf88c8084ee6b28008301388094df03add8bc8046df3b74a538c57c130cefb89b8680a46057361d00000000000000000000000000000000000000000000000000000000000000018401546d72a0f5b7e54553deeb044429b394595581501209a627beef020e764426aa0955e93aa00927cb7de78c15d2715de9a5cbde171c7202755864656cd4726ac43c76a9000a
```

## How does it work?

This project depends on:

- [privacy-scaling-explorations/zkevm-circuits](https://github.com/privacy-scaling-explorations/zkevm-circuits) for the zk stuff.
- [anvil](https://github.com/foundry-rs/foundry/tree/master/anvil) for spawning in-memory mainnet fork chain.

A block is locally mined containing the transaction which solves challenge. This block is used as a witness to the [SuperCircuit](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/7e9603a28a818819c071c81fd2f4f6b58737dea6/zkevm-circuits/src/super_circuit.rs#L270). 

The transaction is expected to flip a slot termed as "challenge slot" in a contract. E.g.

```solidity
contract Challenge {
    function isSolved() public returns (bool) {
        // arbitrary challenge somewhere on EVM
    }
    
    // challenge slot
    bool slot;
    function solve() public {
        slot = isSolved();
    }
}
```

## Potential use cases

- Decentralised CTF (not practical as of now, since current prover effort is very huge).
- Whitehat can prove knowledge of vulnerability on smart contract (by constructing it as a challenge).







