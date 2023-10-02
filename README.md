# proof-of-exploit (WIP)

Enables a user to prove that they can solve a challenge on EVM without revealing their solution.

## Installation

To install the `exploit` binary you can use the following command:

```
cargo install --locked --path .
```

See [this section](#how-does-this-work) for further info.

## Potential use cases

- Decentralised CTF (not practical as of now, since current prover effort is very huge).
- Whitehat can prove knowledge of vulnerability on smart contract (by constructing it as a challenge).

## What's under the hood?

This project depends on:

- [fork of PSE/zkevm-circuits](https://github.com/zemse/zkevm-circuits) for the zk stuff.
- [anvil](https://github.com/foundry-rs/foundry/tree/master/anvil) for spawning in-memory mainnet fork chain.

A block is locally mined containing the transaction which solves challenge. This block is used as a witness to the [SuperCircuit](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/7e9603a28a818819c071c81fd2f4f6b58737dea6/zkevm-circuits/src/super_circuit.rs#L270). 

The transaction is expected to flip a slot in the `Challenge` contract.

```solidity
contract Challenge {
    bool isSolved;

    function entryPoint() public returns (bool) {
        // arbitrary challenge somewhere on EVM

        isSolved = true;
    }
}
```

The challenge contract codehash is revealed in the public inputs of the zksnark. 

For example, here is a [repository](https://github.com/zemse/proof-of-exploit-huff-template) which demonstrates exploiting a re-entrancy vulnerability.

## How does this work?

This project creates a binary called `exploit`.

```
$ exploit --help

Usage: exploit [COMMAND]

Commands:
  test    Test the exploit
  prove   Generate proofs
  verify  Verify proofs
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Proving

For generating a zk proof, the `prove` subcommand can be used.

```
$ exploit prove --help

Usage: exploit prove [OPTIONS]

Options:
      --rpc <URL>                 Enter ethereum archive node RPC url (required)
      --block <NUMBER>            Enter the fork block number (required)
      --challenge <CONTRACT>      Enter hex bytecode or file path (required)
      --exploit <CONTRACT>        Enter hex bytecode or file path (required)
      --tx <HEX>                  Enter the tx
      --dir <PATH>                Enter the dir for srs params
      --mock                      Use mock prover
  -h, --help                      Print help
```

- `Challenge` contract will be public and included in the proof.
- `Exploit` contract will not be revealed.
- Generating proof requires lot of memory (200G+).

### Testing exploit

During writing the exploit if needed to check if the exploit is working properly, the `test` subcommand can be used and it is exactly same as the `prove`.

```
$ exploit test --rpc https://eth-sepolia.g.alchemy.com/v2/<alchemy-key> --block 4405541 \
    --challenge src/Challenge.sol --exploit src/Exploit.huff

anvil initialized - chain_id: 11155111, block_number: 4405541
transaction gas: 97945
test passed
```

### Verification

```
$ exploit verify --help

Usage: exploit verify [OPTIONS]

Options:
      --dir <PATH>       Enter the srs directory
      --proof <PATH>     Enter the proof path
  -h, --help             Print help
```