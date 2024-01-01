# Proof of Exploit CLI

Security researchers can prove that a smart contract can be exploited without revealing the bug.

Bug bounty managers receiving lot of bug reports can easily screen bug reports.

For example, this [repository](https://github.com/zemse/proof-of-exploit-huff-template) demonstrates exploiting a re-entrancy vulnerability and here is it's [proof of exploit link](https://proofofexplo.it/verify/Qmek2Mo43HgFn3B6kjMHXBLznqbxyiyxMbTV9sYbJ4oKwE). 

## Technical details

This project depends on:

- [fork of PSE/zkevm-circuits](https://github.com/proof-of-exploit/zkevm-circuits) for the zk stuff.
- [anvil](https://github.com/foundry-rs/foundry/tree/master/anvil) for spawning in-memory mainnet fork chain.

A block is locally mined containing the transaction which solves challenge. This block is used as a witness to the [SuperCircuit](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/7e9603a28a818819c071c81fd2f4f6b58737dea6/zkevm-circuits/src/super_circuit.rs#L270). 

The transaction is expected to flip a slot in the `Challenge` contract.

```solidity
contract Challenge {
    bool isSolved;

    function entryPoint() public returns (bool) {
        // arbitrary EVM code

        isSolved = true;
    }
}
```

The challenge contract codehash is revealed in the public inputs of the zksnark. 

## Installation

To install the `exploit` binary you can clone this repository and run the following command:

```
cargo install --locked --path .
```

Note: the `--locked` is important 

Installation on a fresh Ubuntu 22 instance:

```shell
# install libs
sudo apt-get update
sudo apt-get install gcc libssl-dev pkg-config
# install rust and cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
# install proof-of-exploit cli
git clone https://github.com/proof-of-exploit/cli proof-of-exploit-cli
cd proof-of-exploit-cli
cargo install --locked --path .
```


## Usage

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
$ exploit prove
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
$ exploit verify --proof Qmek2Mo43HgFn3B6kjMHXBLznqbxyiyxMbTV9sYbJ4oKwE
Proof verification success!

Public Inputs:
  Chain Id: 11155111
  Block: 4814850 https://sepolia.etherscan.io/block/4814850
  State Root: 0x17a4764598b67b7c6fb327e9ae56693b641606850b1a28758b6c28b2a3381ce3
  Challenge Codehash: 0x11864e842a04f15016579a7e3f747a18e7dc6eb8c817789bb02be4f94a19d18c

To view challenge source code, use --unpack flag.
```

### Verification on website

For the ease of use for the bug bounty manager, a website can be used to verify the proofs.

https://proofofexplo.it/verify/Qmek2Mo43HgFn3B6kjMHXBLznqbxyiyxMbTV9sYbJ4oKwE

The project is compiled into WASM using the `wasm_build.sh` script.

## Credits

Thanks to [Privacy and Scaling Explorations](http://github.com/privacy-scaling-explorations) for supporting this project.