# zk-proof-of-evm-challenge (WIP)

Enables a user to prove that they can solve a challenge on EVM without revealing their solution.

### Potential use cases

- Decentralised CTF (not practical as of now, since current prover effort is very huge).
- Whitehat can prove knowledge of vulnerability on smart contract (by constructing it as a challenge).

## How does it work?

This project depends on:

- [fork of PSE/zkevm-circuits](https://github.com/zemse/zkevm-circuits) for the zk stuff.
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

## Other info

_The development during EthGlobal is on the [hackathon](https://github.com/zemse/zk-proof-of-evm-challenge/tree/hackathon) branch._

