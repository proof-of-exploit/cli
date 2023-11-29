mod inputs_builder;

use crate::{
    cli::ProveArgs,
    constants::{MAX_CALLDATA, MAX_TXS, RANDOMNESS},
    utils::{
        anvil::{conversion::Conversion, types::anvil_types},
        halo2::real_prover::RealProver,
        ipfs,
    },
    witness::inputs_builder::BuilderClient,
};
use bus_mapping::{
    circuit_input_builder::{FixedCParams, PoxInputs},
    POX_CHALLENGE_ADDRESS, POX_EXPLOIT_ADDRESS,
};
use core::slice::SlicePattern;
use eth_types::{keccak256, Fr, U256, U64};
use ethers::{
    signers::{LocalWallet, Signer},
    types::{transaction::eip2718::TypedTransaction, NameOrAddress, TransactionRequest},
    utils::hex,
};
use halo2_proofs::dev::MockProver;
use std::{
    path::Path,
    process,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use zkevm_circuits::{
    super_circuit::SuperCircuit,
    util::{log2_ceil, SubCircuit},
};

pub struct Witness {
    k: u32,
    instance: Vec<Vec<Fr>>,
    circuit: SuperCircuit<Fr>,
}

impl Witness {
    pub async fn gen(args: &ProveArgs) -> Witness {
        let challenge_bytecode = args
            .challenge_artifact
            .get_deployed_bytecode("Challenge".to_string())
            .unwrap();

        let builder = BuilderClient::from_config(
            FixedCParams {
                max_rws: args.max_rws,
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                max_copy_rows: args.max_copy_rows,
                max_exp_steps: args.max_exp_steps,
                max_bytecode: args.max_bytecode,
                max_evm_rows: args.max_evm_rows,
                max_keccak_rows: args.max_keccak_rows,
            },
            Some(args.rpc.clone()),
            args.geth_rpc.clone(),
            args.block,
        )
        .await
        .unwrap();

        let chain_id = builder.anvil.eth_chain_id().unwrap().unwrap();
        let block_number = builder.anvil.block_number().unwrap();
        println!("Anvil initialized with chain_id: {chain_id:?}, block_number: {block_number:?}");

        // updating challenge bytecode in local mainnet fork chain
        builder
            .anvil
            .set_code(POX_CHALLENGE_ADDRESS, challenge_bytecode.clone())
            .await
            .unwrap();
        // updating exploit bytecode in local mainnet fork chain
        builder
            .anvil
            .set_code(POX_EXPLOIT_ADDRESS, args.exploit_bytecode.clone())
            .await
            .unwrap();

        let exploit_balance_before = builder
            .anvil
            .get_balance(POX_EXPLOIT_ADDRESS, args.block)
            .await
            .unwrap();
        builder
            .anvil
            .set_balance(POX_EXPLOIT_ADDRESS, args.exploit_balance)
            .await
            .unwrap();

        let signer = LocalWallet::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // generate transaction request
        let tx_req_estimate = anvil_types::EthTransactionRequest {
            from: Some(signer.address()),
            to: Some(POX_CHALLENGE_ADDRESS),
            gas_price: Some(U256::zero()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas: args.gas.or(Some(1_000_000)).map(U256::from),
            value: Some(U256::zero()),
            data: Some(anvil_types::Bytes::from_str("0xb0d691fe").unwrap()),
            nonce: Some(
                builder
                    .anvil
                    .get_nonce(signer.address(), Some(block_number))
                    .await
                    .unwrap(),
            ),
            chain_id: Some(chain_id.as_u64().into()),
            access_list: None,
            transaction_type: None,
        };
        let mut tx_req_sign = TypedTransaction::Legacy(TransactionRequest {
            from: tx_req_estimate.from,
            to: tx_req_estimate.to.map(NameOrAddress::Address),
            gas_price: tx_req_estimate.gas_price,
            gas: tx_req_estimate.gas,
            value: tx_req_estimate.value,
            data: tx_req_estimate.data.clone(),
            nonce: tx_req_estimate.nonce,
            chain_id: tx_req_estimate.chain_id,
        });

        // check for reverts and panic out
        let gas_estimate = builder
            .anvil
            .estimate_gas(tx_req_estimate, None)
            .await
            .unwrap();
        tx_req_sign.set_gas(args.gas.map(U256::from).unwrap_or(gas_estimate));

        let signature = signer.sign_transaction_sync(&tx_req_sign).unwrap();
        let raw_tx = tx_req_sign.rlp_signed(&signature);

        // confirm the tx on the local block
        let hash = builder
            .anvil
            .send_raw_transaction(raw_tx.to_zkevm_type())
            .await
            .unwrap();
        builder.anvil.wait_for_transaction(hash).await.unwrap();

        let rc = builder
            .anvil
            .transaction_receipt(hash)
            .await
            .unwrap()
            .unwrap();

        println!("Gas consumed: {}", rc.gas_used.unwrap());

        if rc.status.unwrap() != U64::from(1) {
            // TODO make sure that storage is also updated and not just tx is successful
            // TODO make sure that storage update with reversion does not pass the lookup check
            println!("Error: Exploit transaction is not successful.");
            process::exit(1);
        }

        println!("Tx confirmed on Anvil: {}", hex::encode_prefixed(hash));

        println!("Generating Witness...");

        let tx = builder
            .anvil
            .transaction_by_hash(hash)
            .await
            .unwrap()
            .unwrap();

        let mut witness = builder
            .gen_witness(
                tx.block_number.unwrap().as_usize(),
                PoxInputs {
                    challenge_codehash: keccak256(challenge_bytecode.as_slice()).into(),
                    challenge_bytecode,
                    exploit_codehash: keccak256(args.exploit_bytecode.as_slice()).into(),
                    exploit_bytecode: args.exploit_bytecode.clone(),
                    exploit_balance: args.exploit_balance,
                    exploit_balance_before,
                },
                args.geth_rpc.is_some(),
            )
            .await
            .unwrap();
        witness.randomness = Fr::from(RANDOMNESS);

        println!("Witness generated!");

        let (_, rows_needed) = SuperCircuit::<Fr>::min_num_rows_block(&witness);
        let circuit = SuperCircuit::<Fr>::new_from_block(&witness);
        let k = log2_ceil(64 + rows_needed);
        let instance = circuit.instance();

        // println!("Instances: {instance:?}");

        Witness {
            k,
            instance,
            circuit,
        }
    }

    pub fn assert(self) {
        println!("Running MockProver");
        let prover = MockProver::run(self.k, &self.circuit, self.instance).unwrap();
        println!("Verifying constraints");
        prover.assert_satisfied_par();
        println!("Success!");
    }

    pub async fn prove(self, args: ProveArgs) {
        println!("Running RealProver");
        let mut prover = RealProver::from(self.circuit, self.k, Some(args.srs_path.clone()));

        println!("Generating proof...");
        let mut proof = prover.prove().unwrap();
        proof.challenge_artifact = Some(args.challenge_artifact);

        // TODO don't write to SRS directory
        let proof_path = args.srs_path.join(Path::new(&format!(
            "proof_{}_{}.json",
            self.k,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )));
        println!("Writing proof to {}", proof_path.display());
        proof.write_to_file(&proof_path).unwrap();
        println!("Success!");

        // sanity check
        let verifier = prover.verifier();
        verifier.verify(&proof).await.unwrap();

        if args.ipfs {
            let hash = ipfs::publish(&proof).await.unwrap();
            println!("Published proof to ipfs: {}", hash);
        }
    }
}
