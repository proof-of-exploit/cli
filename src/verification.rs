use crate::{
    cli::VerifyArgs,
    utils::{self, halo2::real_verifier::RealVerifier},
};
use semver::Version;
use std::{process, str::FromStr};

pub async fn handle_verify(args: VerifyArgs) {
    let my_version = Version::from_str(env!("CARGO_PKG_VERSION")).unwrap();
    if my_version < args.proof.version {
        println!(
            "This proof was generated using a newer version of Proof of Exploit. Please upgrade to version v{} or latest if you are facing issues.\n",
            args.proof.version
        );
    }

    let verifier = RealVerifier::load_srs(args.srs_path, &args.proof).await;
    if let Err(error) = verifier.verify(&args.proof).await {
        println!("Proof verification failed: {:?}", error);
        process::exit(1);
    } else {
        println!("Proof verification success!\n");

        if let Some(summary) = args.proof.summary {
            println!("Summary: {}\n", summary);
        }

        println!("Public Inputs:");
        println!("  Chain Id: {:?}", args.proof.public_data.chain_id,);
        println!(
            "  Block: {:?} {}",
            args.proof.public_data.block_constants.number - 1,
            utils::etherscan::block_url(
                args.proof.public_data.chain_id.as_u64(),
                args.proof.public_data.block_constants.number.as_u64() - 1
            )
        );
        println!("  State Root: {:?}", args.proof.public_data.prev_state_root);
        println!(
            "  Challenge Codehash: {:?}",
            args.proof.public_data.pox_challenge_codehash,
        );
        println!(
            "  Exploit Stipend: {} ether",
            ethers::utils::format_ether(args.proof.public_data.pox_exploit_balance)
                .parse::<f64>()
                .unwrap()
        );
    }

    if let Some(unpack_dir) = args.unpack_dir {
        if let Some(challenge_artifact) = args.proof.challenge_artifact {
            println!("\nUnpacking challenge source code...");
            challenge_artifact.unpack(unpack_dir);
            println!("Done!");
        } else {
            println!("\nError: Proof does not contain challenge source code to unpack.");
        }
    } else {
        println!("\nTo view challenge source code, use --unpack flag.");
    }
}
