use clap::command;
use proof_of_exploit::{
    args::{handle_verify, ProveArgs, VerifyArgs, Witness},
    env::Env,
};

#[tokio::main]
async fn main() {
    let env = Env::load();

    let mut c = command!("exploit")
        .version("v0.1.0")
        .about("Proof of Exploit")
        .subcommands([
            ProveArgs::apply(command!("test")).about("Test the exploit"),
            ProveArgs::apply(command!("prove")).about("Generate proofs"),
            VerifyArgs::apply(command!("verify"))
                .about("Verify proofs")
                .after_help("after verify help"),
        ]);

    let matches = c.clone().get_matches();
    let subcommand_name = matches.subcommand_name();
    let arg_matches = subcommand_name.and_then(|name| matches.subcommand_matches(name));

    match subcommand_name {
        Some("test") => {
            let r = ProveArgs::from(arg_matches, env);
            let w = Witness::gen(&r).await;
            w.assert();
        }
        Some("prove") => {
            let r = ProveArgs::from(arg_matches, env);
            let w = Witness::gen(&r).await;
            w.prove(r).await;
        }
        Some("verify") => {
            let r = VerifyArgs::from(arg_matches).await;
            handle_verify(r).await;
        }
        _ => c.print_help().unwrap(),
    }
}
