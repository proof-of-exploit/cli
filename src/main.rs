use proof_of_exploit::{
    cli::{exploit_command, handle_verify, ProveArgs, VerifyArgs, PROVE, TEST, VERIFY},
    env::Env,
    witness::Witness,
};

#[tokio::main]
async fn main() {
    let env = Env::load();

    let matches = exploit_command().get_matches();
    let subcommand_name = matches.subcommand_name();
    let arg_matches = subcommand_name.and_then(|name| matches.subcommand_matches(name));

    match subcommand_name {
        Some(TEST) => {
            let r = ProveArgs::from(arg_matches, env);
            let w = Witness::gen(&r).await;
            w.assert();
        }
        Some(PROVE) => {
            let r = ProveArgs::from(arg_matches, env);
            let w = Witness::gen(&r).await;
            w.prove(r).await;
        }
        Some(VERIFY) => {
            let r = VerifyArgs::from(arg_matches).await;
            handle_verify(r).await;
        }
        _ => unreachable!("command not found"),
    }
}
