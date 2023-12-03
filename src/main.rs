use proof_of_exploit::{
    cli::{
        exploit_command, ProveArgs, PublishArgs, ScaffoldArgs, VerifyArgs, PROVE, PUBLISH,
        SCAFFOLD, TEST, VERIFY,
    },
    env::Env,
    utils::{ipfs, scaffold},
    verification::handle_verify,
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
            let r = ProveArgs::from(arg_matches, &env);
            let w = Witness::gen(&r).await;
            w.assert();
        }
        Some(PROVE) => {
            let r = ProveArgs::from(arg_matches, &env);
            let w = Witness::gen(&r).await;
            w.prove(r).await;
        }
        Some(VERIFY) => {
            let r = VerifyArgs::from(arg_matches, &env).await;
            handle_verify(r).await;
        }
        Some(PUBLISH) => {
            let r = PublishArgs::from(arg_matches);
            let hash = ipfs::publish_file(r.file_path).await.unwrap();
            println!("Published file to ipfs: {}", hash);
        }
        Some(SCAFFOLD) => {
            let r = ScaffoldArgs::from(arg_matches);
            scaffold::huff_template(r.project_name.as_str());
            println!("\nGet started:\ncd {}", r.project_name);
        }
        _ => unreachable!("command not found"),
    }
}
