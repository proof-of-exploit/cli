use eth_types::Bytes;
use std::{process, str::FromStr};

pub fn compile_huff(source_path_string: String) -> Bytes {
    let mut cmd = process::Command::new("huffc");
    cmd.arg(source_path_string);
    cmd.arg("-r");
    cmd.args(["-e", "paris"]); // TODO put this behind a flag somehow
    let output = cmd.output().unwrap();
    if !output.stderr.is_empty() {
        println!(
            "huffc error: {:?}",
            String::from_utf8(output.stderr).unwrap()
        );
        process::exit(1);
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    Bytes::from_str(stdout.as_str()).unwrap()
}
