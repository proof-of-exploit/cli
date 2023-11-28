use std::{
    env::current_dir,
    process::{Command, Stdio},
};

const HUFF_TEMPLATE: &str = "https://github.com/zemse/proof-of-exploit-huff-template";

pub fn huff_template(project_name: &str) {
    use_template(HUFF_TEMPLATE, project_name);
}

pub fn use_template(git_url: &str, project_name: &str) {
    let next_dir = current_dir().unwrap().join(project_name);
    let next_dir = next_dir.to_str().unwrap();
    run(format!("git clone {git_url} {project_name}",).as_str());
    run_at(next_dir, "rm -rf .git");
    run_at(next_dir, "git init");
    run_at(next_dir, "git add .");
    run_at(next_dir, "git commit -m init");
}

pub fn run(cmd: &str) {
    let split: Vec<&str> = cmd.split(' ').collect();
    let mut cmd = Command::new(split[0]);
    for arg in &split[1..] {
        cmd.arg(arg);
    }
    cmd.stdout(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.wait().unwrap();
}

pub fn run_at(dir: &str, cmd: &str) {
    let split: Vec<&str> = cmd.split(' ').collect();

    let mut cmd = Command::new(split[0]);
    cmd.current_dir(dir);
    for arg in &split[1..] {
        cmd.arg(arg);
    }
    cmd.stdout(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.wait().unwrap();
}
