use std::env;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    Command::new("cp").args(&["-rf", ".github"])
        .arg(format!("{}/", out_dir))
        .status().unwrap();

    println!("cargo:rerun-if-changed=src/hello.c");
}