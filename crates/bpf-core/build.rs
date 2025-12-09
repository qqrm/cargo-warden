use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");

    if env::var_os("DOCS_RS").is_some() {
        return;
    }

    let has_bpf_linker = Command::new("bpf-linker")
        .arg("--version")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !has_bpf_linker {
        panic!("bpf-linker not found in PATH. Install it (cargo install bpf-linker или nixpkgs.bpf-linker) и перезапусти сборку.");
    }
}

