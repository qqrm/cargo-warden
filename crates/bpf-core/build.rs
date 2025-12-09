use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");

    if env::var_os("DOCS_RS").is_some() {
        return;
    }

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_arch == "bpf" {
        ensure_bpf_linker();
        return;
    }

    if env::var_os("WARDEN_BPF_BUILD_CHILD").is_some() {
        return;
    }

    ensure_bpf_linker();

    let status = Command::new("cargo")
        .env("WARDEN_BPF_BUILD_CHILD", "1")
        .args([
            "+nightly",
            "build",
            "-p",
            "warden-bpf-core",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--target-dir",
            "target/nightly-bpf",
        ])
        .status()
        .expect("failed to spawn cargo for eBPF build");

    if !status.success() {
        panic!("eBPF build failed");
    }
}

fn ensure_bpf_linker() {
    let has_bpf_linker = Command::new("bpf-linker")
        .arg("--version")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !has_bpf_linker {
        panic!(
            "bpf-linker not found in PATH. Install it (cargo install bpf-linker или nixpkgs.bpf-linker) и перезапусти сборку."
        );
    }
}
