use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let checkout_dir = out_dir.join("https-clone");
    match fs::remove_dir_all(&checkout_dir) {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            println!(
                "cargo:warning=failed to remove previous checkout directory {}: {err}",
                checkout_dir.display()
            );
        }
    }

    let default_remote = "https://127.0.0.1:9/cargo-warden-denied";
    let remote = env::var("WARDEN_EXAMPLE_REMOTE").unwrap_or_else(|_| default_remote.to_string());

    let output = Command::new("git")
        .args(["clone", "--depth", "1", &remote])
        .arg(&checkout_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output();

    match output {
        Ok(output) if output.status.success() => {
            println!(
                "cargo:warning=git clone unexpectedly succeeded; adjust policy or clean up manually"
            );
            if let Err(err) = fs::remove_dir_all(&checkout_dir) {
                println!(
                    "cargo:warning=failed to remove unexpected checkout {}: {err}",
                    checkout_dir.display()
                );
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("git clone failed without diagnostic");
            println!("cargo:warning=git clone blocked as expected: {message}");
        }
        Err(err) => {
            println!("cargo:warning=failed to invoke git: {err}");
        }
    }
}
