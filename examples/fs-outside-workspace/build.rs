use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = Path::new("/tmp/cargo-warden-outside-workspace");

    match std::fs::write(target, b"blocked?") {
        Ok(_) => {
            println!(
                "cargo:warning=unexpectedly wrote to {} — clean up manually if sandboxing was disabled",
                target.display()
            );
            if let Err(err) = std::fs::remove_file(target) {
                println!("cargo:warning=failed to remove {}: {err}", target.display());
            }
        }
        Err(err) => {
            println!("cargo:warning=write outside workspace blocked as expected: {err}");
        }
    }
}
