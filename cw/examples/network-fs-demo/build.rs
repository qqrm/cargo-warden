use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    check_filesystem();
    check_network();
}

fn check_filesystem() {
    let write_target = Path::new("/tmp/warden-network-fs-demo.txt");
    match fs::write(write_target, b"blocked?") {
        Ok(_) => {
            println!(
                "cargo:warning=unexpectedly wrote to {} — clean up manually if sandboxing was disabled",
                write_target.display()
            );
            if let Err(err) = fs::remove_file(write_target) {
                println!(
                    "cargo:warning=failed to remove {}: {err}",
                    write_target.display()
                );
            }
        }
        Err(err) => {
            println!("cargo:warning=write outside workspace blocked as expected: {err}");
        }
    }

    let read_target = Path::new("/etc/hostname");
    match fs::read_to_string(read_target) {
        Ok(contents) => {
            println!(
                "cargo:warning=unexpectedly read {} ({} bytes) — sandbox should block host reads",
                read_target.display(),
                contents.len()
            );
        }
        Err(err) => {
            println!("cargo:warning=read outside workspace blocked as expected: {err}");
        }
    }
}

fn check_network() {
    let addr: SocketAddr = "1.1.1.1:443"
        .parse()
        .expect("static socket address should parse");
    let timeout = Duration::from_millis(200);
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => {
            println!(
                "cargo:warning=unexpectedly reached {} — sandbox should block outbound network",
                addr
            );
        }
        Err(err) => {
            println!(
                "cargo:warning=network access blocked as expected for {}: {err}",
                addr
            );
        }
    }
}
