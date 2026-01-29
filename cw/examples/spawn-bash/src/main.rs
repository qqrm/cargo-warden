fn main() {
    match std::process::Command::new("/bin/bash").spawn() {
        Ok(_) => println!("spawned /bin/bash"),
        Err(e) => eprintln!("spawn blocked: {e}"),
    }
}
