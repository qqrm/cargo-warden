fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    match std::net::TcpStream::connect("example.com:80") {
        Ok(_) => println!("cargo:warning=unexpected network success"),
        Err(err) => println!("cargo:warning=network blocked: {err}"),
    }
}
