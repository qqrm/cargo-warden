fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::net::TcpStream::connect("example.com:80").is_ok() {
        panic!("unexpected network success");
    }
}
