fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("WARDEN_OFFLINE").is_some()
        && std::net::TcpStream::connect("example.com:80").is_ok()
    {
        panic!("unexpected network success");
    }
}
