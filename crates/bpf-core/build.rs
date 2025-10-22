use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const TARGET: &str = "bpfel-unknown-none";
const STACK_SIZE: usize = 4096;
const MANIFEST_NAME: &str = "manifest.json";
const SUPPORTED_ARCHES: &[&str] = &["x86_64", "aarch64"];

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=WARDEN_BPF_USE_PREBUILT");

    if let Err(err) = try_main() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("DOCS_RS").is_some() {
        return Ok(());
    }

    if env::var_os("WARDEN_BPF_BUILD_SKIP").is_some() {
        return Ok(());
    }

    if env::var_os("WARDEN_BPF_USE_PREBUILT").is_some() {
        return Ok(());
    }

    if env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "bpf" {
        return Ok(());
    }

    build_prebuilt_bundle()?;
    Ok(())
}

fn build_prebuilt_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("failed to resolve workspace root"))?;
    let prebuilt_dir = workspace_dir.join("prebuilt");

    if prebuilt_dir.exists() {
        fs::remove_dir_all(&prebuilt_dir)?;
    }
    fs::create_dir_all(&prebuilt_dir)?;

    let object_path = compile_bpf_object(workspace_dir)?;
    let object_bytes = fs::read(&object_path)?;
    let checksum = hex_digest(&object_bytes);

    let mut checksums = BTreeMap::new();
    for arch in SUPPORTED_ARCHES {
        let arch_dir = prebuilt_dir.join(arch);
        fs::create_dir_all(&arch_dir)?;
        fs::write(arch_dir.join("warden-bpf-core.o"), &object_bytes)?;
        checksums.insert(*arch, checksum.clone());
    }

    let manifest_path = prebuilt_dir.join(MANIFEST_NAME);
    let manifest = json!({
        "package": "warden-bpf-core",
        "version": env::var("CARGO_PKG_VERSION")?,
        "kernel_min": "5.13",
        "generated_at": OffsetDateTime::now_utc().format(&Rfc3339)?,
        "target": TARGET,
        "artifacts": checksums
            .iter()
            .map(|(arch, digest)| {
                json!({
                    "architecture": arch,
                    "file": format!("{arch}/warden-bpf-core.o"),
                    "sha256": digest,
                })
            })
            .collect::<Vec<_>>(),
    });
    fs::write(
        manifest_path,
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;

    Ok(())
}

fn compile_bpf_object(workspace_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let toolchain = ensure_nightly_toolchain()?;
    let toolchain_arg = format!("+{toolchain}");

    let sysroot = Command::new("rustc")
        .arg(&toolchain_arg)
        .args(["--print", "sysroot"])
        .stderr(Stdio::inherit())
        .output()?;
    if !sysroot.status.success() {
        return Err(io::Error::other("failed to determine nightly sysroot").into());
    }
    let sysroot_raw = String::from_utf8(sysroot.stdout)?;
    let sysroot_path = PathBuf::from(sysroot_raw.trim());
    let llvm_lib = sysroot_path.join("lib");

    let mut ld_paths = vec![llvm_lib];
    if let Some(existing) = env::var_os("LD_LIBRARY_PATH") {
        ld_paths.extend(env::split_paths(&existing));
    }
    let ld_library_path = env::join_paths(ld_paths)?;

    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    if !rustflags.is_empty() {
        rustflags.push(' ');
    }
    rustflags.push_str(&format!(
        "-C link-arg=--llvm-args=-bpf-stack-size={STACK_SIZE}"
    ));

    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_dir)
        .env("WARDEN_BPF_BUILD_SKIP", "1")
        .env("LD_LIBRARY_PATH", &ld_library_path)
        .env("RUSTUP_TOOLCHAIN", &toolchain)
        .env("RUSTFLAGS", rustflags)
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .arg(&toolchain_arg)
        .args([
            "rustc",
            "-p",
            "warden-bpf-core",
            "--release",
            "--target",
            TARGET,
            "-Z",
            "build-std=core",
            "--",
            "--emit=obj",
        ])
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());

    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other("failed to compile eBPF program").into());
    }

    let deps_dir = workspace_dir
        .join("target")
        .join(TARGET)
        .join("release")
        .join("deps");
    let object = find_object(&deps_dir)?;
    Ok(object)
}

fn find_object(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("o") {
            continue;
        }
        if path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|stem| stem.starts_with("warden_bpf_core"))
            .unwrap_or(false)
        {
            candidates.push(path);
        }
    }

    candidates.into_iter().next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "failed to locate generated object").into()
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn ensure_nightly_toolchain() -> Result<String, Box<dyn std::error::Error>> {
    let nightly_ready = Command::new("rustc")
        .args(["+nightly", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if !nightly_ready {
        let mut install = Command::new("rustup");
        install.args(["toolchain", "install", "nightly"]);
        run_command(install, "failed to install nightly toolchain")?;
    }

    let host_triple = env::var("HOST").unwrap_or_else(|_| String::from("x86_64-unknown-linux-gnu"));
    let nightly_toolchain = format!("nightly-{host_triple}");

    for toolchain in ["nightly", nightly_toolchain.as_str()] {
        let mut components = Command::new("rustup");
        components.args([
            "component",
            "add",
            "rust-src",
            "llvm-tools-preview",
            "--toolchain",
            toolchain,
        ]);
        run_command(components, "failed to add nightly components")?;
    }

    Ok(nightly_toolchain)
}

fn run_command(mut command: Command, error: &str) -> Result<(), Box<dyn std::error::Error>> {
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let status = command
        .status()
        .map_err(|err| io::Error::other(format!("{error}: {err}")))?;

    if !status.success() {
        return Err(io::Error::other(error.to_string()).into());
    }

    Ok(())
}
