use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const TARGET: &str = "bpfel-unknown-none";
const STACK_SIZE: usize = 8192;
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

    let object_path = compile_bpf_object()?;
    build_prebuilt_bundle(&object_path)?;
    Ok(())
}

fn compile_bpf_object() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("failed to resolve workspace root"))?;

    let bpf_target_dir = workspace_dir.join("target").join("nightly-bpf");

    let has_bpf_linker = Command::new("bpf-linker")
        .arg("--version")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !has_bpf_linker {
        return Err(io::Error::other(
            "bpf-linker is not available in PATH - install it with `cargo install bpf-linker`",
        )
        .into());
    }

    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    if !rustflags.is_empty() && !rustflags.ends_with(' ') {
        rustflags.push(' ');
    }
    // Увеличиваем лимит стека и для rustc, и для bpf-linker
    rustflags.push_str(&format!(
        "-C llvm-args=-bpf-stack-size={STACK_SIZE} \
         -C link-arg=--llvm-args=-bpf-stack-size={STACK_SIZE}"
    ));

    // Увеличиваем лимит стека и на стадии codegen, и на стадии линковки (bpf-linker)
    rustflags.push_str(&format!(
        "-C llvm-args=-bpf-stack-size={size} -C link-arg=-mllvm -C link-arg=-bpf-stack-size={size}",
        size = STACK_SIZE,
    ));

    let status = Command::new("cargo")
        .current_dir(&workspace_dir)
        .env("WARDEN_BPF_BUILD_SKIP", "1")
        .env("RUSTFLAGS", rustflags)
        .env("CARGO_TARGET_DIR", &bpf_target_dir)
        .arg("+nightly-2025-11-30-x86_64-unknown-linux-gnu")
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
        .status()
        .map_err(|err| io::Error::other(format!("failed to invoke cargo for bpf build: {err}")))?;

    if !status.success() {
        return Err(io::Error::other("bpf build failed - see cargo output above").into());
    }

    let deps_dir = bpf_target_dir.join(TARGET).join("release").join("deps");

    let object = find_object(&deps_dir)?;
    Ok(object)
}

fn build_prebuilt_bundle(object_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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

    let object_bytes = fs::read(object_path)?;
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
