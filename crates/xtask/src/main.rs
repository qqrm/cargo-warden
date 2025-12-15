use anyhow::{Context, Result, anyhow};
use cargo_metadata::MetadataCommand;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::{Builder, Header};

const PACKAGE_NAME: &str = "warden-bpf-core";
const TARGET: &str = "bpfel-unknown-none";
const OBJECT_NAME: &str = "warden-bpf-core.o";

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("bpf-prebuilt") => build_prebuilt_artifacts(),
        _ => Err(anyhow!("Usage: cargo xtask bpf-prebuilt")),
    }
}

#[derive(Serialize)]
struct Manifest {
    package: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_min: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Serialize)]
struct ManifestArtifact {
    architecture: String,
    file: PathBuf,
    sha256: String,
}

fn build_prebuilt_artifacts() -> Result<()> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("failed to read cargo metadata")?;

    let workspace_root = PathBuf::from(metadata.workspace_root.clone());

    let target_base = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"));

    let target_dir = target_base.join(TARGET).join("release");

    run_build(&workspace_root)?;

    let artifact = locate_artifact(&target_dir).with_context(|| {
        format!(
            "unable to locate compiled object for target {}; expected {}",
            TARGET,
            target_dir.join(OBJECT_NAME).display()
        )
    })?;

    let prebuilt_dir = workspace_root.join("prebuilt");
    if prebuilt_dir.exists() {
        fs::remove_dir_all(&prebuilt_dir)
            .with_context(|| format!("failed to clear {}", prebuilt_dir.display()))?;
    }

    let arch = env::consts::ARCH;
    let dest_rel_path = PathBuf::from(arch).join(OBJECT_NAME);
    let dest_path = prebuilt_dir.join(&dest_rel_path);
    fs::create_dir_all(
        dest_path
            .parent()
            .ok_or_else(|| anyhow!("missing parent for {}", dest_path.display()))?,
    )?;
    fs::copy(&artifact, &dest_path).with_context(|| {
        format!(
            "failed to copy {} to {}",
            artifact.display(),
            dest_path.display()
        )
    })?;

    let checksum = sha256_file(&dest_path)?;
    let manifest_path = prebuilt_dir.join("manifest.json");
    let manifest = Manifest {
        package: PACKAGE_NAME.to_string(),
        version: resolve_package_version(&metadata, PACKAGE_NAME)?,
        kernel_min: None,
        generated_at: None,
        target: Some(TARGET.to_string()),
        artifacts: vec![ManifestArtifact {
            architecture: arch.to_string(),
            file: dest_rel_path.clone(),
            sha256: checksum,
        }],
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, manifest_json).context("failed to write prebuilt manifest.json")?;

    let tarball_path = workspace_root.join("prebuilt.tar.gz");
    if tarball_path.exists() {
        fs::remove_file(&tarball_path).ok();
    }

    create_tarball(
        &prebuilt_dir,
        &tarball_path,
        [&manifest_path as &Path, &dest_path as &Path],
    )?;

    println!(
        "BPF artifacts ready: {} and {}",
        tarball_path.display(),
        manifest_path.display()
    );

    Ok(())
}

fn run_build(workspace_root: &Path) -> Result<()> {
    let status = Command::new("cargo")
        .current_dir(workspace_root)
        .args([
            "build",
            "-p",
            PACKAGE_NAME,
            "--release",
            "--target",
            TARGET,
            "-Z",
            "build-std=core,compiler_builtins",
        ])
        .env(
            "CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER",
            env::var("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER")
                .unwrap_or_else(|_| "bpf-linker".into()),
        )
        .status()
        .context("failed to invoke cargo build")?;

    if !status.success() {
        return Err(anyhow!("cargo build for {PACKAGE_NAME} failed"));
    }

    Ok(())
}

fn locate_artifact(target_dir: &Path) -> Result<PathBuf> {
    let preferred = target_dir.join(OBJECT_NAME);
    if preferred.exists() {
        return Ok(preferred);
    }

    let mut fallback: Option<PathBuf> = None;
    for dir in [target_dir, &target_dir.join("deps")] {
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if !is_artifact_candidate(&path) {
                    continue;
                }

                let ext = path.extension().and_then(|ext| ext.to_str());
                match ext {
                    Some("o") => return Ok(path),
                    Some("so") if fallback.is_none() => fallback = Some(path),
                    None if fallback.is_none() => fallback = Some(path),
                    _ => (),
                }
            }
        }
    }

    fallback.ok_or_else(|| anyhow!("no build output found in {}", target_dir.display()))
}

fn is_artifact_candidate(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.replace('-', "_").contains("warden_bpf_core"))
        .unwrap_or(false)
}

fn resolve_package_version(metadata: &cargo_metadata::Metadata, name: &str) -> Result<String> {
    metadata
        .packages
        .iter()
        .find(|package| package.name == name)
        .map(|package| package.version.to_string())
        .ok_or_else(|| anyhow!("missing package {name} in workspace"))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn create_tarball<'a>(
    prebuilt_dir: &Path,
    tarball: &Path,
    files: impl IntoIterator<Item = &'a Path>,
) -> Result<()> {
    let tar_file =
        File::create(tarball).with_context(|| format!("failed to create {}", tarball.display()))?;
    let encoder = GzEncoder::new(tar_file, Compression::default());
    let mut builder = Builder::new(encoder);

    for path in files {
        let rel = path
            .strip_prefix(prebuilt_dir)
            .context("failed to strip prebuilt prefix from artifact path")?;
        append_file(&mut builder, path, &PathBuf::from("prebuilt").join(rel))?;
    }

    builder.finish()?;
    let mut encoder = builder.into_inner()?;
    encoder.try_finish()?;

    Ok(())
}

fn append_file(
    builder: &mut Builder<GzEncoder<File>>,
    path: &Path,
    archive_path: &Path,
) -> Result<()> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let metadata = file.metadata()?;

    let mut header = Header::new_gnu();
    header.set_path(archive_path)?;
    header.set_size(metadata.len());
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();

    builder.append(&header, &mut file)?;
    Ok(())
}
