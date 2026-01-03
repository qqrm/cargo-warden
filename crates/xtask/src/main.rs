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

fn workspace_root() -> Result<std::path::PathBuf> {
    use anyhow::{Context, Result, anyhow};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn is_workspace_root(dir: &Path) -> Result<bool> {
        let toml = dir.join("Cargo.toml");
        if !toml.is_file() {
            return Ok(false);
        }
        let contents = fs::read_to_string(&toml)
            .with_context(|| format!("failed to read {}", toml.display()))?;
        Ok(contents.contains("[workspace]"))
    }

    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if is_workspace_root(&dir)? {
            return Ok(dir);
        }
        if !dir.pop() {
            break;
        }
    }

    Err(anyhow!(
        "failed to locate workspace root from CARGO_MANIFEST_DIR"
    ))
}

fn build_prebuilt_artifacts() -> Result<()> {
    let workspace_root = workspace_root()?;
    let prebuilt_dir = workspace_root.join("prebuilt");
    if prebuilt_dir.exists() {
        fs::remove_dir_all(&prebuilt_dir)
            .with_context(|| format!("failed to clear {}", prebuilt_dir.display()))?;
    }
    fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("failed to create {}", prebuilt_dir.display()))?;

    // Disable basic block sections to avoid `.text.unlikely.*` sections in the BPF object.
    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    if !rustflags.is_empty() {
        rustflags.push(' ');
    }
    rustflags.push_str("-C llvm-args=-basic-block-sections=none");

    let status = Command::new("cargo")
        .current_dir(&workspace_root)
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
        .env("RUSTFLAGS", rustflags)
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

    let target_dir = workspace_root.join("target").join(TARGET).join("release");
    let built_object = locate_artifact(&target_dir)?;

    let arch = env::consts::ARCH;

    let dest_rel_path = PathBuf::from(arch).join(OBJECT_NAME);
    let dest_path = prebuilt_dir.join(&dest_rel_path);
    fs::create_dir_all(dest_path.parent().unwrap())
        .with_context(|| format!("failed to create {}", dest_path.parent().unwrap().display()))?;

    fs::copy(&built_object, &dest_path).with_context(|| {
        format!(
            "failed to copy {} to {}",
            built_object.display(),
            dest_path.display()
        )
    })?;

    let metadata = MetadataCommand::new()
        .current_dir(&workspace_root)
        .exec()
        .context("failed to query cargo metadata")?;
    let version = resolve_package_version(&metadata, PACKAGE_NAME)?;

    let sha256 = sha256_file(&dest_path)?;
    let manifest = Manifest {
        package: PACKAGE_NAME.to_string(),
        version,
        kernel_min: None,
        generated_at: None,
        target: Some(TARGET.to_string()),
        artifacts: vec![ManifestArtifact {
            architecture: arch.to_string(),
            file: dest_rel_path.clone(),
            sha256,
        }],
    };

    let manifest_path = prebuilt_dir.join("manifest.json");
    let manifest_json =
        serde_json::to_vec_pretty(&manifest).context("failed to serialize manifest")?;
    fs::write(&manifest_path, manifest_json).context("failed to write prebuilt manifest.json")?;

    let tarball_path = workspace_root.join("prebuilt.tar.gz");
    create_tarball(
        &prebuilt_dir,
        &tarball_path,
        [manifest_path.as_path(), dest_path.as_path()],
    )
    .context("failed to build prebuilt.tar.gz")?;

    println!(
        "BPF artifacts ready: {} and {}",
        tarball_path.display(),
        manifest_path.display()
    );
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
