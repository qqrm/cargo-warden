//! Utilities for locating and verifying prebuilt warden-bpf-core objects.

use sha2::{Digest, Sha256};
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

const MANIFEST_NAME: &str = "manifest.json";
const DEFAULT_RELATIVE_DIR: &str = "../../prebuilt";
const SHARE_DIR: &str = "/usr/share/cargo-warden/bpf";
const XDG_SUBDIR: &str = "cargo-warden/bpf";
const EXPECTED_PACKAGE: &str = "warden-bpf-core";
const EXPECTED_TARGET: &str = "bpfel-unknown-none";

/// Description of a prebuilt artifact bundle.
#[derive(Debug, Deserialize)]
struct Manifest {
    package: String,
    version: String,
    #[serde(default)]
    kernel_min: Option<String>,
    #[serde(default)]
    generated_at: Option<String>,
    artifacts: Vec<ManifestArtifact>,
    #[serde(default)]
    target: Option<String>,
}

/// Single architecture entry within the manifest.
#[derive(Clone, Debug, Deserialize)]
struct ManifestArtifact {
    architecture: String,
    file: PathBuf,
    sha256: String,
}

impl Manifest {
    fn artifact_for_arch(&self, arch: &str) -> Option<&ManifestArtifact> {
        self.artifacts
            .iter()
            .find(|entry| entry.architecture == arch)
    }
}

/// Fully qualified prebuilt object validated against the manifest checksum.
pub struct PrebuiltObject {
    base_dir: PathBuf,
    artifact: ManifestArtifact,
    version: String,
    target: Option<String>,
    kernel_min: Option<String>,
    generated_at: Option<String>,
}

impl fmt::Debug for PrebuiltObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrebuiltObject")
            .field("base_dir", &self.base_dir)
            .field("artifact", &self.artifact)
            .finish()
    }
}

impl PrebuiltObject {
    /// Loads and validates a prebuilt object from the provided directory.
    pub fn from_directory<P: AsRef<Path>>(dir: P) -> io::Result<Self> {
        let dir = dir.as_ref();
        let manifest_path = dir.join(MANIFEST_NAME);
        let manifest_bytes = fs::read(&manifest_path).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to read prebuilt manifest {}: {err}",
                    manifest_path.display()
                ),
            )
        })?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|err| {
            io::Error::other(format!(
                "failed to parse prebuilt manifest {}: {err}",
                manifest_path.display()
            ))
        })?;

        if manifest.package != EXPECTED_PACKAGE {
            return Err(io::Error::other(format!(
                "prebuilt manifest {} references unexpected package {}",
                manifest_path.display(),
                manifest.package,
            )));
        }

        if let Some(target) = &manifest.target
            && target != EXPECTED_TARGET
        {
            return Err(io::Error::other(format!(
                "prebuilt manifest target {target} does not match {EXPECTED_TARGET}"
            )));
        }

        let arch = env::consts::ARCH;
        let artifact = manifest.artifact_for_arch(arch).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("prebuilt manifest does not contain architecture {arch}"),
            )
        })?;

        ensure_relative(&artifact.file).map_err(|err| {
            io::Error::other(format!(
                "manifest entry {} has invalid file path: {err}",
                artifact.file.display()
            ))
        })?;

        let object_path = dir.join(&artifact.file);
        let data = fs::read(&object_path).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to read prebuilt object {}: {err}",
                    object_path.display()
                ),
            )
        })?;
        let checksum = hex_digest(&data);
        if !constant_time_eq(&checksum, &artifact.sha256) {
            return Err(io::Error::other(format!(
                "checksum mismatch for {}: expected {}, found {}",
                object_path.display(),
                artifact.sha256,
                checksum
            )));
        }

        Ok(Self {
            base_dir: dir.to_path_buf(),
            artifact: artifact.clone(),
            version: manifest.version,
            target: manifest.target,
            kernel_min: manifest.kernel_min,
            generated_at: manifest.generated_at,
        })
    }

    /// Attempts to locate a prebuilt object using the default search paths.
    pub fn locate_default() -> io::Result<Self> {
        let mut errors = Vec::new();
        for candidate in candidate_directories() {
            match Self::from_directory(&candidate) {
                Ok(obj) => return Ok(obj),
                Err(err) => errors.push(format!("{}: {err}", candidate.display())),
            }
        }

        if errors.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no prebuilt directories configured",
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "failed to locate prebuilt artifacts; attempted:\n{}",
                    errors.join("\n")
                ),
            ))
        }
    }

    /// Returns the on-disk path to the validated object file.
    pub fn path(&self) -> PathBuf {
        self.base_dir.join(&self.artifact.file)
    }

    /// Reads the validated object bytes into memory.
    pub fn into_bytes(self) -> io::Result<Vec<u8>> {
        fs::read(self.path())
    }

    /// Returns the version recorded in the manifest.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the manifest target triple when present.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Returns the minimum supported kernel version, if recorded.
    pub fn kernel_min(&self) -> Option<&str> {
        self.kernel_min.as_deref()
    }

    /// Returns the manifest timestamp, if present.
    pub fn generated_at(&self) -> Option<&str> {
        self.generated_at.as_deref()
    }
}

fn candidate_directories() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(dir) = env::var_os("WARDEN_BPF_DIST_DIR") {
        candidates.push(PathBuf::from(dir));
    }

    if let Some(dir) = data_home().map(|home| home.join(XDG_SUBDIR)) {
        candidates.push(dir);
    }

    candidates.push(PathBuf::from(SHARE_DIR));
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_RELATIVE_DIR));

    candidates
}

fn data_home() -> Option<PathBuf> {
    if let Some(dir) = env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(dir));
    }

    env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
}

fn ensure_relative(path: &Path) -> Result<(), &'static str> {
    if path.is_absolute() {
        return Err("absolute path is not allowed");
    }

    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("path traversal is not allowed");
    }

    Ok(())
}

fn hex_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}")).expect("write to string");
    }
    hex
}

fn constant_time_eq(lhs: &str, rhs: &str) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }

    let mut result = 0u8;
    for (a, b) in lhs.bytes().zip(rhs.bytes()) {
        result |= a ^ b;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn loads_and_validates_object() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let arch = env::consts::ARCH;
        let rel_path = PathBuf::from(arch).join("warden-bpf-core.o");
        fs::create_dir_all(base.join(rel_path.parent().unwrap())).unwrap();
        fs::write(base.join(&rel_path), b"test-bytes").unwrap();

        let checksum = hex_digest(b"test-bytes");
        let manifest = format!(
            "{{\n  \"package\": \"warden-bpf-core\",\n  \"version\": \"0.1.0\",\n  \"artifacts\": [\n    {{\n      \"architecture\": \"{arch}\",\n      \"file\": \"{path}\",\n      \"sha256\": \"{checksum}\"\n    }}\n  ]\n}}\n",
            arch = arch,
            path = rel_path.to_string_lossy(),
            checksum = checksum,
        );
        fs::write(base.join(MANIFEST_NAME), manifest).unwrap();

        let object = PrebuiltObject::from_directory(base).unwrap();
        assert_eq!(object.path(), base.join(&rel_path));
        assert_eq!(object.into_bytes().unwrap(), b"test-bytes");
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let arch = env::consts::ARCH;
        let rel_path = PathBuf::from(arch).join("warden-bpf-core.o");
        fs::create_dir_all(base.join(rel_path.parent().unwrap())).unwrap();
        fs::write(base.join(&rel_path), b"actual").unwrap();

        let manifest = format!(
            "{{\n  \"package\": \"warden-bpf-core\",\n  \"version\": \"0.1.0\",\n  \"artifacts\": [\n    {{\n      \"architecture\": \"{arch}\",\n      \"file\": \"{path}\",\n      \"sha256\": \"deadbeef\"\n    }}\n  ]\n}}\n",
            arch = arch,
            path = rel_path.to_string_lossy(),
        );
        fs::write(base.join(MANIFEST_NAME), manifest).unwrap();

        let err = PrebuiltObject::from_directory(base).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn candidate_search_order() {
        unsafe {
            env::remove_var("WARDEN_BPF_DIST_DIR");
            env::remove_var("XDG_DATA_HOME");
            env::set_var("HOME", "/tmp/home");
        }
        let mut candidates = candidate_directories();
        assert!(candidates.pop().unwrap().ends_with(DEFAULT_RELATIVE_DIR));
        assert_eq!(candidates.pop().unwrap(), PathBuf::from(SHARE_DIR));
        assert_eq!(
            candidates.pop().unwrap(),
            PathBuf::from("/tmp/home/.local/share").join(XDG_SUBDIR)
        );
    }
}
