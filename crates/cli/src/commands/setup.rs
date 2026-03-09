use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use bpf_host::prebuilt::{PrebuiltObject, default_install_dir, default_search_directories};
use flate2::read::GzDecoder;
use tar::Archive;

pub(crate) struct SetupArgs {
    pub(crate) bundle: Option<PathBuf>,
    pub(crate) dest: Option<PathBuf>,
    pub(crate) force: bool,
}

pub(crate) fn exec(args: SetupArgs) -> io::Result<()> {
    if let Ok(obj) = PrebuiltObject::locate_default() {
        if args.bundle.is_none() {
            println!(
                "bpf bundle already installed: version={} path={}",
                obj.version(),
                obj.path().display()
            );
            return Ok(());
        }
        if !args.force {
            println!(
                "bpf bundle already installed (version={} path={}); re-run with --force to reinstall",
                obj.version(),
                obj.path().display()
            );
            return Ok(());
        }
    }

    let bundle = args.bundle.ok_or_else(|| {
        let mut msg = String::from(
            "missing --bundle <FILE>; download prebuilt.tar.gz and pass it here. searched:\n",
        );
        for dir in default_search_directories() {
            msg.push_str("  - ");
            msg.push_str(&dir.display().to_string());
            msg.push('\n');
        }
        io::Error::new(io::ErrorKind::InvalidInput, msg)
    })?;

    let dest = match args.dest {
        Some(dest) => dest,
        None => default_install_dir().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "could not determine XDG data home (HOME/XDG_DATA_HOME missing); provide --dest",
            )
        })?,
    };

    install_bundle(&bundle, &dest, args.force)
}

fn install_bundle(bundle: &Path, dest: &Path, force: bool) -> io::Result<()> {
    let parent = dest.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid destination {}", dest.display()),
        )
    })?;
    fs::create_dir_all(parent)?;

    if dest.exists() {
        if !force {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "destination {} already exists; re-run with --force to replace",
                    dest.display()
                ),
            ));
        }
        fs::remove_dir_all(dest)?;
    }

    let tmp = tempfile::Builder::new()
        .prefix("cargo-warden-bpf-")
        .tempdir_in(parent)?;

    extract_tar_gz(bundle, tmp.path())?;

    // Validate manifest + object checksum before installing.
    let obj = PrebuiltObject::from_directory(tmp.path())?;

    let extracted = tmp.into_path();
    fs::rename(&extracted, dest)?;

    println!(
        "installed bpf bundle: version={} dest={} object={}",
        obj.version(),
        dest.display(),
        obj.path().display()
    );

    Ok(())
}

fn extract_tar_gz(bundle: &Path, out_dir: &Path) -> io::Result<()> {
    let file = fs::File::open(bundle)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        ensure_safe_path(&path).map_err(|reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bundle contains unsafe path {}: {reason}", path.display()),
            )
        })?;
        entry.unpack_in(out_dir)?;
    }

    Ok(())
}

fn ensure_safe_path(path: &Path) -> Result<(), &'static str> {
    if path.is_absolute() {
        return Err("absolute path is not allowed");
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err("path traversal is not allowed");
    }
    Ok(())
}
