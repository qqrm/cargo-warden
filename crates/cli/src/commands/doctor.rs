use std::fs;
use std::io;
use std::path::Path;

use bpf_host::prebuilt::{PrebuiltObject, default_search_directories};

use crate::privileges;

const MIN_KERNEL_MAJOR: u64 = 5;
const MIN_KERNEL_MINOR: u64 = 13;

pub(crate) fn exec() -> io::Result<()> {
    println!("cargo-warden doctor");

    check_kernel()?;
    check_bpf_lsm()?;
    check_cgroup_v2()?;
    check_prebuilt()?;
    check_privileges()?;

    Ok(())
}

fn check_kernel() -> io::Result<()> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| String::new())
        .trim()
        .to_string();

    let parsed = parse_kernel_release(&release);

    match parsed {
        Some((major, minor))
            if (major > MIN_KERNEL_MAJOR)
                || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR) =>
        {
            println!("kernel: OK ({release})");
        }
        Some((major, minor)) => {
            println!(
                "kernel: FAIL ({release}); need >= {MIN_KERNEL_MAJOR}.{MIN_KERNEL_MINOR} (found {major}.{minor})"
            );
        }
        None if !release.is_empty() => {
            println!("kernel: WARN ({release}); could not parse, expected leading MAJOR.MINOR");
        }
        None => {
            println!("kernel: WARN (unknown); could not read /proc/sys/kernel/osrelease");
        }
    }

    Ok(())
}

fn parse_kernel_release(release: &str) -> Option<(u64, u64)> {
    let mut split = release.split(|c: char| !c.is_ascii_digit() && c != '.');
    let first = split.next()?;
    let mut nums = first.split('.');
    let major = nums.next()?.parse().ok()?;
    let minor = nums.next()?.parse().ok()?;
    Some((major, minor))
}

fn check_bpf_lsm() -> io::Result<()> {
    let path = Path::new("/sys/kernel/security/lsm");
    match fs::read_to_string(path) {
        Ok(contents) => {
            let has = contents
                .split(|c: char| c.is_ascii_whitespace() || c == ',')
                .any(|part| part.trim() == "bpf");
            if has {
                println!("bpf_lsm: OK");
            } else {
                println!("bpf_lsm: FAIL (bpf not present in /sys/kernel/security/lsm)");
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            println!("bpf_lsm: WARN (/sys/kernel/security/lsm not found)");
        }
        Err(err) => {
            println!("bpf_lsm: WARN (failed to read /sys/kernel/security/lsm: {err})");
        }
    }
    Ok(())
}

fn check_cgroup_v2() -> io::Result<()> {
    let controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if controllers.exists() {
        println!("cgroup_v2: OK");
    } else {
        println!("cgroup_v2: FAIL (/sys/fs/cgroup/cgroup.controllers missing; need cgroup v2)");
    }
    Ok(())
}

fn check_prebuilt() -> io::Result<()> {
    match PrebuiltObject::locate_default() {
        Ok(obj) => {
            let path = obj.path();
            let mut extra = Vec::new();
            if let Some(min) = obj.kernel_min() {
                extra.push(format!("kernel_min={min}"));
            }
            if let Some(ts) = obj.generated_at() {
                extra.push(format!("generated_at={ts}"));
            }
            let extra = if extra.is_empty() {
                String::new()
            } else {
                format!(" ({})", extra.join(", "))
            };
            println!(
                "bpf_prebuilt: OK (version={} path={}){extra}",
                obj.version(),
                path.display(),
            );
        }
        Err(err) => {
            println!("bpf_prebuilt: FAIL ({err})");
            let dirs = default_search_directories();
            if !dirs.is_empty() {
                println!("bpf_prebuilt: searched:");
                for dir in dirs {
                    println!("  - {}", dir.display());
                }
                println!(
                    "bpf_prebuilt: next: download prebuilt.tar.gz and run `cargo warden setup --bundle prebuilt.tar.gz`"
                );
            }
        }
    }
    Ok(())
}

fn check_privileges() -> io::Result<()> {
    if privileges::is_privilege_check_skipped() {
        println!("privileges: WARN (CARGO_WARDEN_SKIP_PRIVILEGE_CHECK set; enforcement disabled)");
        return Ok(());
    }

    match privileges::is_isolated() {
        Ok(true) => println!("isolation: OK (container/VM markers detected)"),
        Ok(false) => {
            println!("isolation: FAIL (no container/VM markers detected)");
            println!(
                "isolation: next: run inside a dedicated container/VM with its own network namespace"
            );
        }
        Err(err) => println!("isolation: WARN ({err})"),
    }

    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        println!("euid: FAIL (running as root; cargo-warden rejects root)");
    } else {
        println!("euid: OK ({euid})");
    }

    match privileges::effective_capabilities() {
        Ok(caps) => {
            let required = privileges::required_cap_mask();
            let allowed = privileges::allowed_cap_mask();
            let missing = required & !caps;
            let extra = caps & !allowed;

            if missing != 0 {
                println!(
                    "caps: FAIL (missing: {}; effective: {})",
                    privileges::describe_cap_mask(missing),
                    privileges::describe_cap_mask(caps)
                );
            } else if extra != 0 {
                println!(
                    "caps: FAIL (extra: {}; effective: {})",
                    privileges::describe_cap_mask(extra),
                    privileges::describe_cap_mask(caps)
                );
            } else {
                println!(
                    "caps: OK (effective: {}; allowed: {})",
                    privileges::describe_cap_mask(caps),
                    privileges::describe_cap_mask(allowed)
                );
            }
        }
        Err(err) => {
            println!("caps: WARN ({err})");
        }
    }

    Ok(())
}
