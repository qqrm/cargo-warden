use std::ffi::{OsStr, OsString};

use bpf_api::{UNIT_BUILD_SCRIPT, UNIT_LINKER, UNIT_OTHER, UNIT_PROC_MACRO, UNIT_RUSTC};
use unicase::UniCase;

pub(crate) fn detect_program_unit(program: &OsStr, args: &[OsString]) -> u32 {
    let program_str = program.to_string_lossy();
    let arg_storage: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let arg_refs: Vec<&str> = arg_storage.iter().map(|s| s.as_str()).collect();
    classify_path(program_str.as_ref(), &arg_refs)
}

fn classify_path(path: &str, args: &[&str]) -> u32 {
    let filename = filename_from_path(path);
    if is_build_script(path, filename) {
        return UNIT_BUILD_SCRIPT;
    }
    if is_linker(filename) {
        return UNIT_LINKER;
    }
    if is_rustc(filename) {
        if args_include_proc_macro(args) {
            return UNIT_PROC_MACRO;
        }
        return UNIT_RUSTC;
    }
    if is_cargo(filename) {
        return UNIT_OTHER;
    }
    UNIT_OTHER
}

fn filename_from_path(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn is_build_script(path: &str, filename: &str) -> bool {
    let lower_file = filename.to_ascii_lowercase();
    if lower_file.contains("build-script") {
        return true;
    }
    let lower_path = path.to_ascii_lowercase();
    lower_path.contains("/build-script-") || lower_path.contains("\\build-script-")
}

fn is_rustc(filename: &str) -> bool {
    matches_ignore_case(filename, "rustc") || matches_ignore_case(filename, "rustc.exe")
}

fn is_cargo(filename: &str) -> bool {
    matches_ignore_case(filename, "cargo") || matches_ignore_case(filename, "cargo.exe")
}

fn is_linker(filename: &str) -> bool {
    const LINKERS: [&str; 12] = [
        "ld", "ld.lld", "ld64", "lld", "link", "link.exe", "cc", "clang", "clang++", "gcc", "g++",
        "collect2",
    ];
    LINKERS
        .iter()
        .any(|candidate| matches_ignore_case(filename, candidate))
}

fn matches_ignore_case(input: &str, expected: &str) -> bool {
    UniCase::new(input) == UniCase::new(expected)
}

fn args_include_proc_macro(args: &[&str]) -> bool {
    let crate_type_flag = UniCase::new("--crate-type");
    let proc_macro = "proc-macro";

    let inline = args.iter().any(|arg| {
        arg.split_once('=')
            .filter(|(flag, _)| UniCase::new(*flag) == crate_type_flag)
            .map(|(_, value)| contains_proc_macro(value, proc_macro))
            .unwrap_or(false)
    });

    inline
        || args.windows(2).any(|window| {
            UniCase::new(window[0]) == crate_type_flag && contains_proc_macro(window[1], proc_macro)
        })
}

fn contains_proc_macro(value: &str, needle: &str) -> bool {
    value
        .split(',')
        .any(|entry| matches_ignore_case(entry.trim(), needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os_strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn detects_rustc_variants() {
        let args = os_strings(&["--crate-type", "proc-macro"]);
        assert_eq!(
            detect_program_unit(OsStr::new("rustc"), &args),
            UNIT_PROC_MACRO
        );
        let other = os_strings(&["--crate-name", "example"]);
        assert_eq!(detect_program_unit(OsStr::new("rustc"), &other), UNIT_RUSTC);
    }

    #[test]
    fn detects_build_script() {
        let path = OsStr::new("/workspace/target/debug/build/foo-123/build-script-build");
        assert_eq!(detect_program_unit(path, &[]), UNIT_BUILD_SCRIPT);
    }

    #[test]
    fn detects_linker() {
        assert_eq!(detect_program_unit(OsStr::new("ld"), &[]), UNIT_LINKER);
        assert_eq!(
            detect_program_unit(OsStr::new("link.exe"), &[]),
            UNIT_LINKER
        );
    }

    #[test]
    fn cargo_defaults_to_other() {
        assert_eq!(detect_program_unit(OsStr::new("cargo"), &[]), UNIT_OTHER);
    }
}
