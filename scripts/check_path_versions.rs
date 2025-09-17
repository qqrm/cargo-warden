#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! cargo_metadata = "0.18"
//! toml = { version = "0.8", default-features = false, features = ["parse"] }
//! ```

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cargo_metadata::{MetadataCommand, PackageId};
use toml::value::Table;
use toml::Value;

#[derive(Debug)]
struct Problem {
    manifest: PathBuf,
    dependency: String,
    target: Option<String>,
    path_value: String,
}

impl Problem {
    fn render(&self, root: &Path) -> String {
        let relative = self
            .manifest
            .strip_prefix(root)
            .unwrap_or(self.manifest.as_path());
        let mut location = relative.display().to_string();
        if let Some(target) = &self.target {
            location = format!("{location} ({target})");
        }
        format!(
            "{location}: dependency '{}' uses path '{}' without a version",
            self.dependency, self.path_value
        )
    }
}

fn main() {
    match run() {
        Ok((root, problems)) => {
            if problems.is_empty() {
                return;
            }
            for problem in &problems {
                eprintln!("{}", problem.render(&root));
            }
            eprintln!("error: add an explicit version alongside each path dependency");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(PathBuf, Vec<Problem>)> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("failed to invoke `cargo metadata`")?;

    let root = metadata.workspace_root.into_std_path_buf();
    let workspace_members: HashSet<PackageId> =
        metadata.workspace_members.iter().cloned().collect();

    let mut problems = Vec::new();
    for package in metadata.packages {
        if !workspace_members.contains(&package.id) {
            continue;
        }
        let manifest_path = package.manifest_path.into_std_path_buf();
        problems.extend(collect_problems(&manifest_path)?);
    }

    Ok((root, problems))
}

fn collect_problems(manifest_path: &Path) -> Result<Vec<Problem>> {
    let contents = fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let parsed: Value = toml::from_str(&contents)
        .with_context(|| format!("failed to parse {}", manifest_path.display()))?;
    let table = parsed
        .as_table()
        .context("manifest root is not a TOML table")?;

    let mut problems = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = table.get(section).and_then(Value::as_table) {
            check_dependency_table(deps, manifest_path, None, &mut problems);
        }
    }

    if let Some(targets) = table.get("target").and_then(Value::as_table) {
        for (target_name, target_table) in targets {
            if let Some(target_table) = target_table.as_table() {
                for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(deps) = target_table.get(section).and_then(Value::as_table) {
                        check_dependency_table(
                            deps,
                            manifest_path,
                            Some(target_name.as_str()),
                            &mut problems,
                        );
                    }
                }
            }
        }
    }

    Ok(problems)
}

fn check_dependency_table(
    table: &Table,
    manifest_path: &Path,
    target: Option<&str>,
    problems: &mut Vec<Problem>,
) {
    for (name, spec) in table {
        let Some(spec_table) = spec.as_table() else {
            continue;
        };
        if !spec_table.contains_key("path") || spec_table.contains_key("version") {
            continue;
        }

        let path_value = spec_table
            .get("path")
            .map(value_to_string)
            .unwrap_or_else(|| "<unknown>".to_string());

        problems.push(Problem {
            manifest: manifest_path.to_owned(),
            dependency: name.clone(),
            target: target.map(|t| t.to_string()),
            path_value,
        });
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
   }
}
