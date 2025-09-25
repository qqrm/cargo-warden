use std::io;
use std::path::Path;

use crate::commands::read_recent_events;
use crate::policy::{PolicySource, PolicySourceKind, collect_policy_status};
use policy_core::Mode;

pub(crate) fn exec(policy_paths: &[String], mode_override: Option<Mode>) -> io::Result<()> {
    let policy_status = collect_policy_status(policy_paths, mode_override)?;
    print_policy_sources(&policy_status.sources);
    println!(
        "effective mode: {}",
        mode_to_str(policy_status.effective_mode)
    );
    let events = read_recent_events(Path::new("warden-events.jsonl"), 10)?;
    if events.is_empty() {
        println!("recent events: none");
    } else {
        println!("recent events:");
        for e in events {
            println!("{}", e);
        }
    }
    Ok(())
}

fn print_policy_sources(sources: &[PolicySource]) {
    if sources.is_empty() {
        println!("policy sources: none");
        return;
    }
    println!("policy sources:");
    for source in sources {
        match &source.kind {
            PolicySourceKind::Workspace { path, member } => {
                if let Some(member) = member {
                    println!(
                        "- workspace policy: {} (member: {}) [mode: {}]",
                        path.display(),
                        member,
                        mode_to_str(source.mode)
                    );
                } else {
                    println!(
                        "- workspace policy: {} [mode: {}]",
                        path.display(),
                        mode_to_str(source.mode)
                    );
                }
            }
            PolicySourceKind::LocalFile { path } => {
                println!(
                    "- local policy: {} [mode: {}]",
                    path.display(),
                    mode_to_str(source.mode)
                );
            }
            PolicySourceKind::CliFile { path } => {
                println!(
                    "- CLI policy: {} [mode: {}]",
                    path.display(),
                    mode_to_str(source.mode)
                );
            }
            PolicySourceKind::DefaultEmpty => {
                println!("- built-in defaults [mode: {}]", mode_to_str(source.mode));
            }
            PolicySourceKind::ModeOverride => {
                println!("- CLI mode override [mode: {}]", mode_to_str(source.mode));
            }
        }
    }
}

fn mode_to_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
    }
}
