use std::io;
use std::path::Path;

use crate::commands::read_recent_events;

pub(crate) fn exec() -> io::Result<()> {
    let policy_path = Path::new("warden.toml");
    if policy_path.exists() {
        println!("active policy: {}", policy_path.display());
    } else {
        println!("active policy: none");
    }
    let events = read_recent_events(Path::new("warden-events.jsonl"), 10)?;
    if events.skipped_lines > 0 {
        if let Some(err) = events.last_error.as_deref() {
            eprintln!(
                "warning: skipped {} malformed event log line(s): {err}",
                events.skipped_lines
            );
        } else {
            eprintln!(
                "warning: skipped {} malformed event log line(s)",
                events.skipped_lines
            );
        }
    }
    if events.is_empty() {
        println!("recent events: none");
    } else {
        println!("recent events:");
        for e in events.events {
            println!("{}", e);
        }
    }
    Ok(())
}
