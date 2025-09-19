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
