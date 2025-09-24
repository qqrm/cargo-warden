use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use event_reporting::EventRecord;

pub(crate) fn read_recent_events(path: &Path, limit: usize) -> io::Result<Vec<EventRecord>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
    let start = lines.len().saturating_sub(limit);
    let mut events = Vec::new();
    for line in &lines[start..] {
        if let Ok(ev) = serde_json::from_str::<EventRecord>(line) {
            events.push(ev);
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::tempdir;

    #[test]
    fn read_recent_events_reads_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut file = File::create(&path).unwrap();
        writeln!(
            file,
            "{}",
            serde_json::json!({
                "pid": 1,
                "tgid": 10,
                "time_ns": 1000,
                "unit": 0,
                "action": 3,
                "verdict": 0,
                "container_id": 0,
                "caps": 0,
                "path_or_addr": "/bin/echo",
                "needed_perm": ""
            })
        )
        .unwrap();
        writeln!(
            file,
            "{}",
            serde_json::json!({
                "pid": 2,
                "tgid": 20,
                "time_ns": 2000,
                "unit": 0,
                "action": 4,
                "verdict": 1,
                "container_id": 0,
                "caps": 0,
                "path_or_addr": "1.2.3.4:80",
                "needed_perm": "allow.net.hosts"
            })
        )
        .unwrap();
        let events = read_recent_events(&path, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pid, 1);
        assert_eq!(events[1].verdict, 1);
    }
}
