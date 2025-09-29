use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

use event_reporting::EventRecord;
use serde_jsonlines::JsonLinesReader;

#[derive(Debug, Default)]
pub(crate) struct ReadEventsResult {
    pub(crate) events: Vec<EventRecord>,
    pub(crate) skipped: usize,
}

pub(crate) fn read_recent_events(path: &Path, limit: usize) -> io::Result<ReadEventsResult> {
    if limit == 0 || !path.exists() {
        return Ok(ReadEventsResult::default());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = VecDeque::new();
    let mut skipped = 0usize;

    for record in JsonLinesReader::new(reader).read_all::<EventRecord>() {
        match record {
            Ok(event) => {
                if events.len() == limit {
                    events.pop_front();
                }
                events.push_back(event);
            }
            Err(err) if is_deserialization_error(&err) => {
                skipped += 1;
            }
            Err(err) => return Err(err),
        }
    }

    if skipped > 0 {
        eprintln!(
            "warning: skipped {skipped} malformed events from {}",
            path.display()
        );
    }

    Ok(ReadEventsResult {
        events: events.into_iter().collect(),
        skipped,
    })
}

fn is_deserialization_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::InvalidData
        && err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<serde_json::Error>())
            .is_some()
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
        assert_eq!(events.events.len(), 2);
        assert_eq!(events.events[0].pid, 1);
        assert_eq!(events.events[1].verdict, 1);
        assert_eq!(events.skipped, 0);
    }

    #[test]
    fn read_recent_events_limits_output() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut file = File::create(&path).unwrap();

        for idx in 0..5 {
            writeln!(
                file,
                "{}",
                serde_json::json!({
                    "pid": idx,
                    "tgid": idx * 10,
                    "time_ns": idx * 1000,
                    "unit": 0,
                    "action": 3,
                    "verdict": 0,
                    "container_id": 0,
                    "caps": 0,
                    "path_or_addr": format!("/bin/cmd{idx}"),
                    "needed_perm": ""
                })
            )
            .unwrap();
        }

        let events = read_recent_events(&path, 2).unwrap();
        assert_eq!(events.events.len(), 2);
        assert_eq!(events.events[0].pid, 3);
        assert_eq!(events.events[1].pid, 4);
        assert_eq!(events.skipped, 0);
    }

    #[test]
    fn read_recent_events_zero_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut file = File::create(&path).unwrap();

        writeln!(
            file,
            "{}",
            serde_json::json!({
                "pid": 1,
                "tgid": 1,
                "time_ns": 1,
                "unit": 0,
                "action": 1,
                "verdict": 0,
                "container_id": 0,
                "caps": 0,
                "path_or_addr": "/bin/echo",
                "needed_perm": ""
            })
        )
        .unwrap();

        let events = read_recent_events(&path, 0).unwrap();
        assert!(events.events.is_empty());
        assert_eq!(events.skipped, 0);
    }

    #[test]
    fn read_recent_events_counts_failures() {
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
        writeln!(file, "{{ not-json }}").unwrap();

        let events = read_recent_events(&path, 10).unwrap();
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.skipped, 1);
    }
}
