use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use event_reporting::EventRecord;

#[derive(Clone, Debug, Default)]
pub(crate) struct RecentEvents {
    pub events: Vec<EventRecord>,
    pub skipped_lines: usize,
    pub last_error: Option<String>,
}

impl RecentEvents {
    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

pub(crate) fn read_recent_events(path: &Path, limit: usize) -> io::Result<RecentEvents> {
    if limit == 0 || !path.exists() {
        return Ok(RecentEvents::default());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = VecDeque::new();
    let mut skipped_lines = 0usize;
    let mut last_error = None;

    for line in reader.lines() {
        let line = line?;
        match serde_json::from_str::<EventRecord>(&line) {
            Ok(event) => {
                if events.len() == limit {
                    events.pop_front();
                }
                events.push_back(event);
            }
            Err(err) => {
                skipped_lines += 1;
                last_error = Some(err.to_string());
            }
        }
    }

    Ok(RecentEvents {
        events: events.into_iter().collect(),
        skipped_lines,
        last_error,
    })
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
        assert!(events.is_empty());
    }

    #[test]
    fn read_recent_events_reports_parse_errors() {
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
        writeln!(file, "not json").unwrap();

        let events = read_recent_events(&path, 10).unwrap();
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.skipped_lines, 1);
        assert!(events.last_error.is_some());
    }
}
