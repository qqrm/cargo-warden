use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use std::io;
use std::path::Path;

/// User-facing representation of an event emitted by the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub pid: u32,
    pub unit: u8,
    pub action: u8,
    pub verdict: u8,
    pub container_id: u64,
    pub caps: u64,
    pub path_or_addr: String,
}

impl fmt::Display for EventRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pid={} unit={} action={} verdict={} container_id={} caps={} path_or_addr={}",
            self.pid,
            self.unit,
            self.action,
            self.verdict,
            self.container_id,
            self.caps,
            self.path_or_addr
        )
    }
}

/// Builds a SARIF log from a slice of events.
pub fn sarif_from_events(events: &[EventRecord]) -> serde_json::Value {
    let results: Vec<_> = events
        .iter()
        .map(|e| {
            json!({
                "ruleId": e.action.to_string(),
                "level": if e.verdict == 1 { "error" } else { "note" },
                "message": { "text": format!("{}", e) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": e.path_or_addr }
                    }
                }]
            })
        })
        .collect();
    json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "cargo-warden" } },
            "results": results
        }]
    })
}

/// Writes a SARIF log to the given path.
pub fn export_sarif(events: &[EventRecord], path: &Path) -> io::Result<()> {
    let sarif = sarif_from_events(events);
    let content = serde_json::to_string_pretty(&sarif).map_err(io::Error::other)?;
    std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn sarif_contains_events() {
        let records = vec![EventRecord {
            pid: 42,
            unit: 1,
            action: 3,
            verdict: 1,
            container_id: 99,
            caps: 0,
            path_or_addr: "/bin/deny".into(),
        }];
        let sarif = sarif_from_events(&records);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn export_writes_file() {
        let record = EventRecord {
            pid: 7,
            unit: 1,
            action: 3,
            verdict: 1,
            container_id: 5,
            caps: 0,
            path_or_addr: "/bin/bad".into(),
        };
        let tmp = NamedTempFile::new().unwrap();
        export_sarif(std::slice::from_ref(&record), tmp.path()).unwrap();

        let mut content = String::new();
        File::open(tmp.path())
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("\"version\": \"2.1.0\""));
        assert!(content.contains(&record.path_or_addr));
    }
}
