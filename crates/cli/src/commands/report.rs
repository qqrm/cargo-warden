use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use event_reporting::EventRecord;
use event_reporting::export_sarif;
use serde::Serialize;

use crate::commands::read_recent_events;

const DEFAULT_SARIF_OUTPUT: &str = "warden.sarif";
const EVENTS_LOG: &str = "warden-events.jsonl";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReportFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
struct UnitStatistics {
    allowed: usize,
    denied: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
struct ReportStatistics {
    allowed: usize,
    denied: usize,
    per_unit: BTreeMap<u8, UnitStatistics>,
}

impl ReportStatistics {
    fn from_events(events: &[EventRecord]) -> Self {
        let mut stats = Self::default();
        for event in events {
            match event.verdict {
                0 => {
                    stats.allowed += 1;
                    stats.per_unit.entry(event.unit).or_default().allowed += 1;
                }
                1 => {
                    stats.denied += 1;
                    stats.per_unit.entry(event.unit).or_default().denied += 1;
                }
                _ => {}
            }
        }
        stats
    }
}

pub(crate) fn exec(format: ReportFormat, output: Option<&str>) -> io::Result<()> {
    let events = read_recent_events(Path::new(EVENTS_LOG), usize::MAX)?;
    let stats = match format {
        ReportFormat::Sarif => None,
        _ => Some(ReportStatistics::from_events(&events)),
    };

    match format {
        ReportFormat::Text => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            export_text(&events, stats.as_ref().unwrap(), &mut handle)
        }
        ReportFormat::Json => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            export_json(&events, stats.as_ref().unwrap(), &mut handle)
        }
        ReportFormat::Sarif => {
            let path = Path::new(output.unwrap_or(DEFAULT_SARIF_OUTPUT));
            export_sarif(&events, path)
        }
    }
}

fn export_text<W: Write>(
    events: &[EventRecord],
    stats: &ReportStatistics,
    writer: &mut W,
) -> io::Result<()> {
    writeln!(writer, "Allowed events: {}", stats.allowed)?;
    writeln!(writer, "Denied events: {}", stats.denied)?;
    writeln!(writer, "Per-unit breakdown:")?;
    for (unit, unit_stats) in &stats.per_unit {
        writeln!(
            writer,
            "  unit {}: allowed={}, denied={}",
            unit, unit_stats.allowed, unit_stats.denied
        )?;
    }
    writeln!(writer)?;
    for event in events {
        writeln!(writer, "{event}")?;
    }
    Ok(())
}

fn export_json<W: Write>(
    events: &[EventRecord],
    stats: &ReportStatistics,
    writer: &mut W,
) -> io::Result<()> {
    #[derive(Serialize)]
    struct JsonReport<'a> {
        stats: &'a ReportStatistics,
        events: &'a [EventRecord],
    }

    let report = JsonReport { stats, events };
    serde_json::to_writer(&mut *writer, &report).map_err(io::Error::other)?;
    writeln!(writer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn exports_sarif_file() {
        let record = event_reporting::EventRecord {
            pid: 2,
            unit: 0,
            action: 3,
            verdict: 1,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bad".into(),
        };
        let tmp = NamedTempFile::new().unwrap();
        export_sarif(std::slice::from_ref(&record), tmp.path()).unwrap();
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(content.contains("\"version\": \"2.1.0\""));
        assert!(content.contains(&record.path_or_addr));
    }

    #[test]
    #[serial_test::serial]
    fn report_creates_empty_file() {
        let dir = tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        File::create("warden-events.jsonl").unwrap();
        exec(ReportFormat::Sarif, Some("out.sarif")).unwrap();
        assert!(dir.path().join("out.sarif").exists());
    }

    #[test]
    fn report_defaults_sarif_output_path() {
        let dir = tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        File::create("warden-events.jsonl").unwrap();
        exec(ReportFormat::Sarif, None).unwrap();
        assert!(dir.path().join("warden.sarif").exists());
    }

    #[test]
    fn text_exporter_includes_statistics() {
        let events = vec![
            EventRecord {
                pid: 1,
                unit: 0,
                action: 2,
                verdict: 0,
                container_id: 3,
                caps: 4,
                path_or_addr: "/bin/allow".into(),
            },
            EventRecord {
                pid: 2,
                unit: 0,
                action: 5,
                verdict: 1,
                container_id: 7,
                caps: 8,
                path_or_addr: "/bin/deny".into(),
            },
            EventRecord {
                pid: 3,
                unit: 1,
                action: 9,
                verdict: 1,
                container_id: 11,
                caps: 12,
                path_or_addr: "10.0.0.1:80".into(),
            },
        ];
        let stats = ReportStatistics::from_events(&events);
        let mut buffer = Vec::new();
        export_text(&events, &stats, &mut buffer).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "Allowed events: 1\n".to_string()
                + "Denied events: 2\n"
                + "Per-unit breakdown:\n"
                + "  unit 0: allowed=1, denied=1\n"
                + "  unit 1: allowed=0, denied=1\n"
                + "\n"
                + "pid=1 unit=0 action=2 verdict=0 container_id=3 caps=4 path_or_addr=/bin/allow\n"
                + "pid=2 unit=0 action=5 verdict=1 container_id=7 caps=8 path_or_addr=/bin/deny\n"
                + "pid=3 unit=1 action=9 verdict=1 container_id=11 caps=12 path_or_addr=10.0.0.1:80\n",
        );
    }

    #[test]
    fn json_exporter_emits_statistics() {
        let events = vec![
            EventRecord {
                pid: 5,
                unit: 2,
                action: 9,
                verdict: 0,
                container_id: 8,
                caps: 16,
                path_or_addr: "127.0.0.1:80".into(),
            },
            EventRecord {
                pid: 6,
                unit: 2,
                action: 10,
                verdict: 1,
                container_id: 9,
                caps: 32,
                path_or_addr: "192.168.0.1:53".into(),
            },
        ];
        let stats = ReportStatistics::from_events(&events);
        let mut buffer = Vec::new();
        export_json(&events, &stats, &mut buffer).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buffer).unwrap();

        assert_eq!(json["stats"]["allowed"], 1);
        assert_eq!(json["stats"]["denied"], 1);
        assert_eq!(
            json["stats"]["per_unit"]["2"]["allowed"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            json["stats"]["per_unit"]["2"]["denied"],
            serde_json::Value::from(1)
        );

        assert_eq!(json["events"].as_array().unwrap().len(), 2);
        assert_eq!(json["events"][0]["pid"], 5);
        assert_eq!(json["events"][1]["pid"], 6);
    }
}
