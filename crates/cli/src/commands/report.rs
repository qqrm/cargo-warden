use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use event_reporting::{EventRecord, METRICS_SNAPSHOT_FILE, MetricsSnapshot, export_sarif};
use serde::Serialize;

use crate::commands::{ReadEventsResult, read_recent_events};

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
    per_unit: BTreeMap<u32, UnitStatistics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<MetricsSnapshot>,
    #[serde(default)]
    skipped_events: usize,
}

impl ReportStatistics {
    fn from_events(events: &[EventRecord]) -> Self {
        let mut stats = Self::default();
        for event in events {
            match event.verdict {
                0 => {
                    stats.allowed += 1;
                    stats
                        .per_unit
                        .entry(u32::from(event.unit))
                        .or_default()
                        .allowed += 1;
                }
                1 => {
                    stats.denied += 1;
                    stats
                        .per_unit
                        .entry(u32::from(event.unit))
                        .or_default()
                        .denied += 1;
                }
                _ => {}
            }
        }
        stats
    }
}

fn read_metrics_snapshot(path: &Path) -> io::Result<Option<MetricsSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(path)?;
    if data.is_empty() {
        return Ok(None);
    }
    match serde_json::from_slice(&data) {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(err) => {
            eprintln!(
                "warning: failed to parse metrics snapshot {}: {err}",
                path.display()
            );
            if let Err(remove_err) = std::fs::remove_file(path) {
                eprintln!(
                    "warning: could not remove corrupted metrics snapshot {}: {remove_err}",
                    path.display()
                );
            }
            Ok(None)
        }
    }
}

pub(crate) fn exec(format: ReportFormat, output: Option<&str>) -> io::Result<()> {
    let ReadEventsResult { events, skipped } =
        read_recent_events(Path::new(EVENTS_LOG), usize::MAX)?;
    let metrics = read_metrics_snapshot(Path::new(METRICS_SNAPSHOT_FILE))?;
    let stats = match format {
        ReportFormat::Sarif => None,
        _ => {
            let mut stats = ReportStatistics::from_events(&events);
            stats.metrics = metrics.clone();
            stats.skipped_events = skipped;
            Some(stats)
        }
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
    writeln!(writer, "Malformed events skipped: {}", stats.skipped_events)?;
    writeln!(writer, "Per-unit breakdown:")?;
    for (unit, unit_stats) in &stats.per_unit {
        writeln!(
            writer,
            "  unit {}: allowed={}, denied={}",
            unit, unit_stats.allowed, unit_stats.denied
        )?;
    }
    match &stats.metrics {
        Some(metrics) => {
            writeln!(writer, "Metrics snapshot:")?;
            writeln!(writer, "  allowed_total: {}", metrics.allowed_total)?;
            writeln!(writer, "  denied_total: {}", metrics.denied_total)?;
            writeln!(writer, "  violations_total: {}", metrics.violations_total)?;
            writeln!(writer, "  blocked_total: {}", metrics.blocked_total)?;
            writeln!(writer, "  Per-unit metrics:")?;
            for (unit, unit_metrics) in &metrics.per_unit {
                writeln!(writer, "    unit {}:", unit)?;
                writeln!(writer, "      allowed: {}", unit_metrics.allowed)?;
                writeln!(writer, "      denied: {}", unit_metrics.denied)?;
                writeln!(
                    writer,
                    "      io_read_bytes: {}",
                    unit_metrics.io_read_bytes
                )?;
                writeln!(
                    writer,
                    "      io_write_bytes: {}",
                    unit_metrics.io_write_bytes
                )?;
                writeln!(writer, "      cpu_time_ms: {}", unit_metrics.cpu_time_ms)?;
                writeln!(writer, "      page_faults: {}", unit_metrics.page_faults)?;
            }
        }
        None => {
            writeln!(writer, "Metrics snapshot unavailable.")?;
        }
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
            tgid: 4,
            time_ns: 500,
            unit: 0,
            action: 3,
            verdict: 1,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bad".into(),
            needed_perm: "allow.exec.allowed".into(),
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
    #[serial_test::serial]
    fn report_defaults_sarif_output_path() {
        let dir = tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        File::create("warden-events.jsonl").unwrap();
        exec(ReportFormat::Sarif, None).unwrap();
        assert!(dir.path().join("warden.sarif").exists());
    }

    #[test]
    #[serial_test::serial]
    fn read_metrics_snapshot_handles_corruption() {
        let dir = tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        std::fs::write(METRICS_SNAPSHOT_FILE, b"{ not json }").unwrap();
        let snapshot = read_metrics_snapshot(Path::new(METRICS_SNAPSHOT_FILE)).unwrap();
        assert!(snapshot.is_none());
        assert!(!dir.path().join(METRICS_SNAPSHOT_FILE).exists());
    }

    #[test]
    fn text_exporter_includes_statistics() {
        let events = vec![
            EventRecord {
                pid: 1,
                tgid: 10,
                time_ns: 100,
                unit: 0,
                action: 2,
                verdict: 0,
                container_id: 3,
                caps: 4,
                path_or_addr: "/bin/allow".into(),
                needed_perm: String::new(),
            },
            EventRecord {
                pid: 2,
                tgid: 20,
                time_ns: 200,
                unit: 0,
                action: 5,
                verdict: 1,
                container_id: 7,
                caps: 8,
                path_or_addr: "/bin/deny".into(),
                needed_perm: "allow.exec.allowed".into(),
            },
            EventRecord {
                pid: 3,
                tgid: 30,
                time_ns: 300,
                unit: 1,
                action: 9,
                verdict: 1,
                container_id: 11,
                caps: 12,
                path_or_addr: "10.0.0.1:80".into(),
                needed_perm: "allow.net.hosts".into(),
            },
        ];
        let mut stats = ReportStatistics::from_events(&events);
        let mut snapshot = MetricsSnapshot {
            allowed_total: 1,
            denied_total: 2,
            violations_total: 2,
            blocked_total: 2,
            ..Default::default()
        };
        snapshot.per_unit.insert(
            0,
            event_reporting::UnitMetricsSnapshot {
                allowed: 1,
                denied: 1,
                io_read_bytes: 64,
                io_write_bytes: 32,
                cpu_time_ms: 10,
                page_faults: 2,
            },
        );
        snapshot.per_unit.insert(
            1,
            event_reporting::UnitMetricsSnapshot {
                allowed: 0,
                denied: 1,
                io_read_bytes: 128,
                io_write_bytes: 256,
                cpu_time_ms: 20,
                page_faults: 3,
            },
        );
        stats.metrics = Some(snapshot);
        let mut buffer = Vec::new();
        export_text(&events, &stats, &mut buffer).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "Allowed events: 1\n".to_string()
                + "Denied events: 2\n"
                + "Malformed events skipped: 0\n"
                + "Per-unit breakdown:\n"
                + "  unit 0: allowed=1, denied=1\n"
                + "  unit 1: allowed=0, denied=1\n"
                + "Metrics snapshot:\n"
                + "  allowed_total: 1\n"
                + "  denied_total: 2\n"
                + "  violations_total: 2\n"
                + "  blocked_total: 2\n"
                + "  Per-unit metrics:\n"
                + "    unit 0:\n"
                + "      allowed: 1\n"
                + "      denied: 1\n"
                + "      io_read_bytes: 64\n"
                + "      io_write_bytes: 32\n"
                + "      cpu_time_ms: 10\n"
                + "      page_faults: 2\n"
                + "    unit 1:\n"
                + "      allowed: 0\n"
                + "      denied: 1\n"
                + "      io_read_bytes: 128\n"
                + "      io_write_bytes: 256\n"
                + "      cpu_time_ms: 20\n"
                + "      page_faults: 3\n"
                + "\n"
                + "pid=1 tgid=10 unit=0 action=2 verdict=0 time_ns=100 container_id=3 caps=4 needed_perm= path_or_addr=/bin/allow\n"
                + "pid=2 tgid=20 unit=0 action=5 verdict=1 time_ns=200 container_id=7 caps=8 needed_perm=allow.exec.allowed path_or_addr=/bin/deny hint=allow.exec.allowed\n"
                + "pid=3 tgid=30 unit=1 action=9 verdict=1 time_ns=300 container_id=11 caps=12 needed_perm=allow.net.hosts path_or_addr=10.0.0.1:80 hint=allow.net.hosts\n",
        );
    }

    #[test]
    fn json_exporter_emits_statistics() {
        let events = vec![
            EventRecord {
                pid: 5,
                tgid: 50,
                time_ns: 500,
                unit: 2,
                action: 9,
                verdict: 0,
                container_id: 8,
                caps: 16,
                path_or_addr: "127.0.0.1:80".into(),
                needed_perm: String::new(),
            },
            EventRecord {
                pid: 6,
                tgid: 60,
                time_ns: 600,
                unit: 2,
                action: 10,
                verdict: 1,
                container_id: 9,
                caps: 32,
                path_or_addr: "192.168.0.1:53".into(),
                needed_perm: "allow.net.hosts".into(),
            },
        ];
        let mut stats = ReportStatistics::from_events(&events);
        let mut snapshot = MetricsSnapshot {
            allowed_total: 1,
            denied_total: 1,
            violations_total: 1,
            blocked_total: 1,
            ..Default::default()
        };
        snapshot.per_unit.insert(
            2,
            event_reporting::UnitMetricsSnapshot {
                allowed: 1,
                denied: 1,
                io_read_bytes: 512,
                io_write_bytes: 1024,
                cpu_time_ms: 30,
                page_faults: 5,
            },
        );
        stats.metrics = Some(snapshot);
        let mut buffer = Vec::new();
        export_json(&events, &stats, &mut buffer).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buffer).unwrap();

        assert_eq!(json["stats"]["allowed"], 1);
        assert_eq!(json["stats"]["denied"], 1);
        assert_eq!(json["stats"]["skipped_events"], 0);
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
        assert_eq!(json["events"][0]["tgid"], 50);
        assert_eq!(json["events"][1]["pid"], 6);
        assert_eq!(json["events"][1]["needed_perm"], "allow.net.hosts");
        assert_eq!(json["stats"]["metrics"]["allowed_total"], 1);
        assert_eq!(json["stats"]["metrics"]["denied_total"], 1);
        assert_eq!(
            json["stats"]["metrics"]["per_unit"]["2"]["io_write_bytes"],
            1024
        );
    }
}
