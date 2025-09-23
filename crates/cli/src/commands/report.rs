use std::io::{self, Write};
use std::path::Path;

use event_reporting::EventRecord;
use event_reporting::export_sarif;

use crate::commands::read_recent_events;

const DEFAULT_SARIF_OUTPUT: &str = "warden.sarif";
const EVENTS_LOG: &str = "warden-events.jsonl";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReportFormat {
    Text,
    Json,
    Sarif,
}

pub(crate) fn exec(format: ReportFormat, output: Option<&str>) -> io::Result<()> {
    let events = read_recent_events(Path::new(EVENTS_LOG), usize::MAX)?;
    match format {
        ReportFormat::Text => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            export_text(&events, &mut handle)
        }
        ReportFormat::Json => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            export_json(&events, &mut handle)
        }
        ReportFormat::Sarif => {
            let path = Path::new(output.unwrap_or(DEFAULT_SARIF_OUTPUT));
            export_sarif(&events, path)
        }
    }
}

fn export_text<W: Write>(events: &[EventRecord], writer: &mut W) -> io::Result<()> {
    for event in events {
        writeln!(writer, "{event}")?;
    }
    Ok(())
}

fn export_json<W: Write>(events: &[EventRecord], writer: &mut W) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, events).map_err(io::Error::other)?;
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
    fn text_exporter_formats_events() {
        let events = vec![EventRecord {
            pid: 1,
            unit: 0,
            action: 2,
            verdict: 1,
            container_id: 3,
            caps: 4,
            path_or_addr: "/bin/example".into(),
        }];
        let mut buffer = Vec::new();
        export_text(&events, &mut buffer).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "pid=1 unit=0 action=2 verdict=1 container_id=3 caps=4 path_or_addr=/bin/example\n"
        );
    }

    #[test]
    fn json_exporter_serializes_events() {
        let events = vec![EventRecord {
            pid: 5,
            unit: 1,
            action: 9,
            verdict: 0,
            container_id: 8,
            caps: 16,
            path_or_addr: "127.0.0.1:80".into(),
        }];
        let mut buffer = Vec::new();
        export_json(&events, &mut buffer).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "[{\"pid\":5,\"unit\":1,\"action\":9,\"verdict\":0,\"container_id\":8,\"caps\":16,\"path_or_addr\":\"127.0.0.1:80\"}]\n"
        );
    }
}
