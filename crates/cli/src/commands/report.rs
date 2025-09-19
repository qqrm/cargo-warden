use std::io;
use std::path::Path;

use event_reporting::export_sarif;

use crate::commands::read_recent_events;

pub(crate) fn exec(output: &str) -> io::Result<()> {
    let events = read_recent_events(Path::new("warden-events.jsonl"), usize::MAX)?;
    export_sarif(&events, Path::new(output))
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
        exec("out.sarif").unwrap();
        assert!(dir.path().join("out.sarif").exists());
    }
}
