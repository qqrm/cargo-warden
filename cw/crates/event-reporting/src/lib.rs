use sarif::{
    ArtifactLocation, Level, Location, PhysicalLocation, ResultBuilder, RunBuilder, SarifLog,
    SarifLogBuilder,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::Path;

pub const METRICS_SNAPSHOT_FILE: &str = "warden-metrics.json";

/// User-facing representation of an event emitted by the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub pid: u32,
    pub tgid: u32,
    pub time_ns: u64,
    pub unit: u8,
    pub action: u8,
    pub verdict: u8,
    pub container_id: u64,
    pub caps: u64,
    pub path_or_addr: String,
    pub needed_perm: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnitMetricsSnapshot {
    #[serde(default)]
    pub allowed: u64,
    #[serde(default)]
    pub denied: u64,
    #[serde(default)]
    pub io_read_bytes: u64,
    #[serde(default)]
    pub io_write_bytes: u64,
    #[serde(default)]
    pub cpu_time_ms: u64,
    #[serde(default)]
    pub page_faults: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    #[serde(default)]
    pub allowed_total: u64,
    #[serde(default)]
    pub denied_total: u64,
    #[serde(default)]
    pub violations_total: u64,
    #[serde(default)]
    pub blocked_total: u64,
    #[serde(default)]
    pub per_unit: BTreeMap<u32, UnitMetricsSnapshot>,
}

impl fmt::Display for EventRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.needed_perm.is_empty() {
            write!(
                f,
                "pid={} tgid={} unit={} action={} verdict={} time_ns={} container_id={} caps={} needed_perm={} path_or_addr={}",
                self.pid,
                self.tgid,
                self.unit,
                self.action,
                self.verdict,
                self.time_ns,
                self.container_id,
                self.caps,
                self.needed_perm,
                self.path_or_addr
            )
        } else {
            write!(
                f,
                "pid={} tgid={} unit={} action={} verdict={} time_ns={} container_id={} caps={} needed_perm={} path_or_addr={} hint={}",
                self.pid,
                self.tgid,
                self.unit,
                self.action,
                self.verdict,
                self.time_ns,
                self.container_id,
                self.caps,
                self.needed_perm,
                self.path_or_addr,
                self.needed_perm
            )
        }
    }
}

/// Builds a SARIF log from a slice of events.
pub fn sarif_from_events(events: &[EventRecord]) -> SarifLog {
    let mut seen_artifacts = BTreeSet::new();
    let mut run_builder = RunBuilder::with_tool("cargo-warden", None::<String>);

    for event in events {
        let path = event.path_or_addr.clone();

        if seen_artifacts.insert(path.clone()) {
            run_builder = run_builder.add_file_artifact(path.clone());
        }

        let location = Location::with_physical_location(PhysicalLocation::with_artifact_location(
            ArtifactLocation::new(path.clone()),
        ));

        let level = if event.verdict == 1 {
            Level::Error
        } else {
            Level::Note
        };

        let result = ResultBuilder::with_text_message(event.to_string())
            .with_rule_id(event.action.to_string())
            .with_level(level)
            .add_location(location)
            .build();

        run_builder = run_builder.add_result(result);
    }

    SarifLogBuilder::v2_1_0()
        .add_run(run_builder.build())
        .build_unchecked()
}

/// Writes a SARIF log to the given path.
pub fn export_sarif(events: &[EventRecord], path: &Path) -> io::Result<()> {
    let sarif = sarif_from_events(events);
    let content = sarif::to_string_pretty(&sarif).map_err(io::Error::other)?;
    std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::{Draft, JSONSchema};
    use sarif::{self, Level, SarifLog};
    use serde_json::json;
    use std::fs::File;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn sarif_contains_events() {
        let records = vec![EventRecord {
            pid: 42,
            tgid: 24,
            time_ns: 123,
            unit: 1,
            action: 3,
            verdict: 1,
            container_id: 99,
            caps: 0,
            path_or_addr: "/bin/deny".into(),
            needed_perm: "allow.fs.read_extra".into(),
        }];
        let sarif = sarif_from_events(&records);
        assert_eq!(sarif.version, sarif::SARIF_VERSION);

        let run = sarif.runs.first().expect("run present");
        assert_eq!(run.tool.driver.name, "cargo-warden");
        let results = run.results.as_ref().expect("results present");
        assert_eq!(results.len(), 1);

        let result = &results[0];
        let expected_message = records[0].to_string();
        assert_eq!(result.rule_id.as_deref(), Some("3"));
        assert_eq!(result.level, Some(Level::Error));
        assert_eq!(
            result.message.text.as_deref(),
            Some(expected_message.as_str())
        );

        let location_uri = result
            .locations
            .as_ref()
            .and_then(|locations| locations.first())
            .and_then(|location| location.physical_location.as_ref())
            .and_then(|physical| physical.artifact_location.as_ref())
            .and_then(|artifact| artifact.uri.as_deref());
        assert_eq!(location_uri, Some(records[0].path_or_addr.as_str()));
    }

    #[test]
    fn export_writes_file() {
        let record = EventRecord {
            pid: 7,
            tgid: 70,
            time_ns: 456,
            unit: 1,
            action: 3,
            verdict: 1,
            container_id: 5,
            caps: 0,
            path_or_addr: "/bin/bad".into(),
            needed_perm: "allow.exec.allowed".into(),
        };
        let tmp = NamedTempFile::new().unwrap();
        export_sarif(std::slice::from_ref(&record), tmp.path()).unwrap();

        let mut content = String::new();
        File::open(tmp.path())
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        let sarif: SarifLog = sarif::from_str(&content).unwrap();
        let run = sarif.runs.first().expect("run present");
        let results = run.results.as_ref().expect("results present");
        let result = results.first().expect("result present");
        assert_eq!(
            result.message.text.as_deref(),
            Some(record.to_string().as_str())
        );

        let artifacts = run.artifacts.as_ref().expect("artifacts present");
        let artifact_uri = artifacts
            .iter()
            .filter_map(|artifact| artifact.location.as_ref())
            .filter_map(|location| location.uri.as_deref())
            .find(|uri| *uri == record.path_or_addr);
        assert!(artifact_uri.is_some());

        let schema = json!({
            "type": "object",
            "required": ["version", "runs"],
            "properties": {
                "version": { "const": "2.1.0" },
                "runs": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["tool"],
                        "properties": {
                            "tool": {
                                "type": "object",
                                "required": ["driver"],
                                "properties": {
                                    "driver": {
                                        "type": "object",
                                        "required": ["name"],
                                        "properties": {
                                            "name": { "type": "string" }
                                        }
                                    }
                                }
                            },
                            "results": { "type": "array" }
                        }
                    }
                }
            }
        });

        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&schema)
            .expect("schema compiles");
        let sarif_value: serde_json::Value = serde_json::from_str(&content).unwrap();
        if let Err(errors) = compiled.validate(&sarif_value) {
            let details: Vec<String> = errors.map(|err| err.to_string()).collect();
            panic!("schema validation failed: {details:?}");
        }
    }

    #[test]
    fn metrics_snapshot_serializes() {
        let mut snapshot = MetricsSnapshot {
            allowed_total: 3,
            denied_total: 1,
            violations_total: 1,
            blocked_total: 1,
            ..Default::default()
        };
        snapshot.per_unit.insert(
            42,
            UnitMetricsSnapshot {
                allowed: 2,
                denied: 1,
                io_read_bytes: 100,
                io_write_bytes: 200,
                cpu_time_ms: 50,
                page_faults: 4,
            },
        );
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("\"allowed_total\":3"));
        assert!(json.contains("\"42\""));
    }

    #[test]
    fn metrics_snapshot_backwards_compatibility() {
        let legacy_json = json!({
            "allowed_total": 7,
            "denied_total": 2
        });
        let snapshot: MetricsSnapshot = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(snapshot.allowed_total, 7);
        assert_eq!(snapshot.denied_total, 2);
        assert_eq!(snapshot.violations_total, 0);
        assert_eq!(snapshot.blocked_total, 0);
        assert!(snapshot.per_unit.is_empty());
    }

    #[test]
    fn event_record_json_roundtrip() {
        let record = EventRecord {
            pid: 9,
            tgid: 90,
            time_ns: 1_000,
            unit: 3,
            action: 4,
            verdict: 1,
            container_id: 11,
            caps: 2,
            path_or_addr: "1.2.3.4:80".into(),
            needed_perm: "allow.net.hosts".into(),
        };
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(
            value,
            json!({
                "pid": 9,
                "tgid": 90,
                "time_ns": 1000,
                "unit": 3,
                "action": 4,
                "verdict": 1,
                "container_id": 11,
                "caps": 2,
                "path_or_addr": "1.2.3.4:80",
                "needed_perm": "allow.net.hosts"
            })
        );
        let decoded: EventRecord = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, record);
        let text = record.to_string();
        assert!(text.contains("hint=allow.net.hosts"));
    }
}
