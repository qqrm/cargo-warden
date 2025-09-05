use aya::maps::{MapData, ring_buf::RingBuf};
use bpf_api::Event;
use serde::Serialize;
use std::thread;
use std::time::Duration;

const ACTION_EXEC: u8 = 3;
const ACTION_CONNECT: u8 = 4;
const VERDICT_DENIED: u8 = 1;

/// User-facing representation of an event.
#[derive(Debug, Serialize)]
pub struct EventRecord {
    pub pid: u32,
    pub unit: u8,
    pub action: u8,
    pub verdict: u8,
    pub container_id: u64,
    pub caps: u64,
    pub path_or_addr: String,
}

impl From<Event> for EventRecord {
    fn from(e: Event) -> Self {
        let end = e
            .path_or_addr
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(e.path_or_addr.len());
        let path_or_addr = String::from_utf8_lossy(&e.path_or_addr[..end]).to_string();
        Self {
            pid: e.pid,
            unit: e.unit,
            action: e.action,
            verdict: e.verdict,
            container_id: e.container_id,
            caps: e.caps,
            path_or_addr,
        }
    }
}

impl std::fmt::Display for EventRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

fn diagnostic(record: &EventRecord) -> Option<String> {
    if record.verdict != VERDICT_DENIED {
        return None;
    }
    match record.action {
        ACTION_EXEC => Some(format!("Execution denied: {}", record.path_or_addr)),
        ACTION_CONNECT => Some(format!("Network denied: {}", record.path_or_addr)),
        _ => None,
    }
}

/// Polls a ring buffer map and prints logs for each record.
pub fn run(mut ring: RingBuf<MapData>) -> Result<(), anyhow::Error> {
    loop {
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<Event>() {
                continue;
            }
            let event = unsafe { *(item.as_ptr() as *const Event) };
            let record: EventRecord = event.into();
            println!("{}", record);
            println!("{}", serde_json::to_string(&record)?);
            if let Some(msg) = diagnostic(&record) {
                eprintln!("{}", msg);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_record_formats() {
        let mut path = [0u8; 256];
        path[..4].copy_from_slice(b"/bin");
        let event = Event {
            pid: 42,
            unit: 1,
            action: 2,
            verdict: 0,
            reserved: 0,
            container_id: 7,
            caps: 1,
            path_or_addr: path,
        };
        let record: EventRecord = event.into();
        assert_eq!(record.pid, 42);
        assert_eq!(record.unit, 1);
        assert_eq!(record.action, 2);
        assert_eq!(record.verdict, 0);
        assert_eq!(record.container_id, 7);
        assert_eq!(record.caps, 1);
        assert_eq!(record.path_or_addr, "/bin");
        let text = format!("{}", record);
        assert!(text.contains("pid=42"));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"pid\":42"));
    }

    #[test]
    fn diagnostics_for_denied_actions() {
        let exec = EventRecord {
            pid: 1,
            unit: 0,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bash".into(),
        };
        assert_eq!(
            diagnostic(&exec),
            Some("Execution denied: /bin/bash".to_string())
        );
        let net = EventRecord {
            pid: 1,
            unit: 0,
            action: ACTION_CONNECT,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "1.2.3.4:80".into(),
        };
        assert_eq!(
            diagnostic(&net),
            Some("Network denied: 1.2.3.4:80".to_string())
        );
        let allow = EventRecord {
            pid: 1,
            unit: 0,
            action: ACTION_EXEC,
            verdict: 0,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bash".into(),
        };
        assert!(diagnostic(&allow).is_none());
    }
}
