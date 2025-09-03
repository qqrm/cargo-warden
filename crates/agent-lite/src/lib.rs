use aya::maps::{MapData, ring_buf::RingBuf};
use bpf_api::Event;
use serde::Serialize;
use std::thread;
use std::time::Duration;

/// User-facing representation of an event.
#[derive(Debug, Serialize)]
pub struct EventRecord {
    pub pid: u32,
    pub unit: u8,
    pub action: u8,
    pub verdict: u8,
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
            path_or_addr,
        }
    }
}

impl std::fmt::Display for EventRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pid={} unit={} action={} verdict={} path_or_addr={}",
            self.pid, self.unit, self.action, self.verdict, self.path_or_addr
        )
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
            path_or_addr: path,
        };
        let record: EventRecord = event.into();
        assert_eq!(record.pid, 42);
        assert_eq!(record.unit, 1);
        assert_eq!(record.action, 2);
        assert_eq!(record.verdict, 0);
        assert_eq!(record.path_or_addr, "/bin");
        let text = format!("{}", record);
        assert!(text.contains("pid=42"));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"pid\":42"));
    }
}
