//! `GET /v1/events`: a server-sent-events stream of what changed the box.
//!
//! Every audited request is published to an in-memory ring (the last 256
//! events); a client connects, optionally with `Last-Event-ID` to resume, and
//! reads `event: audit` frames as they happen, with a `: keepalive` comment
//! every 15 s so a dead peer is noticed. A stream holds one worker thread, so
//! the number of concurrent streams is capped.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::http::Conn;

const RING: usize = 256;
pub const KEEPALIVE: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Inner {
    ring: VecDeque<(u64, String)>,
    next: u64,
}

#[derive(Default)]
pub struct EventBus {
    inner: Mutex<Inner>,
    cv: Condvar,
    streams: AtomicUsize,
}

/// Releases a stream slot when dropped.
pub struct StreamSlot<'a>(&'a EventBus);

impl Drop for StreamSlot<'_> {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

impl EventBus {
    pub fn new() -> EventBus {
        EventBus::default()
    }

    /// Publishes one event; returns its id.
    pub fn publish(&self, data: &Value) -> u64 {
        let Ok(mut i) = self.inner.lock() else {
            return 0;
        };
        i.next += 1;
        let id = i.next;
        i.ring.push_back((id, data.to_string()));
        while i.ring.len() > RING {
            i.ring.pop_front();
        }
        drop(i);
        self.cv.notify_all();
        id
    }

    /// The events after `last`, oldest first.
    pub fn since(&self, last: u64) -> Vec<(u64, String)> {
        self.inner
            .lock()
            .map(|i| {
                i.ring
                    .iter()
                    .filter(|(id, _)| *id > last)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The id of the newest event (0 when there is none).
    pub fn latest(&self) -> u64 {
        self.inner.lock().map_or(0, |i| i.next)
    }

    /// Blocks up to `timeout` for an event after `last`.
    pub fn wait(&self, last: u64, timeout: Duration) -> Vec<(u64, String)> {
        let Ok(mut g) = self.inner.lock() else {
            return Vec::new();
        };
        if g.next <= last {
            g = match self.cv.wait_timeout(g, timeout) {
                Ok((g, _)) => g,
                Err(_) => return Vec::new(),
            };
        }
        g.ring
            .iter()
            .filter(|(id, _)| *id > last)
            .cloned()
            .collect()
    }

    /// Claims a stream slot, or `None` past `max`.
    pub fn open_stream(&self, max: usize) -> Option<StreamSlot<'_>> {
        let n = self.streams.fetch_add(1, Ordering::SeqCst);
        if n >= max {
            self.streams.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(StreamSlot(self))
    }

    pub fn open_streams(&self) -> usize {
        self.streams.load(Ordering::SeqCst)
    }
}

/// Writes the stream until the peer goes away (a failed write) or `stop` is set.
pub fn stream(
    conn: &mut dyn Conn,
    bus: &EventBus,
    mut last: u64,
    stop: &AtomicBool,
    keepalive: Duration,
) {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
    if conn.write_all(head.as_bytes()).is_err() || conn.flush().is_err() {
        return;
    }
    while !stop.load(Ordering::SeqCst) {
        let events = bus.wait(last, keepalive);
        let mut out = String::new();
        if events.is_empty() {
            out.push_str(": keepalive\n\n");
        }
        for (id, data) in events {
            out.push_str(&format!("id: {id}\nevent: audit\ndata: {data}\n\n"));
            last = id;
        }
        if conn.write_all(out.as_bytes()).is_err() || conn.flush().is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::sync::Arc;

    /// A connection that records what is written and fails after `limit` writes.
    struct Sink {
        out: Vec<u8>,
        writes: usize,
        limit: usize,
    }
    impl Read for Sink {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.writes >= self.limit {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.writes += 1;
            self.out.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Conn for Sink {
        fn set_read_timeout(&mut self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&mut self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
        fn peer_ip(&self) -> String {
            "127.0.0.1".into()
        }
    }

    #[test]
    fn events_are_ordered_resumable_and_bounded() {
        let bus = EventBus::new();
        assert_eq!(bus.latest(), 0);
        for i in 0..300 {
            bus.publish(&json!({ "n": i }));
        }
        assert_eq!(bus.latest(), 300);
        let all = bus.since(0);
        assert_eq!(all.len(), RING, "only the last 256 are kept");
        assert_eq!(all[0].0, 45);
        let tail = bus.since(298);
        assert_eq!(
            tail.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![299, 300]
        );
        assert!(bus.since(300).is_empty());
    }

    #[test]
    fn wait_wakes_on_publish_and_times_out_without_one() {
        let bus = Arc::new(EventBus::new());
        assert!(bus.wait(0, Duration::from_millis(30)).is_empty());
        let b = bus.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            b.publish(&json!({ "x": 1 }));
        });
        let got = bus.wait(0, Duration::from_secs(5));
        t.join().unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn stream_slots_are_capped_and_released() {
        let bus = EventBus::new();
        let a = bus.open_stream(2).unwrap();
        let b = bus.open_stream(2).unwrap();
        assert!(bus.open_stream(2).is_none());
        assert_eq!(bus.open_streams(), 2);
        drop(a);
        assert!(bus.open_stream(2).is_some());
        drop(b);
    }

    #[test]
    fn the_stream_writes_sse_frames_and_stops_when_the_peer_goes() {
        let bus = EventBus::new();
        bus.publish(&json!({ "path": "/v1/commit" }));
        let stop = AtomicBool::new(false);
        // header + frame + keepalive, then the 4th write fails
        let mut sink = Sink {
            out: Vec::new(),
            writes: 0,
            limit: 3,
        };
        stream(&mut sink, &bus, 0, &stop, Duration::from_millis(20));
        let text = String::from_utf8(sink.out).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream"),
            "{text}"
        );
        assert!(
            text.contains("id: 1\nevent: audit\ndata: {\"path\":\"/v1/commit\"}\n\n"),
            "{text}"
        );
        assert!(text.contains(": keepalive"), "{text}");
        // resuming after the last id sends nothing but keepalives
        let mut again = Sink {
            out: Vec::new(),
            writes: 0,
            limit: 2,
        };
        stream(&mut again, &bus, 1, &stop, Duration::from_millis(20));
        assert!(
            !String::from_utf8(again.out)
                .unwrap()
                .contains("event: audit")
        );
    }
}
