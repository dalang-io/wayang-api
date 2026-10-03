//! The audit trail: one JSON line per mutating request, accepted or refused.
//!
//! Method, path, status, peer, who (token label and scope) and the resulting
//! revision. **Never a body, a query string or a token** — a config may hold
//! secrets and a query may hold a comment nobody meant to publish.

use std::io::Write;
use std::path::PathBuf;

use serde_json::{Value, json};

const MAX_BYTES: u64 = 4 << 20;
pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 500;

pub struct AuditLog {
    path: PathBuf,
}

/// What is recorded about one request.
pub struct Entry<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub remote: &'a str,
    pub actor: &'a str,
    pub scope: &'a str,
    pub key: Option<&'a str>,
    pub rev: Option<u32>,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> AuditLog {
        AuditLog { path: path.into() }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Appends the entry (0600; the file is rotated to `.1` past 4 MiB) and
    /// returns the JSON that was written, so it can be published as an event.
    pub fn record(&self, e: &Entry) -> Value {
        use std::os::unix::fs::OpenOptionsExt;
        let line = json!({
            "ts": now(),
            "method": e.method,
            "path": e.path,
            "status": e.status,
            "ok": e.status < 400,
            "remote": e.remote,
            "actor": e.actor,
            "scope": e.scope,
            "key": e.key,
            "rev": e.rev,
        });
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > MAX_BYTES) {
            let _ = std::fs::rename(&self.path, self.path.with_extension("jsonl.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        }
        line
    }

    /// The newest `limit` entries, newest first.
    pub fn tail(&self, limit: usize) -> Vec<Value> {
        std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .rev()
            .filter_map(|l| serde_json::from_str(l).ok())
            .take(limit)
            .collect()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn records_newest_first_with_0600_and_no_bodies() {
        let dir = std::env::temp_dir().join(format!("wapi-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = AuditLog::new(dir.join("var/api-audit.jsonl"));
        for (i, p) in ["/v1/candidate", "/v1/commit", "/v1/confirm"]
            .iter()
            .enumerate()
        {
            log.record(&Entry {
                method: "POST",
                path: p,
                status: if i == 2 { 409 } else { 200 },
                remote: "10.0.0.9",
                actor: "ops",
                scope: "rw",
                key: Some("k"),
                rev: Some(i as u32),
            });
        }
        let t = log.tail(2);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0]["path"], "/v1/confirm");
        assert_eq!(t[0]["ok"], false);
        assert_eq!(t[1]["actor"], "ops");
        assert_eq!(t[1]["scope"], "rw");
        let m = std::fs::metadata(log.path()).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        assert_eq!(log.tail(100).len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_an_empty_trail() {
        let log = AuditLog::new("/nonexistent/dir/x.jsonl");
        assert!(log.tail(10).is_empty());
    }
}
