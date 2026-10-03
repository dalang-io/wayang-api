//! The HTTP/1.1 layer: request parsing under a wall-clock budget, responses and
//! the JSON envelope.
//!
//! One request per connection (`Connection: close`). Everything that can be
//! abused before authentication is bounded: header size, body size
//! (`Content-Length` is the peer's claim, not a fact), and the total time a peer
//! may spend sending a request (a byte dribbled just under the per-read timeout
//! must not pin a worker forever).

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const MAX_HEADER: usize = 64 * 1024;
/// Bytes of an abandoned request swallowed so the close is a clean FIN rather
/// than an RST (see [`drain`]).
const MAX_DRAIN: usize = 64 * 1024;

/// A byte stream the server can talk to: plain TCP or TLS over it.
pub trait Conn: Read + Write {
    /// Sets the read timeout on the underlying socket.
    fn set_read_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()>;
    /// The peer's IP address (for rate limiting and the audit trail).
    fn peer_ip(&self) -> String;
}

impl Conn for TcpStream {
    fn set_read_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, d)
    }
    fn set_write_timeout(&mut self, d: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_write_timeout(self, d)
    }
    fn peer_ip(&self) -> String {
        self.peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Percent-decoded path, without the query.
    pub path: String,
    pub query: BTreeMap<String, String>,
    /// Header names lowercased.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    /// The peer's address; empty when unknown.
    pub remote: String,
}

impl Request {
    /// A request without a body, for tests and in-process callers.
    pub fn new(method: &str, target: &str) -> Request {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Request {
            method: method.into(),
            path: percent_decode(path),
            query: parse_query(q),
            headers: BTreeMap::new(),
            body: Vec::new(),
            remote: "127.0.0.1".into(),
        }
    }

    pub fn header(mut self, k: &str, v: &str) -> Request {
        self.headers.insert(k.to_ascii_lowercase(), v.into());
        self
    }

    pub fn body(mut self, b: impl Into<Vec<u8>>) -> Request {
        self.body = b.into();
        self
    }

    pub fn bearer(self, token: &str) -> Request {
        self.header("authorization", &format!("Bearer {token}"))
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(String, String)>,
}

impl Response {
    pub fn header(&self, k: &str) -> Option<&str> {
        self.extra_headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    }

    /// The body as JSON (tests and clients).
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

pub fn json_response(status: u16, v: Value) -> Response {
    match serde_json::to_vec(&v) {
        Ok(body) => Response {
            status,
            content_type: "application/json",
            body,
            extra_headers: Vec::new(),
        },
        Err(_) => Response {
            status: 500,
            content_type: "application/json",
            body: br#"{"ok":false,"error":{"code":"internal","message":"could not serialise the response"}}"#
                .to_vec(),
            extra_headers: Vec::new(),
        },
    }
}

/// `{ "ok": true, "data": …, "rev": …, "pending": … }`
pub fn ok_envelope(data: Value, rev: Option<u32>, pending: Option<u32>) -> Response {
    json_response(
        200,
        json!({ "ok": true, "data": data, "rev": rev, "pending": pending }),
    )
}

/// `{ "ok": false, "error": { "code": …, "message": … } }`
pub fn err(status: u16, code: &str, message: impl Into<String>) -> Response {
    json_response(
        status,
        json!({ "ok": false, "error": { "code": code, "message": message.into() } }),
    )
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        423 => "Locked",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Why a request could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// `Content-Length` over the limit: answered `413`.
    TooLarge(String),
    /// Anything else malformed or stalled: answered `400`.
    Bad(String),
}

impl ReadError {
    pub fn message(&self) -> &str {
        match self {
            ReadError::TooLarge(m) | ReadError::Bad(m) => m,
        }
    }

    pub fn response(&self) -> Response {
        match self {
            ReadError::TooLarge(m) => err(413, "payload_too_large", m.clone()),
            ReadError::Bad(m) => err(400, "bad_request", m.clone()),
        }
    }
}

/// One read bounded by what is left of the request budget. `Ok(0)` is EOF; a
/// timeout is an error, never an empty read, so a stalled peer cannot be
/// mistaken for a finished request.
fn read_within(conn: &mut dyn Conn, buf: &mut [u8], deadline: Instant) -> Result<usize, ReadError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(ReadError::Bad("request timed out".into()));
    }
    let _ = conn.set_read_timeout(Some(deadline - now));
    match conn.read(buf) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
            Err(ReadError::Bad("request timed out".into()))
        }
        Err(e) => Err(ReadError::Bad(e.to_string())),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn read_request(
    conn: &mut dyn Conn,
    deadline: Instant,
    max_body: usize,
) -> Result<Request, ReadError> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEADER {
            return Err(ReadError::Bad("request headers too large".into()));
        }
        let n = read_within(conn, &mut tmp, deadline)?;
        if n == 0 {
            return Err(ReadError::Bad("connection closed before headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ReadError::Bad("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(ReadError::Bad("no method".into()))?
        .to_string();
    let target = parts
        .next()
        .ok_or(ReadError::Bad("no request target".into()))?
        .to_string();

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    // A chunked body has no `Content-Length` to bound: refuse it instead of
    // guessing where the request ends.
    if headers.contains_key("transfer-encoding") {
        return Err(ReadError::Bad("transfer-encoding is not supported".into()));
    }
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > max_body {
        return Err(ReadError::TooLarge(format!(
            "request body too large ({content_length} bytes, limit {max_body})"
        )));
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = read_within(conn, &mut tmp, deadline)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    let (raw_path, raw_query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    Ok(Request {
        method,
        path: percent_decode(raw_path),
        query: parse_query(raw_query),
        headers,
        body,
        remote: conn.peer_ip(),
    })
}

/// Reads and discards whatever the peer is still sending, briefly. The point
/// is not to receive the request: it is to let the bytes already in flight
/// land, so closing afterwards is a clean FIN rather than an RST that would
/// discard the response we just wrote.
pub fn drain(conn: &mut dyn Conn, request_deadline: Instant) {
    const DRAIN: Duration = Duration::from_millis(250);
    let until = request_deadline.min(Instant::now() + DRAIN);
    let mut sink = [0u8; 4096];
    let mut total = 0usize;
    while total < MAX_DRAIN {
        let now = Instant::now();
        if now >= until {
            break;
        }
        let _ = conn.set_read_timeout(Some(until - now));
        match conn.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
}

pub fn write_response(conn: &mut dyn Conn, resp: &Response) {
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len()
    );
    for (k, v) in &resp.extra_headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let _ = conn.write_all(out.as_bytes());
    let _ = conn.write_all(&resp.body);
    let _ = conn.flush();
}

/// `a=1&b=x+y%21` → `{a: "1", b: "x y!"}`. `+` is a space in a query string
/// (form encoding), `%XX` is a byte; an encoded `+` (`%2B`) stays a plus.
pub fn parse_query(raw: &str) -> BTreeMap<String, String> {
    let dec = |s: &str| percent_decode(&s.replace('+', " "));
    raw.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (dec(k), dec(v))
        })
        .collect()
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_decodes_plus_and_percent() {
        let q = parse_query("comment=api+lab%21&confirm=30&flag&x=a%2Bb");
        assert_eq!(q["comment"], "api lab!");
        assert_eq!(q["confirm"], "30");
        assert_eq!(q["flag"], "");
        assert_eq!(q["x"], "a+b");
        assert!(parse_query("").is_empty());
    }

    #[test]
    fn percent_decode_is_forgiving_about_bad_escapes() {
        assert_eq!(percent_decode("/v1/a%20b"), "/v1/a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%e2%82%ac"), "€");
    }

    #[test]
    fn request_builder_parses_the_target() {
        let r = Request::new("POST", "/v1/commit?confirm=30&comment=a+b")
            .bearer("t")
            .body("x");
        assert_eq!(r.path, "/v1/commit");
        assert_eq!(r.query["comment"], "a b");
        assert_eq!(r.headers["authorization"], "Bearer t");
        assert_eq!(r.body, b"x");
    }

    #[test]
    fn envelopes_have_the_documented_shape() {
        let r = ok_envelope(json!({"a": 1}), Some(7), None);
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["data"]["a"], 1);
        assert_eq!(r.json()["rev"], 7);
        assert!(r.json()["pending"].is_null());
        let e = err(422, "validation", "bad");
        assert_eq!(e.json()["ok"], false);
        assert_eq!(e.json()["error"]["code"], "validation");
        assert_eq!(reason(429), "Too Many Requests");
    }
}
