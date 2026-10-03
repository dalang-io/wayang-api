//! The server: accept loop, the request pipeline and the [`App`] a tool
//! implements.
//!
//! A tool supplies its routes ([`App::route`], which also says what scope a
//! route needs) and handlers ([`App::handle`]); everything around them is here
//! and identical for every tool, in this order:
//!
//! 1. rate limit per peer (`429`), method check, `GET /v1/health` (the only
//!    unauthenticated route);
//! 2. token authentication — failed attempts are throttled per peer, so the
//!    token cannot be guessed at line speed (`401`);
//! 3. the routes every tool shares: `GET /v1/audit`, `GET /v1/events` (SSE);
//! 4. the tool's routes: unknown `404`, wrong method `405`, scope too low or a
//!    read-only server `403`;
//! 5. idempotent replay, the handler, the audit line and the event.
//!
//! Authentication comes before the route table, so an anonymous peer learns
//! nothing about what the server offers or allows.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::audit::{self, AuditLog};
use crate::auth::{Principal, Scope, TokenStore};
use crate::events::{self, EventBus};
use crate::http::{self, Conn, Request, Response, err, json_response, ok_envelope};
use crate::idem::{self, IdemCache};
use crate::limit::{RateConfig, RateLimiter};
use crate::tls::TlsConn;

/// What a route needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Any authenticated token.
    Read,
    /// A token with scope `rw` or more, on a server started with writes on.
    Write,
    /// A token with scope `admin`, on a server started with writes on.
    Admin,
}

/// What an [`App`] says about a `(method, path)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Known(Need),
    /// The path exists but takes another method (named, for the `Allow` header).
    WrongMethod(&'static str),
    Unknown,
}

/// One tool's half of the API.
pub trait App: Send + Sync {
    /// The tool's name (`wayang-fw`), for `WWW-Authenticate` and `/v1/health`.
    fn name(&self) -> &str;
    /// The `data` of `GET /v1/health` (no authentication: keep it harmless).
    fn health(&self) -> Value;
    fn route(&self, method: &str, path: &str) -> Route;
    /// Runs an authenticated, authorised request.
    fn handle(&self, req: &Request, who: &Principal) -> Response;
    /// (active revision, pending revision): for the envelope and the audit line.
    fn revision(&self) -> (Option<u32>, Option<u32>) {
        (None, None)
    }
}

pub struct Options {
    /// `None` = no authentication (loopback development): everyone is
    /// [`Principal::anonymous`], read-only.
    pub tokens: Option<TokenStore>,
    /// Writes allowed at all. Needs `tokens`.
    pub rw: bool,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// `None` = no rate limit.
    pub rate: Option<RateConfig>,
    pub audit: Option<AuditLog>,
    /// Concurrent connections served; more get `503`.
    pub max_conns: usize,
    pub max_body: usize,
    /// Concurrent `/v1/events` streams.
    pub max_streams: usize,
    /// Wall-clock budget for reading one request.
    pub request_budget: Duration,
    pub io_timeout: Duration,
    pub keepalive: Duration,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            tokens: None,
            rw: false,
            tls: None,
            rate: Some(RateConfig::DEFAULT),
            audit: None,
            max_conns: 32,
            max_body: 1 << 20,
            max_streams: 8,
            request_budget: Duration::from_secs(10),
            io_timeout: Duration::from_secs(10),
            keepalive: events::KEEPALIVE,
        }
    }
}

/// What a request turns into: a response, or an event stream the connection
/// handler then runs.
pub enum Outcome {
    Response(Response),
    Events { last_id: u64 },
}

pub struct Server {
    app: Arc<dyn App>,
    opts: Options,
    limiter: Option<RateLimiter>,
    auth_failures: RateLimiter,
    idem: Mutex<IdemCache>,
    bus: EventBus,
    stop: Arc<AtomicBool>,
    active: AtomicUsize,
}

impl Server {
    pub fn new(app: Arc<dyn App>, opts: Options) -> Result<Server, String> {
        if opts.rw && opts.tokens.is_none() {
            return Err("writes need authentication: a server with --rw must have tokens".into());
        }
        Ok(Server {
            limiter: opts.rate.map(RateLimiter::new),
            auth_failures: RateLimiter::new(RateConfig::FAILURES),
            idem: Mutex::new(IdemCache::default()),
            bus: EventBus::new(),
            stop: Arc::new(AtomicBool::new(false)),
            active: AtomicUsize::new(0),
            app,
            opts,
        })
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    pub fn events(&self) -> &EventBus {
        &self.bus
    }

    fn too_many(secs: u64) -> Response {
        let mut r = err(
            429,
            "rate_limited",
            format!("too many requests: retry in {secs}s"),
        );
        r.extra_headers
            .push(("Retry-After".into(), secs.to_string()));
        r
    }

    fn unauthorized(&self) -> Response {
        let mut r = err(401, "unauthorized", "a bearer token is required");
        r.extra_headers.push((
            "WWW-Authenticate".into(),
            format!("Bearer realm=\"{}\"", self.app.name()),
        ));
        r
    }

    fn audit(&self, req: &Request, who: &Principal, status: u16, key: Option<&str>) {
        let Some(log) = &self.opts.audit else { return };
        let line = log.record(&audit::Entry {
            method: &req.method,
            path: &req.path,
            status,
            remote: &req.remote,
            actor: &who.label,
            scope: who.scope.as_str(),
            key,
            rev: self.app.revision().0,
        });
        self.bus.publish(&line);
    }

    /// The whole pipeline for one request, without any I/O.
    pub fn dispatch(&self, req: &Request) -> Outcome {
        Outcome::Response(match self.pipeline(req) {
            Ok(o) => return o,
            Err(r) => r,
        })
    }

    fn pipeline(&self, req: &Request) -> Result<Outcome, Response> {
        if let Some(l) = &self.limiter
            && let Err(secs) = l.take(&req.remote)
        {
            return Err(Self::too_many(secs));
        }
        if !matches!(req.method.as_str(), "GET" | "PUT" | "POST") {
            let mut r = err(
                405,
                "method_not_allowed",
                "this API takes GET, PUT and POST",
            );
            r.extra_headers
                .push(("Allow".into(), "GET, PUT, POST".into()));
            return Err(r);
        }
        if req.method == "GET" && !req.body.is_empty() {
            return Err(err(
                400,
                "bad_request",
                "GET requests must not carry a body",
            ));
        }
        if req.method == "GET" && req.path == "/v1/health" {
            return Ok(Outcome::Response(json_response(
                200,
                json!({ "ok": true, "data": self.app.health() }),
            )));
        }

        // ---- authentication (before anything that reveals the route table)
        let who = match &self.opts.tokens {
            None => Principal::anonymous(),
            Some(store) => {
                if let Err(secs) = self.auth_failures.would_allow(&req.remote) {
                    return Err(Self::too_many(secs));
                }
                let presented = req
                    .headers
                    .get("authorization")
                    .and_then(|h| {
                        h.strip_prefix("Bearer ")
                            .or_else(|| h.strip_prefix("bearer "))
                    })
                    .map(str::trim)
                    .unwrap_or("");
                match store.authenticate(presented) {
                    Some(p) => p,
                    None => {
                        let _ = self.auth_failures.take(&req.remote);
                        return Err(self.unauthorized());
                    }
                }
            }
        };

        // ---- the routes every tool shares
        if req.method == "GET" && req.path == "/v1/audit" {
            return self.audit_tail(req).map(Outcome::Response);
        }
        if req.method == "GET" && req.path == "/v1/events" {
            let last = req
                .headers
                .get("last-event-id")
                .or_else(|| req.query.get("last_id"))
                .and_then(|v| v.trim().parse::<u64>().ok())
                // a new subscriber starts at "now", not at the whole ring
                .unwrap_or_else(|| self.bus.latest());
            return Ok(Outcome::Events { last_id: last });
        }

        // ---- the tool's routes
        let need = match self.app.route(&req.method, &req.path) {
            Route::Unknown => {
                return Err(err(404, "not_found", format!("no route for {}", req.path)));
            }
            Route::WrongMethod(allow) => {
                let mut r = err(
                    405,
                    "method_not_allowed",
                    format!("{} takes {allow}", req.path),
                );
                r.extra_headers.push(("Allow".into(), allow.into()));
                return Err(r);
            }
            Route::Known(n) => n,
        };
        let key = if req.method == "GET" {
            None
        } else {
            idem::key_of(req)?
        };
        // what the client sent (the audit line shows it; the cache key above
        // also carries the method and path)
        let raw_key = key
            .as_ref()
            .and_then(|_| req.headers.get("idempotency-key"))
            .map(|k| k.trim().to_string());
        let refused = match need {
            Need::Read => None,
            Need::Write | Need::Admin if !self.opts.rw => Some(err(
                403,
                "read_only",
                "this API server is read-only (start it with --rw to allow changes)",
            )),
            Need::Write if who.scope < Scope::Rw => Some(err(
                403,
                "forbidden",
                format!(
                    "this token (scope {}) may not change anything: rw is needed",
                    who.scope.as_str()
                ),
            )),
            Need::Admin if who.scope < Scope::Admin => Some(err(
                403,
                "forbidden",
                format!(
                    "this action needs a token with scope admin (this one is {})",
                    who.scope.as_str()
                ),
            )),
            _ => None,
        };
        if let Some(r) = refused {
            if req.method != "GET" {
                self.audit(req, &who, r.status, raw_key.as_deref());
            }
            return Err(r);
        }

        // ---- idempotent replay, the handler, the audit line
        if let Some(k) = &key
            && let Some(mut hit) = self.idem.lock().ok().and_then(|c| c.get(k))
        {
            hit.extra_headers
                .push(("Idempotent-Replay".into(), "true".into()));
            return Ok(Outcome::Response(hit));
        }
        let resp = self.app.handle(req, &who);
        if req.method != "GET" {
            self.audit(req, &who, resp.status, raw_key.as_deref());
            if let Some(k) = key
                && let Ok(mut c) = self.idem.lock()
            {
                c.put(k, resp.clone());
            }
        }
        Ok(Outcome::Response(resp))
    }

    fn audit_tail(&self, req: &Request) -> Result<Response, Response> {
        let limit = match req.query.get("limit") {
            None => audit::DEFAULT_LIMIT,
            Some(s) => s
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=audit::MAX_LIMIT).contains(n))
                .ok_or_else(|| {
                    err(
                        400,
                        "bad_request",
                        format!("limit must be 1-{}", audit::MAX_LIMIT),
                    )
                })?,
        };
        let entries = self
            .opts
            .audit
            .as_ref()
            .map(|a| a.tail(limit))
            .unwrap_or_default();
        let (rev, pending) = self.app.revision();
        Ok(ok_envelope(json!({ "entries": entries }), rev, pending))
    }

    // ------------------------------------------------------------ I/O

    fn handle_conn(&self, conn: &mut dyn Conn) {
        let _ = conn.set_write_timeout(Some(self.opts.io_timeout));
        let deadline = Instant::now() + self.opts.request_budget;
        match http::read_request(conn, deadline, self.opts.max_body) {
            Err(e) => {
                // The peer may still be sending (an oversized upload is
                // rejected mid-stream): let it land before closing, or the
                // kernel answers with an RST that discards our response.
                http::drain(conn, deadline);
                http::write_response(conn, &e.response());
            }
            Ok(req) => match self.dispatch(&req) {
                Outcome::Response(r) => http::write_response(conn, &r),
                Outcome::Events { last_id } => match self.bus.open_stream(self.opts.max_streams) {
                    Some(_slot) => {
                        events::stream(conn, &self.bus, last_id, &self.stop, self.opts.keepalive)
                    }
                    None => http::write_response(
                        conn,
                        &err(503, "too_many_streams", "too many event streams are open"),
                    ),
                },
            },
        }
    }

    /// Serves `listener` until [`Server::stop_flag`] is set (and one more
    /// connection arrives to wake the accept). One thread per connection, at
    /// most `max_conns` at a time: a slow peer holds its own thread, not the
    /// server.
    pub fn serve(self: &Arc<Server>, listener: TcpListener) {
        for stream in listener.incoming() {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else { continue };
            if self.active.fetch_add(1, Ordering::SeqCst) >= self.opts.max_conns {
                self.active.fetch_sub(1, Ordering::SeqCst);
                let mut s = stream;
                http::write_response(&mut s, &err(503, "busy", "too many connections"));
                continue;
            }
            let me = self.clone();
            let spawned = std::thread::Builder::new()
                .name("wayang-api-conn".into())
                .spawn(move || {
                    match &me.opts.tls {
                        None => {
                            let mut s = stream;
                            me.handle_conn(&mut s);
                        }
                        Some(cfg) => {
                            if let Ok(mut c) = TlsConn::accept(cfg, stream) {
                                me.handle_conn(&mut c);
                            }
                        }
                    }
                    me.active.fetch_sub(1, Ordering::SeqCst);
                });
            if spawned.is_err() {
                self.active.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::AtomicU32;

    const RO: &str = "rorororororororororororororororo";
    const RW: &str = "rwrwrwrwrwrwrwrwrwrwrwrwrwrwrwrw";
    const AD: &str = "adadadadadadadadadadadadadadadad";

    /// A tool with a read route, a write route and an admin route.
    struct Dummy {
        puts: AtomicU32,
        rev: AtomicU32,
    }

    impl App for Dummy {
        fn name(&self) -> &str {
            "wayang-dummy"
        }
        fn health(&self) -> Value {
            json!({ "version": "0" })
        }
        fn route(&self, m: &str, p: &str) -> Route {
            match (m, p) {
                ("GET", "/v1/thing") => Route::Known(Need::Read),
                ("PUT", "/v1/thing") => Route::Known(Need::Write),
                ("POST", "/v1/danger") => Route::Known(Need::Admin),
                (_, "/v1/thing") => Route::WrongMethod("GET, PUT"),
                (_, "/v1/danger") => Route::WrongMethod("POST"),
                _ => Route::Unknown,
            }
        }
        fn handle(&self, req: &Request, who: &Principal) -> Response {
            if req.method == "PUT" || req.method == "POST" {
                self.puts.fetch_add(1, Ordering::SeqCst);
                self.rev.fetch_add(1, Ordering::SeqCst);
            }
            ok_envelope(
                json!({ "by": who.label, "scope": who.scope.as_str() }),
                self.revision().0,
                None,
            )
        }
        fn revision(&self) -> (Option<u32>, Option<u32>) {
            (Some(self.rev.load(Ordering::SeqCst)), None)
        }
    }

    fn dummy() -> Arc<Dummy> {
        Arc::new(Dummy {
            puts: AtomicU32::new(0),
            rev: AtomicU32::new(0),
        })
    }

    fn tokens() -> TokenStore {
        TokenStore::single(Scope::Ro, "dash", RO)
            .with(Scope::Rw, "ci", RW)
            .with(Scope::Admin, "ops", AD)
    }

    fn opts(rw: bool) -> Options {
        Options {
            tokens: Some(tokens()),
            rw,
            rate: None,
            ..Options::default()
        }
    }

    fn server(app: &Arc<Dummy>, o: Options) -> Server {
        Server::new(app.clone(), o).unwrap()
    }

    fn resp(s: &Server, r: Request) -> Response {
        match s.dispatch(&r) {
            Outcome::Response(r) => r,
            Outcome::Events { .. } => panic!("unexpected event stream"),
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wapi-srv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn writes_need_a_token_store() {
        let e = Server::new(
            dummy(),
            Options {
                rw: true,
                ..Options::default()
            },
        )
        .err()
        .unwrap();
        assert!(e.contains("authentication"), "{e}");
        assert!(Server::new(dummy(), Options::default()).is_ok());
    }

    #[test]
    fn health_is_open_and_everything_else_needs_a_token_first() {
        let s = server(&dummy(), opts(true));
        assert_eq!(resp(&s, Request::new("GET", "/v1/health")).status, 200);
        for (m, p) in [
            ("GET", "/v1/thing"),
            ("PUT", "/v1/thing"),
            ("GET", "/v1/nope"),
            ("POST", "/v1/danger"),
        ] {
            let r = resp(&s, Request::new(m, p));
            assert_eq!(r.status, 401, "{m} {p}: an anonymous peer learns nothing");
            assert_eq!(
                r.header("www-authenticate"),
                Some("Bearer realm=\"wayang-dummy\"")
            );
        }
        assert_eq!(
            resp(&s, Request::new("GET", "/v1/thing").bearer("wrong")).status,
            401
        );
    }

    #[test]
    fn scopes_decide_what_a_token_may_do() {
        let app = dummy();
        let s = server(&app, opts(true));
        let get = |t: &str| resp(&s, Request::new("GET", "/v1/thing").bearer(t));
        let put = |t: &str| resp(&s, Request::new("PUT", "/v1/thing").bearer(t));
        let post = |t: &str| resp(&s, Request::new("POST", "/v1/danger").bearer(t));
        assert_eq!(get(RO).status, 200);
        assert_eq!(get(RO).json()["data"]["by"], "dash");
        // ro: reads only
        let r = put(RO);
        assert_eq!(r.status, 403);
        assert_eq!(r.json()["error"]["code"], "forbidden");
        assert_eq!(post(RO).status, 403);
        // rw: may change the config, not do admin things
        assert_eq!(put(RW).status, 200);
        assert_eq!(post(RW).json()["error"]["code"], "forbidden");
        // admin: everything
        assert_eq!(put(AD).status, 200);
        assert_eq!(post(AD).status, 200);
        assert_eq!(
            app.puts.load(Ordering::SeqCst),
            3,
            "only the permitted writes ran"
        );
        // wrong method on a known path: 405 with Allow
        let r = resp(&s, Request::new("POST", "/v1/thing").bearer(RW));
        assert_eq!((r.status, r.header("allow")), (405, Some("GET, PUT")));
        assert_eq!(
            resp(&s, Request::new("DELETE", "/v1/thing").bearer(RW)).status,
            405
        );
        assert_eq!(
            resp(&s, Request::new("GET", "/v1/nope").bearer(RO)).status,
            404
        );
    }

    #[test]
    fn a_read_only_server_refuses_writes_whatever_the_token() {
        let app = dummy();
        let s = server(&app, opts(false));
        for t in [RO, RW, AD] {
            let r = resp(&s, Request::new("PUT", "/v1/thing").bearer(t));
            assert_eq!(
                (r.status, r.json()["error"]["code"].as_str()),
                (403, Some("read_only"))
            );
        }
        assert_eq!(
            resp(&s, Request::new("POST", "/v1/danger").bearer(AD)).status,
            403
        );
        assert_eq!(app.puts.load(Ordering::SeqCst), 0);
        assert_eq!(
            resp(&s, Request::new("GET", "/v1/thing").bearer(RO)).status,
            200
        );
    }

    #[test]
    fn without_tokens_everyone_is_anonymous_and_read_only() {
        let s = server(
            &dummy(),
            Options {
                rate: None,
                ..Options::default()
            },
        );
        let r = resp(&s, Request::new("GET", "/v1/thing"));
        assert_eq!(
            (r.status, r.json()["data"]["by"].as_str()),
            (200, Some("anonymous"))
        );
        assert_eq!(resp(&s, Request::new("PUT", "/v1/thing")).status, 403);
    }

    #[test]
    fn a_get_with_a_body_and_other_methods_are_refused() {
        let s = server(&dummy(), opts(true));
        assert_eq!(
            resp(&s, Request::new("GET", "/v1/thing").bearer(RO).body("{}")).status,
            400
        );
        for m in ["PATCH", "DELETE", "HEAD", "OPTIONS"] {
            assert_eq!(
                resp(&s, Request::new(m, "/v1/thing").bearer(RW)).status,
                405,
                "{m}"
            );
        }
    }

    #[test]
    fn rate_limit_answers_429_with_retry_after_per_peer() {
        let o = Options {
            rate: Some(RateConfig {
                burst: 3.0,
                per_sec: 0.01,
            }),
            ..opts(true)
        };
        let s = server(&dummy(), o);
        for _ in 0..3 {
            assert_eq!(
                resp(&s, Request::new("GET", "/v1/thing").bearer(RO)).status,
                200
            );
        }
        let r = resp(&s, Request::new("GET", "/v1/thing").bearer(RO));
        assert_eq!(r.status, 429);
        assert!(r.header("retry-after").unwrap().parse::<u64>().unwrap() >= 1);
        assert_eq!(r.json()["error"]["code"], "rate_limited");
        let mut other = Request::new("GET", "/v1/thing").bearer(RO);
        other.remote = "10.9.9.9".into();
        assert_eq!(
            resp(&s, other).status,
            200,
            "another peer has its own bucket"
        );
    }

    #[test]
    fn guessing_tokens_is_throttled_per_peer() {
        let s = server(&dummy(), opts(true));
        for _ in 0..5 {
            assert_eq!(
                resp(&s, Request::new("GET", "/v1/thing").bearer("guess")).status,
                401
            );
        }
        // the sixth attempt is throttled, and so is a *valid* token from that peer
        assert_eq!(
            resp(&s, Request::new("GET", "/v1/thing").bearer("guess")).status,
            429
        );
        assert_eq!(
            resp(&s, Request::new("GET", "/v1/thing").bearer(RO)).status,
            429
        );
        // another peer is unaffected
        let mut other = Request::new("GET", "/v1/thing").bearer(RO);
        other.remote = "10.8.8.8".into();
        assert_eq!(resp(&s, other).status, 200);
    }

    #[test]
    fn idempotent_retries_replay_and_the_audit_names_the_actor() {
        let dir = tmp("audit");
        let app = dummy();
        let o = Options {
            audit: Some(AuditLog::new(dir.join("a.jsonl"))),
            ..opts(true)
        };
        let s = server(&app, o);
        let put = || {
            Request::new("PUT", "/v1/thing")
                .bearer(RW)
                .header("Idempotency-Key", "k-1")
        };
        let first = resp(&s, put());
        let second = resp(&s, put());
        assert_eq!(second.body, first.body);
        assert_eq!(second.header("idempotent-replay"), Some("true"));
        assert_eq!(app.puts.load(Ordering::SeqCst), 1, "acted once");
        // a refused write is audited too (a ro token), reads are not
        resp(&s, Request::new("PUT", "/v1/thing").bearer(RO));
        resp(&s, Request::new("GET", "/v1/thing").bearer(RO));
        let r = resp(&s, Request::new("GET", "/v1/audit?limit=10").bearer(RO));
        let e = r.json()["data"]["entries"].as_array().unwrap().clone();
        assert_eq!(e.len(), 2, "{e:?}");
        assert_eq!(e[0]["status"], 403);
        assert_eq!(e[0]["actor"], "dash");
        assert_eq!(e[1]["actor"], "ci");
        assert_eq!(e[1]["scope"], "rw");
        assert_eq!(e[1]["key"], "k-1");
        assert_eq!(e[1]["rev"], 1);
        assert_eq!(
            resp(&s, Request::new("GET", "/v1/audit?limit=0").bearer(RO)).status,
            400
        );
        let raw = std::fs::read_to_string(dir.join("a.jsonl")).unwrap();
        assert!(
            !raw.contains(RW) && !raw.contains(RO),
            "no tokens in the trail"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn events_start_at_now_and_resume_from_last_event_id() {
        let dir = tmp("events");
        let s = server(
            &dummy(),
            Options {
                audit: Some(AuditLog::new(dir.join("a.jsonl"))),
                ..opts(true)
            },
        );
        resp(&s, Request::new("PUT", "/v1/thing").bearer(RW));
        let o = s.dispatch(&Request::new("GET", "/v1/events").bearer(RO));
        assert!(
            matches!(o, Outcome::Events { last_id: 1 }),
            "a new subscriber starts at the newest"
        );
        let o = s.dispatch(
            &Request::new("GET", "/v1/events")
                .bearer(RO)
                .header("Last-Event-ID", "0"),
        );
        assert!(matches!(o, Outcome::Events { last_id: 0 }));
        assert!(
            matches!(s.dispatch(&Request::new("GET", "/v1/events")), Outcome::Response(r) if r.status == 401)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------- over sockets

    fn start(
        app: &Arc<Dummy>,
        o: Options,
    ) -> (
        std::net::SocketAddr,
        Arc<Server>,
        std::thread::JoinHandle<()>,
    ) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let s = Arc::new(server(app, o));
        let s2 = s.clone();
        let h = std::thread::spawn(move || s2.serve(l));
        (addr, s, h)
    }

    fn shut(addr: std::net::SocketAddr, s: &Arc<Server>, h: std::thread::JoinHandle<()>) {
        s.stop_flag().store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(addr);
        h.join().unwrap();
    }

    fn raw(addr: std::net::SocketAddr, req: &str) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out
    }

    #[test]
    fn a_stalled_connection_does_not_block_the_others() {
        let (addr, s, h) = start(&dummy(), opts(true));
        // a peer that connects and says nothing holds one thread, not the server
        let _idle = TcpStream::connect(addr).unwrap();
        let t = Instant::now();
        let out = raw(addr, "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "answered while another connection hangs"
        );
        // many at once
        let threads: Vec<_> = (0..12)
            .map(|_| {
                std::thread::spawn(move || {
                    raw(addr, &format!("GET /v1/thing HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {RO}\r\n\r\n"))
                })
            })
            .collect();
        for t in threads {
            assert!(t.join().unwrap().starts_with("HTTP/1.1 200"));
        }
        shut(addr, &s, h);
    }

    #[test]
    fn oversized_bodies_are_413_over_the_wire_and_the_limit_is_configurable() {
        let (addr, s, h) = start(
            &dummy(),
            Options {
                max_body: 1000,
                ..opts(true)
            },
        );
        let out = raw(
            addr,
            &format!(
                "PUT /v1/thing HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {RW}\r\nContent-Length: 5000\r\n\r\n"
            ),
        );
        assert!(out.starts_with("HTTP/1.1 413"), "{out}");
        let body = "x".repeat(900);
        let out = raw(
            addr,
            &format!(
                "PUT /v1/thing HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {RW}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        shut(addr, &s, h);
    }

    #[test]
    fn connections_past_the_cap_get_503() {
        let (addr, s, h) = start(
            &dummy(),
            Options {
                max_conns: 2,
                request_budget: Duration::from_secs(2),
                ..opts(true)
            },
        );
        let _a = TcpStream::connect(addr).unwrap();
        let _b = TcpStream::connect(addr).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let out = raw(addr, "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 503"), "{out}");
        shut(addr, &s, h);
    }

    #[test]
    fn an_event_stream_delivers_a_write_as_it_happens() {
        let dir = tmp("sse");
        let app = dummy();
        let (addr, s, h) = start(
            &app,
            Options {
                audit: Some(AuditLog::new(dir.join("a.jsonl"))),
                ..opts(true)
            },
        );
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            c,
            "GET /v1/events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {RO}\r\n\r\n"
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let out = raw(
            addr,
            &format!("PUT /v1/thing HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {RW}\r\n\r\n"),
        );
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        let mut got = String::new();
        let mut buf = [0u8; 1024];
        while !got.contains("event: audit") {
            let n = c.read(&mut buf).unwrap();
            assert!(n > 0, "stream closed early: {got}");
            got.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert!(
            got.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream"),
            "{got}"
        );
        assert!(
            got.contains("\"path\":\"/v1/thing\"") && got.contains("\"actor\":\"ci\""),
            "{got}"
        );
        drop(c);
        shut(addr, &s, h);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn too_many_event_streams_are_refused() {
        let (addr, s, h) = start(
            &dummy(),
            Options {
                max_streams: 1,
                ..opts(true)
            },
        );
        let mut first = TcpStream::connect(addr).unwrap();
        write!(
            first,
            "GET /v1/events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {RO}\r\n\r\n"
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let out = raw(
            addr,
            &format!("GET /v1/events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {RO}\r\n\r\n"),
        );
        assert!(out.starts_with("HTTP/1.1 503"), "{out}");
        drop(first);
        shut(addr, &s, h);
    }

    // ------------------------------------------------------------------ TLS

    use crate::tls::testpki;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    fn pem_certs(p: &std::path::Path) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(p).unwrap(),
        ))
        .collect::<Result<_, _>>()
        .unwrap()
    }

    fn pem_key(p: &std::path::Path) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(p).unwrap(),
        ))
        .unwrap()
        .unwrap()
    }

    /// One HTTPS request; `Err` when the handshake or the exchange failed.
    fn https(
        addr: std::net::SocketAddr,
        pki: &testpki::Pki,
        client: Option<(&std::path::Path, &std::path::Path)>,
        path: &str,
        token: Option<&str>,
    ) -> Result<String, String> {
        let mut roots = RootCertStore::empty();
        for c in pem_certs(&pki.ca) {
            roots.add(c).unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let b = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let cfg = match client {
            None => b.with_no_client_auth(),
            Some((c, k)) => b.with_client_auth_cert(pem_certs(c), pem_key(k)).unwrap(),
        };
        let tcp = TcpStream::connect(addr).map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let conn = ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").unwrap())
            .map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}\r\n").as_bytes())
            .map_err(|e| e.to_string())?;
        let mut out = String::new();
        match tls.read_to_string(&mut out) {
            Ok(_) => Ok(out),
            // a server that closes without close_notify after the response is fine
            Err(e) if !out.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(out),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn https_serves_the_same_pipeline() {
        let pki = testpki::make("https");
        let tls = crate::tls::server_config(&pki.server_cert, &pki.server_key, None).unwrap();
        let (addr, s, h) = start(
            &dummy(),
            Options {
                tls: Some(tls),
                ..opts(true)
            },
        );
        let ok = https(addr, &pki, None, "/v1/health", None).unwrap();
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        let r = https(addr, &pki, None, "/v1/thing", Some(RO)).unwrap();
        assert!(
            r.starts_with("HTTP/1.1 200") && r.contains("\"by\":\"dash\""),
            "{r}"
        );
        let r = https(addr, &pki, None, "/v1/thing", None).unwrap();
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");
        // plaintext to the TLS port gets nothing usable
        let plain = raw(addr, "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(!plain.starts_with("HTTP/1.1 200"), "{plain}");
        shut(addr, &s, h);
        let _ = std::fs::remove_dir_all(&pki.dir);
    }

    #[test]
    fn mutual_tls_demands_a_client_certificate_from_the_right_ca() {
        let pki = testpki::make("mtls");
        let tls =
            crate::tls::server_config(&pki.server_cert, &pki.server_key, Some(&pki.ca)).unwrap();
        let (addr, s, h) = start(
            &dummy(),
            Options {
                tls: Some(tls),
                ..opts(true)
            },
        );
        // the right certificate, and the token on top
        let r = https(
            addr,
            &pki,
            Some((&pki.client_cert, &pki.client_key)),
            "/v1/thing",
            Some(RO),
        )
        .unwrap();
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        // the certificate alone is not enough: the token is still required
        let r = https(
            addr,
            &pki,
            Some((&pki.client_cert, &pki.client_key)),
            "/v1/thing",
            None,
        )
        .unwrap();
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");
        // no certificate: no HTTP at all
        assert!(https(addr, &pki, None, "/v1/health", None).is_err());
        // a certificate from another CA: no HTTP at all
        assert!(
            https(
                addr,
                &pki,
                Some((&pki.other_client_cert, &pki.other_client_key)),
                "/v1/health",
                None
            )
            .is_err()
        );
        shut(addr, &s, h);
        let _ = std::fs::remove_dir_all(&pki.dir);
    }
}
