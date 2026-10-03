# wayang-api

The shared management-API transport of the wayang tools (`wayang-fw`,
`wayang-router`, `wayang`). Each tool implements its routes; everything around
them — HTTP, authentication, scopes, rate limiting, TLS/mTLS, idempotency, the
audit trail and its event stream — is written once, here.

```
client ──► TLS? ──► rate limit ──► method ──► /v1/health (open)
                                      │
                       token (failures throttled per peer) → 401
                                      │
              /v1/audit · /v1/events (shared) ── or ── App::route
                                      │
        404 unknown · 405 wrong method · 403 scope / read-only server
                                      │
                 Idempotency-Key replay ► App::handle ► audit + event
```

Authentication comes **before** the route table: an anonymous peer learns
nothing about what the server offers or allows.

## Using it

```rust
use std::sync::Arc;
use wayang_api::{App, Need, Options, Principal, Request, Response, Route, Server, TokenStore, ok_envelope};

struct Tool;
impl App for Tool {
    fn name(&self) -> &str { "wayang-tool" }
    fn health(&self) -> serde_json::Value { serde_json::json!({ "version": "1" }) }
    fn route(&self, m: &str, p: &str) -> Route {
        match (m, p) {
            ("GET", "/v1/thing") => Route::Known(Need::Read),
            ("PUT", "/v1/thing") => Route::Known(Need::Write),
            (_, "/v1/thing") => Route::WrongMethod("GET, PUT"),
            _ => Route::Unknown,
        }
    }
    fn handle(&self, req: &Request, who: &Principal) -> Response {
        ok_envelope(serde_json::json!({ "by": who.label }), None, None)
    }
}

let server = Arc::new(Server::new(Arc::new(Tool), Options {
    tokens: TokenStore::load("/data/etc/tool/api-token".as_ref()),
    rw: false,                       // read-only unless the operator passes --rw
    ..Options::default()
})?);
server.serve(std::net::TcpListener::bind("127.0.0.1:8630")?);
```

## Tokens and scopes

A token file has one token per line: `scope token [label]`, scope `ro`, `rw` or
`admin` (a bare token is `rw`, the behaviour before scopes). `ro` reads, `rw`
may change the configuration, `admin` may also do what a tool marks
[`Need::Admin`] (an OS update, a reset). A server started without `rw` refuses
every write whatever the token (`403 read_only`); a token below the needed
scope gets `403 forbidden`. `auth::gen_token` writes a fresh token 0600.

Failed authentications are throttled per peer (5, then one more every 12 s):
past that even a valid token from the same address gets `429` until the bucket
refills.

## TLS and mTLS

`tls::server_config(cert, key, client_ca)` — PEM files; with a `client_ca` the
handshake **requires** a client certificate signed by it, and the bearer token is
still checked on top. TLS 1.2 and 1.3. The crypto provider is `ring`; building for
`x86_64-unknown-linux-musl` needs a C compiler (`CC_x86_64_unknown_linux_musl=musl-gcc`
or `gcc`).

## Limits

One thread per connection, at most `max_conns` (32; more get `503`); a request
must arrive within 10 s; bodies up to 1 MiB (`413`); header block 64 KiB;
rate limit 60 burst / 20 per second per peer; 8 concurrent `/v1/events`
streams. All configurable in [`Options`].

## The shared routes

* `GET /v1/audit?limit=N` — newest first (default 50, max 500).
* `GET /v1/events` — server-sent events: every audited request as `event: audit`,
  `id:` numbered, `: keepalive` every 15 s. `Last-Event-ID` (or `?last_id=`)
  resumes from the last 256; a new subscriber starts at "now".

The audit trail is one JSON line per mutating request, accepted or refused
(method, path, status, peer, token label and scope, `Idempotency-Key`, revision) — never a body, a
query string or a token.

MIT.
