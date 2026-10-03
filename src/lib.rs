//! The shared management-API transport of the wayang tools.
//!
//! `wayang-fw`, `wayang-router` and `wayang` each expose their operations as a
//! small local HTTP/JSON API. Everything that is the same for all three lives
//! here, so it is written, fixed and audited once:
//!
//! * [`http`] — HTTP/1.1 request parsing under a wall-clock budget, responses,
//!   the JSON envelope.
//! * [`auth`] — bearer tokens with scopes (`ro` < `rw` < `admin`).
//! * [`limit`] — per-peer rate limiting and token-guessing throttling.
//! * [`tls`] — TLS and mutual TLS (rustls).
//! * [`idem`] — `Idempotency-Key` replays.
//! * [`audit`] / [`events`] — the audit trail and its server-sent-events stream.
//! * [`server`] — the accept loop and the request pipeline; a tool implements
//!   [`server::App`] (its routes and handlers) and nothing else.
//!
//! The crate has no knowledge of any tool. It depends on `serde_json` and, for
//! TLS, `rustls` (the `ring` provider) — nothing else.

pub mod audit;
pub mod auth;
pub mod events;
pub mod http;
pub mod idem;
pub mod limit;
pub mod server;
pub mod tls;

pub use auth::{Principal, Scope, TokenStore};
pub use http::{Request, Response, err, json_response, ok_envelope};
pub use server::{App, Need, Options, Outcome, Route, Server};
