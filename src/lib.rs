//! OxiServe — an nginx-configuration-compatible web server.
//!
//! The crate is split into three layers:
//!
//! * [`config`] turns an `nginx.conf` into a fully-resolved runtime model.
//!   Nothing here runs per request.
//! * [`http`] is the wire format — request parsing, response building, URI
//!   normalisation. Zero-copy where it matters.
//! * [`server`] is the data plane: listeners, the per-connection state machine,
//!   and the handlers that turn a matched location into bytes.
//!
//! The performance strategy is a thread-per-core runtime with per-worker
//! `SO_REUSEPORT` listeners, so an accepted connection is handled start to
//! finish on one core with no cross-thread handoff and no shared mutable state
//! on the request path.

pub mod config;
pub mod http;
pub mod mime;
pub mod server;
