//! Generic access-control / routing engine for the wind proxy framework.
//!
//! This crate is the single, protocol-agnostic place where wind servers express
//! "given a destination, which outbound (if any) serves it". It unifies the two
//! rule dialects that used to live in separate places:
//!
//! * **Clash / Mihomo rules** (`DOMAIN-SUFFIX,google.com,proxy`) — parsed by
//!   [`wind_core::rule`].
//! * **Hysteria-style ACL** (`proxy 10.6.0.0/16 tcp/443 [hijack]`) — parsed by
//!   this crate's [`acl`] module and compiled down to the same
//!   [`wind_core::rule::Rule`] representation via [`acl::acl_to_rules`].
//!
//! Both dialects feed a single [`AclEngine`], which implements
//! [`wind_core::Router`] and therefore drops straight into a
//! [`wind_core::Dispatcher`] / [`wind_core::App`]. The engine also folds in the
//! loopback / private-range guards that individual servers used to
//! re-implement.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use wind_acl::{AclEngine, GuardConfig};
//!
//! let engine = AclEngine::builder("direct")
//!     .clash_rules(["DOMAIN-SUFFIX,google.com,proxy", "IP-CIDR,10.0.0.0/8,direct"])?
//!     .hysteria_acl_str("reject private\nproxy *.example.com tcp/443")?
//!     .guards(GuardConfig { drop_loopback: true, drop_private: false })
//!     .resolver(resolver)        // required while any guard is enabled
//!     .build()?;
//!
//! let mut dispatcher = wind_core::Dispatcher::new(engine);
//! // dispatcher.add_handler("direct", ...);
//! ```
//!
//! # Not in v1
//!
//! * **Per-user / source-aware matching.** The [`wind_core::Router::route`]
//!   signature carries only the destination and the transport, so the
//!   [`MatchContext`](wind_core::rule::MatchContext) fields `src_ip` and
//!   `inbound_user` are always left `None`. Populating them needs a `route`
//!   signature change in `wind-core` and is deliberately out of scope.
//! * **Hijack / destination rewrite.** The Hysteria grammar parses the optional
//!   `hijack` field, but neither [`acl::acl_to_rules`] nor
//!   [`wind_core::RouteAction`] honor it today. The engine logs a warning if
//!   any rule sets it and otherwise ignores it — matching the prior behaviour.

pub mod acl;
mod config;
mod engine;

pub use config::AclConfig;
pub use engine::{AclEngine, AclEngineBuilder, GuardConfig};
