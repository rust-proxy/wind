//! Per-project ACL / routing rule dialects ("syntaxes").
//!
//! Each submodule parses one upstream project's rule format into the shared
//! wind representation (`wind_core::rule::Rule` / this crate's [`Ruleset`]):
//!
//! * [`apernet`] — Hysteria ACL (`apernet/hysteria`): `proxy 10.0.0.0/8
//!   tcp/443`.
//! * `metacubex` — Clash / Mihomo rule lines (`MetaCubeX/mihomo`). Not yet a
//!   dedicated submodule: these are parsed today by `wind_core::rule`.
//! * `sagernet` — sing-box route rules (`SagerNet/sing-box`). Future work.
//!
//! [`Ruleset`]: crate::Ruleset

pub mod apernet;
