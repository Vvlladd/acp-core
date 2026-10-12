//! `agent-control-plane` — the `acp` control plane library.
//!
//! Leads drive it over MCP (`mcp::server`, stdio); humans and the macOS app drive it over the
//! local Unix socket (`ipc::socket`). `core` owns all state and is the only writer of the event
//! log; provider-, IDE- and platform-specific knowledge lives in `providers` and `workspace`.
//!
//! See `reports/03-design.md` § Components for the contract each module implements.

pub mod core;
pub mod providers;
pub mod workspace;
pub mod roles;
pub mod mcp;
pub mod ipc;
pub mod checks;
