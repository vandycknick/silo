//! The lobby: SSH-reachable VM management for tailnet peers, served by silod.
//! tsgate (Go) owns the tailnet node; everything else lives here.
// The SSH and HTTP front ends and the silod supervisor arrive in the next
// commits; until then nothing outside tests reaches this module.
#![allow(dead_code)]

pub(crate) mod audit;
pub(crate) mod caller;
pub(crate) mod dispatch;
pub(crate) mod failure;
pub(crate) mod grammar;
pub(crate) mod identity;
pub(crate) mod jobs;
pub(crate) mod metrics;
pub(crate) mod redact;
pub(crate) mod service;
pub(crate) mod session;
pub(crate) mod state;
pub(crate) mod tailnet;
pub(crate) mod units;
pub(crate) mod views;
