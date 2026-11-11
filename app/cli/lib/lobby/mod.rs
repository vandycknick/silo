//! The lobby: SSH-reachable VM management for tailnet peers, served by silod.
//! tsgate (Go) owns the tailnet node; everything else lives here.

// Wired into silod's supervisor once the lobby front ends exist.
#[allow(dead_code)]
pub(crate) mod tailnet;
