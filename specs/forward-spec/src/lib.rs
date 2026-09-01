//! Shared grammar and validation for Silo's vsock forwards.

mod endpoint;
mod forward;
mod target_line;

#[cfg(feature = "tokio")]
pub mod io;

pub use endpoint::{Address, AddressError, Endpoint, EndpointError};
pub use forward::{
    validate_forwards, Direction, Forward, ForwardError, ForwardShape, GuestHalf, Side, UnixMode,
    UnixModeError, RESERVED_RUNTIME_FILENAMES,
};
pub use target_line::{
    encode_connect, encode_reply, parse_connect, parse_reply, ErrReason, Reply, TargetLine,
    TargetLineError, Token, TokenError,
};

/// Vsock port used by the guest dialer and host return listener.
pub const FORWARD_VSOCK_PORT: u32 = 1028;
/// Guest agent control port, reserved for forward listen endpoints.
pub const GUEST_CONTROL_VSOCK_PORT: u32 = 1027;
/// Largest target or reply line, including its newline.
pub const MAX_TARGET_LINE_BYTES: usize = 512;
