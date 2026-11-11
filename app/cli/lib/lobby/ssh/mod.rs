//! SSH over accepted streams. Transport addresses select identity resolvers;
//! usernames, environment variables and forwarding requests have no authority.
//! Host keys live under the private lobby state directory. Session limits count
//! channels, including those awaiting their first exec or shell request.
//!
//! Unlike the Go frontend, this server uses bounded russh channel writers and
//! carries terminal resize and signal events directly through `SessionIo`.
//!
pub(crate) mod host_key;
pub(crate) mod input;
pub(crate) mod notices;
pub(crate) mod output;
pub(crate) mod server;
pub(crate) mod session;
