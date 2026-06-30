//! POSIX shell implementation.
//!
//! Adapted from Armybox `src/applets/shell/*`.

#![allow(
    clippy::collapsible_else_if,
    clippy::collapsible_if,
    clippy::comparison_chain,
    clippy::manual_range_contains,
    clippy::needless_return
)]

mod arithmetic;
mod builtins;
mod control;
mod entry;
mod execute;
mod expand;
mod parser;
mod standalone;
mod state;
mod util;

use crate::applets::get_arg;

pub use entry::{ash, dash, sh};
pub use standalone::{echo, false_cmd, true_cmd};

use execute::execute_script;
use expand::expand_string;
use parser::parse_word;
use util::skip_whitespace_and_comments;
