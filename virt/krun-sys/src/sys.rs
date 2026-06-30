#![allow(
    missing_docs,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    clippy::all,
    reason = "generated bindgen output"
)]

#[cfg(feature = "regenerate")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(not(feature = "regenerate"))]
include!("bindings.rs");
