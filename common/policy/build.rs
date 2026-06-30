#[cfg(feature = "regenerate-ffi-header")]
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=BENTO_POLICY_REGENERATE_HEADER");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/ffi.rs");

    #[cfg(feature = "regenerate-ffi-header")]
    regenerate_header();
}

#[cfg(feature = "regenerate-ffi-header")]
fn regenerate_header() {
    if std::env::var_os("BENTO_POLICY_REGENERATE_HEADER").is_none() {
        return;
    }

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let config = cbindgen::Config::from_file(manifest_dir.join("cbindgen.toml"))
        .expect("load cbindgen config");
    let output = manifest_dir.join("../../net/netd/internal/policy/native/bento_policy.h");

    cbindgen::Builder::new()
        .with_crate(&manifest_dir)
        .with_config(config)
        .generate()
        .expect("generate bento_policy.h")
        .write_to_file(output);
}
