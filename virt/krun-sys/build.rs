use std::env;
use std::path::{Path, PathBuf};

const LIBKRUN_VERSION: &str = "1.19.0";

fn main() {
    println!("cargo:rerun-if-env-changed=KRUN_DEPS_DIR");
    println!("cargo:rerun-if-env-changed=BENTO_KRUN_LINK_SYSTEM");

    #[cfg(feature = "regenerate")]
    generate_bindings();

    if let Some(dir) = env::var_os("KRUN_DEPS_DIR").map(PathBuf::from) {
        create_versioned_symlinks(&dir);
        println!("cargo:rustc-link-search=native={}", dir.display());
        println!("cargo:rustc-link-lib=dylib=krun");
        return;
    }

    if env::var_os("BENTO_KRUN_LINK_SYSTEM").is_some() {
        println!("cargo:rustc-link-lib=dylib=krun");
    }
}

#[cfg(feature = "regenerate")]
fn generate_bindings() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let header = manifest.join("include/libkrun.h");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("bindings.rs");
    bindgen::Builder::default()
        .header(header.to_string_lossy())
        .use_core()
        .allowlist_function("krun_.*")
        .allowlist_var("KRUN_.*")
        .allowlist_var("NET_.*")
        .allowlist_var("COMPAT_.*")
        .allowlist_var("VIRGLRENDERER_.*")
        .generate()
        .expect("generate libkrun bindings")
        .write_to_file(out)
        .expect("write libkrun bindings");
}

fn create_versioned_symlinks(dir: &Path) {
    if cfg!(target_os = "macos") {
        create_link(
            dir,
            "libkrun.dylib",
            &format!("libkrun.{}.dylib", major(LIBKRUN_VERSION)),
        );
    } else {
        create_link(
            dir,
            "libkrun.so",
            &format!("libkrun.so.{}", major(LIBKRUN_VERSION)),
        );
    }
}

fn create_link(dir: &Path, target: &str, link: &str) {
    let target_path = dir.join(target);
    let link_path = dir.join(link);
    if !target_path.exists() || link_path.exists() {
        return;
    }
    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink(target, link_path);
}

fn major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}
