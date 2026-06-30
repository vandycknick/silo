use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=KRUN_DEPS_DIR");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-arg-bin=krun=-Wl,-rpath,@loader_path");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-arg-bin=krun=-Wl,-rpath,$ORIGIN");
    }

    let Some(deps_dir) = env::var_os("KRUN_DEPS_DIR").map(PathBuf::from) else {
        return;
    };
    let Some(profile) = env::var_os("PROFILE") else {
        return;
    };
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        return;
    };

    let target_dir = manifest_dir
        .ancestors()
        .nth(2)
        .map(|workspace| workspace.join("target").join(profile))
        .unwrap_or_else(|| PathBuf::from("target"));

    if let Ok(entries) = std::fs::read_dir(deps_dir) {
        let _ = std::fs::create_dir_all(&target_dir);
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(file_name) = path.file_name() else {
                continue;
            };
            let name = file_name.to_string_lossy();
            let is_library = name == "libkrun.so"
                || name.starts_with("libkrun.so.")
                || name == "libkrun.dylib"
                || (name.starts_with("libkrun.") && name.ends_with(".dylib"));
            if is_library {
                let _ = std::fs::copy(&path, target_dir.join(file_name));
            }
        }
    }
}
