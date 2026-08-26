use std::env;
use std::error::Error;
use std::io;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Cargo did not provide CARGO_MANIFEST_DIR",
        )
    })?;
    let crate_dir = PathBuf::from(manifest_dir);
    let config_path = crate_dir.join("cbindgen.toml");
    let config = cbindgen::Config::from_file(config_path)?;
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()?
        .write_to_file(crate_dir.join("include/silo_go_ffi.h"));

    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");
    Ok(())
}
