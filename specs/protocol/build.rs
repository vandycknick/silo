fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/common.proto");
    println!("cargo:rerun-if-changed=proto/errors.proto");
    println!("cargo:rerun-if-changed=proto/filesystem.proto");
    println!("cargo:rerun-if-changed=proto/guest.proto");
    println!("cargo:rerun-if-changed=proto/vm_monitor.proto");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    let descriptor_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("silo-v1-descriptor.bin");

    let mut config = prost_build::Config::new();
    config.skip_source_info();

    tonic_prost_build::configure()
        .file_descriptor_set_path(descriptor_path)
        .bytes(".silo.v1.ByteChunk.data")
        .compile_with_config(
            config,
            &[
                "proto/common.proto",
                "proto/errors.proto",
                "proto/filesystem.proto",
                "proto/guest.proto",
                "proto/vm_monitor.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
