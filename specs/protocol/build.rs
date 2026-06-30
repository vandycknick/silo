fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/common.proto");
    println!("cargo:rerun-if-changed=proto/guest.proto");
    println!("cargo:rerun-if-changed=proto/vm_monitor.proto");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_prost_build::configure().compile_protos(
        &[
            "proto/common.proto",
            "proto/guest.proto",
            "proto/vm_monitor.proto",
        ],
        &["proto"],
    )?;

    Ok(())
}
