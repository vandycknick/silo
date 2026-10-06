fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/daemon.proto");
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    let mut config = prost_build::Config::new();
    config.btree_map(["."]);
    config.boxed(".silo.daemon.v1.CreateMachineEvent.event.machine");
    config.boxed(".silo.daemon.v1.AgentStatus.status.enabled");
    config.skip_debug([
        ".silo.daemon.v1.HelperBootstrap",
        ".silo.daemon.v1.EgressSecret",
        ".silo.daemon.v1.SetMachineSecretRequest",
    ]);
    config.skip_source_info();
    tonic_prost_build::configure().compile_with_config(
        config,
        &[std::path::PathBuf::from("proto/daemon.proto")],
        &[
            std::path::PathBuf::from("proto"),
            protoc_bin_vendored::include_path()?,
        ],
    )?;
    Ok(())
}
