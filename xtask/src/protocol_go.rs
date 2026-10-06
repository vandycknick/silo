use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::command;

const MODULE: &str = "github.com/vandycknick/silo/specs/protocol/go";
const GENERATED: [&str; 2] = [
    "silo/daemon/v1/daemon.pb.go",
    "silo/daemon/v1/daemon_grpc.pb.go",
];

pub fn generate(workspace: &Path, check: bool) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let tools = temporary.path().join("tools");
    let output = temporary.path().join("output");
    fs::create_dir(&tools)?;
    fs::create_dir(&output)?;
    let module = workspace.join("specs/protocol/go");
    for tool in [
        "google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12",
        "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2",
    ] {
        let mut install = Command::new("go");
        install
            .current_dir(&module)
            .env("GOBIN", &tools)
            .env("GOWORK", "off")
            .args(["install", tool]);
        command::run(install)?;
    }
    let sources = workspace.join("specs/silod-spec/proto");
    let mut protoc = Command::new(protoc_bin_vendored::protoc_bin_path()?);
    protoc
        .arg(format!(
            "--plugin=protoc-gen-go={}",
            tools.join("protoc-gen-go").display()
        ))
        .arg(format!(
            "--plugin=protoc-gen-go-grpc={}",
            tools.join("protoc-gen-go-grpc").display()
        ))
        .arg(format!("--go_out={}", output.display()))
        .arg(format!("--go_opt=module={MODULE}"))
        .arg(format!("--go-grpc_out={}", output.display()))
        .arg(format!("--go-grpc_opt=module={MODULE}"))
        .arg("-I")
        .arg(&sources)
        .arg("-I")
        .arg(protoc_bin_vendored::include_path()?)
        .arg(sources.join("daemon.proto"));
    command::run(protoc)?;
    for relative in GENERATED {
        let generated = fs::read(output.join(relative))?;
        let committed = module.join(relative);
        if check {
            if fs::read(&committed).ok().as_deref() != Some(generated.as_slice()) {
                return Err(format!(
                    "generated management binding differs: {}; run make protocol-go",
                    committed.display()
                )
                .into());
            }
        } else {
            let parent = committed.parent().ok_or("generated path has no parent")?;
            fs::create_dir_all(parent)?;
            fs::write(committed, generated)?;
        }
    }
    println!(
        "Go management bindings {}",
        if check {
            "match committed output"
        } else {
            "generated"
        }
    );
    Ok(())
}
