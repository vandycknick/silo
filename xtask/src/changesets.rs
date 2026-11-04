use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use crate::command;

const DATA: &str = "runtime/oci/testdata/changesets";

fn cargo(workspace: &Path, target: &Path, test: &str) -> Command {
    let mut command = if cfg!(target_os = "linux") {
        bounded("cargo")
    } else {
        Command::new("cargo")
    };
    command
        .current_dir(workspace)
        .env("CARGO_TARGET_DIR", target)
        .args([
            "test",
            "--locked",
            "-p",
            "oci",
            "--test",
            "changeset_conformance",
            test,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ]);
    command
}

fn absolute(workspace: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    }
}

pub fn fixtures(
    workspace: &Path,
    target: &Path,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let out = out
        .map(|path| absolute(workspace, path))
        .unwrap_or_else(|| workspace.join(DATA).join("generated"));
    let mut command = cargo(workspace, target, "tests::generate_goldens");
    command.env("SILO_CHANGESET_FIXTURES", out);
    command::run(command)?;
    Ok(())
}

fn require_linux() -> Result<(), Box<dyn Error>> {
    if !cfg!(target_os = "linux") {
        return Err("external changeset evidence requires Linux lstat/xattrs and GNU timeout; offline Rust fixture tests remain portable".into());
    }
    Ok(())
}

fn bounded(program: impl AsRef<std::ffi::OsStr>) -> Command {
    bounded_for(program, 290)
}

fn bounded_for(program: impl AsRef<std::ffi::OsStr>, seconds: u64) -> Command {
    let mut command = Command::new("timeout");
    command
        .args(["--signal=TERM", "--kill-after=5s"])
        .arg(format!("{seconds}s"))
        .arg(program);
    command
}

fn logged(mut process: Command, log: &Path) -> Result<(), Box<dyn Error>> {
    let output = File::create(log)?;
    process
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output));
    command::run(process).map_err(|error| format!("{error}; retained log {}", log.display()).into())
}

pub fn extractor(workspace: &Path, target: &Path, offline: bool) -> Result<(), Box<dyn Error>> {
    require_linux()?;
    let directory = target.join("changeset-tools");
    fs::create_dir_all(&directory)?;
    let mut process = bounded("go");
    process
        .current_dir(workspace.join(DATA).join("extractor"))
        .env("GOWORK", "off")
        .env("GOTOOLCHAIN", "local")
        .args(["build", "-mod=readonly", "-trimpath", "-o"])
        .arg(directory.join("extractor"))
        .arg(".");
    if offline {
        process.env("GOPROXY", "off").env("GOSUMDB", "off");
    }
    logged(process, &directory.join("build.log"))?;
    println!(
        "Pinned containerd v2.4.2 helper: {}",
        directory.join("extractor").display()
    );
    Ok(())
}

fn helper(target: &Path) -> Result<PathBuf, Box<dyn Error>> {
    require_linux()?;
    let path = target.join("changeset-tools/extractor");
    if !path.is_file() {
        return Err("build the pinned test-only helper first: make changeset-extractor".into());
    }
    Ok(path)
}

pub fn acquire(
    workspace: &Path,
    target: &Path,
    image: &str,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let helper = helper(target)?;
    let out = out
        .map(|path| absolute(workspace, path))
        .unwrap_or_else(|| target.join("changeset-acquired").join(image));
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut process = bounded(helper);
    process
        .arg("acquire")
        .arg("--corpus")
        .arg(workspace.join(DATA).join("corpus.json"))
        .arg("--image")
        .arg(image)
        .arg("--out")
        .arg(&out);
    command::run(process)?;
    println!(
        "Exact manifest/config/transport/decoded bytes retained in {}",
        out.display()
    );
    Ok(())
}

pub fn qualify(
    workspace: &Path,
    target: &Path,
    acquired: Option<PathBuf>,
    out: Option<PathBuf>,
    user_namespace: bool,
) -> Result<(), Box<dyn Error>> {
    let executable = helper(target)?;
    let acquired = acquired.map(|path| absolute(workspace, path));
    let request = if let Some(acquired) = &acquired {
        let mut process = cargo(workspace, target, "tests::qualify_acquired");
        process.env("SILO_CHANGESET_ACQUIRED", acquired);
        command::run(process)?;
        acquired.join("request.json")
    } else {
        workspace.join(DATA).join("generated/manifest.json")
    };
    if !request.is_file() {
        return Err(format!(
            "missing {}; run make changeset-fixtures first",
            request.display()
        )
        .into());
    }
    let out = out
        .map(|path| absolute(workspace, path))
        .unwrap_or_else(|| {
            target
                .join("changeset-qualification")
                .join(if acquired.is_some() {
                    "published"
                } else {
                    "synthetic"
                })
        });
    fs::create_dir_all(&out)?;
    let mut process = if user_namespace {
        let mut process = bounded("unshare");
        process
            .args(["--user", "--map-auto", "--map-root-user", "--mount"])
            .arg(&executable);
        process
    } else {
        bounded(&executable)
    };
    process
        .arg("apply")
        .arg("--request")
        .arg(&request)
        .arg("--out")
        .arg(&out);
    logged(process, &out.join("extractor.log"))?;
    println!(
        "External evidence: {} and {} (non-equality is preserved, not waived)",
        out.join("differences.json").display(),
        out.join("differences.md").display()
    );
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16384];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let hex = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

fn find_star(directory: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let objects = directory.join("star/OBJ");
    for entry in fs::read_dir(objects)? {
        let path = entry?.path().join("star");
        if path.is_file() {
            return Ok(path);
        }
    }
    Err("pinned star build produced no star/OBJ/*/star executable".into())
}

fn star_specimen(
    workspace: &Path,
    target: &Path,
    out: Option<PathBuf>,
    metadata: bool,
) -> Result<(), Box<dyn Error>> {
    let helper = helper(target)?;
    let tools = target.join("changeset-tools");
    fs::create_dir_all(&tools)?;
    let pin_path = workspace.join(DATA).join("star-source.json");
    let pin: serde_json::Value = serde_json::from_slice(&fs::read(&pin_path)?)?;
    let archive = tools.join("schilytools-source.tar.gz");
    let url = pin["url"].as_str().ok_or("missing star source URL")?;
    let expected = pin["sha256"].as_str().ok_or("missing star source hash")?;
    if !archive.is_file() {
        let mut download = bounded("curl");
        download
            .args(["--fail", "--location", "--max-time", "280", "--output"])
            .arg(&archive)
            .arg(url);
        command::run(download)?;
    }
    if file_digest(&archive)? != expected {
        return Err(
            "pinned schilytools source digest mismatch; retained source is not built".into(),
        );
    }
    if fs::metadata(&archive)?.len() != pin["length"].as_u64().ok_or("missing source length")? {
        return Err("pinned schilytools source length mismatch".into());
    }
    // Always build from a fresh verified extraction, never a mutable cached tree.
    let build_root = tempfile::tempdir_in(&tools)?;
    let mut unpack = bounded("tar");
    unpack
        .args(["--extract", "--gzip", "--file"])
        .arg(&archive)
        .arg("--directory")
        .arg(build_root.path());
    command::run(unpack)?;
    let source = build_root.path().join("schilytools");
    // COPTX is the upstream final C_FLAGS override, also propagated into both
    // global/local configure probes by RULES/{rules,local}.cnf. Pin the language
    // mode rather than hiding modern-GCC diagnostics or changing upstream code.
    let mut compiler = bounded("gcc");
    compiler.arg("--version").env("LC_ALL", "C");
    let compiler = command::output(compiler)?;
    // README.compile explicitly supports subtree builds after inc. Bootstrap
    // only the SMakefile RULES target (MKLINKS), then headers, the four static
    // archives named in star/Makefile LIBS, and star itself. Never invoke the
    // root "all", whose SSPM TARGETS list also builds unrelated programs.
    let common = ["CC=gcc", "COPTX=-std=gnu17", "CFLAGS=", "NOECHO="];
    let steps = [
        vec!["-f", "SMakefile", "RULES"],
        vec!["-C", "inc", "all"],
        vec!["-C", "libschily", "-f", "libschily.mk", "all"],
        vec!["-C", "libdeflt", "-f", "libdeflt.mk", "all"],
        vec!["-C", "librmt", "-f", "librmt.mk", "all"],
        vec!["-C", "libfind", "-f", "libfind.mk", "all"],
        vec!["-C", "star", "all"],
    ]
    .map(|mut arguments| {
        arguments.extend(common);
        arguments
    });
    let build_deadline_seconds = 600_u64;
    let environment: std::collections::BTreeMap<_, _> = [
        "PATH",
        "CC",
        "CFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "COPTX",
        "NIX_CFLAGS_COMPILE",
        "NIX_LDFLAGS",
        "C_INCLUDE_PATH",
        "LIBRARY_PATH",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok().map(|value| (name, value)))
    .collect();
    let build_recipe = serde_json::to_vec_pretty(&serde_json::json!({
        "schema":1,"source":pin,"compiler":"gcc","compilerVersion":String::from_utf8(compiler.stdout)?,
        "compilerStderr":String::from_utf8(compiler.stderr)?,"steps":&steps,"environment":environment,
        "buildDeadlineSeconds":build_deadline_seconds,"killGraceSeconds":5,
        "overrideEvidence":["RULES/cc-gcc.rul C_FLAGS includes COPTX last","RULES/rules.cnf and RULES/local.cnf pass C_FLAGS to configure CFLAGS"],
        "focusedBuildEvidence":["SMakefile RULES target runs MKLINKS without root all","README.compile permits subtree builds after inc","star/Makefile LIBS names deflt/rmt/find/schily","each named static .mk uses RULES/rules.lib all"]
    }))?;
    let build_evidence = tools.join("star-build.json");
    fs::write(&build_evidence, &build_recipe)?;
    let mut build_log = File::create(tools.join("star-build.log"))?;
    let build_started = std::time::Instant::now();
    for arguments in &steps {
        let remaining = build_deadline_seconds
            .checked_sub(build_started.elapsed().as_secs())
            .filter(|remaining| *remaining != 0)
            .ok_or(
                "focused star build exceeded its combined 600-second deadline; see star-build.log",
            )?;
        writeln!(
            build_log,
            "\n# make {arguments:?}; remaining deadline {remaining}s"
        )?;
        build_log.flush()?;
        let mut build = bounded_for("make", remaining);
        build
            .current_dir(&source)
            .args(arguments)
            .stdout(Stdio::from(build_log.try_clone()?))
            .stderr(Stdio::from(build_log.try_clone()?));
        command::run(build).map_err(|error| {
            format!(
                "{error}; retained focused build log {}",
                tools.join("star-build.log").display()
            )
        })?;
    }
    let star = find_star(&source)?;
    let out = out
        .map(|path| absolute(workspace, path))
        .unwrap_or_else(|| {
            workspace.join(DATA).join(if metadata {
                "metadata-producers"
            } else {
                "socket"
            })
        });
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut process = bounded(helper);
    process
        .arg(if metadata { "metadata" } else { "socket" })
        .arg("--star")
        .arg(star)
        .arg("--source-pin")
        .arg(pin_path)
        .arg("--build-evidence")
        .arg(&build_evidence)
        .arg("--out")
        .arg(&out);
    command::run(process)?;
    fs::write(out.join("build.json"), build_recipe)?;
    println!(
        "Real upstream specimen and producer/extraction evidence: {}",
        out.display()
    );
    Ok(())
}

pub fn socket(workspace: &Path, target: &Path, out: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    star_specimen(workspace, target, out, false)
}

pub fn metadata(
    workspace: &Path,
    target: &Path,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    star_specimen(workspace, target, out, true)
}
