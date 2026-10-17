use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};

use crate::command;
use crate::components::standard_cargo_command;
use crate::coverage::diff::{parse_go_total, parse_lcov, FileCoverage};
use crate::coverage::CoverageError;
use crate::targets::HostTarget;

pub fn coverage(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<(), CoverageError> {
    let output_dir = target_dir.join("coverage");
    if output_dir.exists() {
        fs::remove_dir_all(&output_dir).map_err(|error| CoverageError::io(&output_dir, error))?;
    }
    fs::create_dir_all(&output_dir).map_err(|error| CoverageError::io(&output_dir, error))?;

    rust_lane(workspace_root, target_dir, host, &output_dir)?;

    let binary_dir = target_dir.join("debug");
    let bridge = binary_dir.join(host.go_ffi_library());
    let runtime_dir = target_dir
        .join("silo-runtime")
        .join(host.runtime_target())
        .join("debug");
    let mut go_summary = Map::new();
    for (module, name, needs_stage) in [
        ("net/netd", "netd", false),
        ("app/taild", "taild", true),
        ("sdk/go", "sdk-go", true),
    ] {
        if needs_stage && (!bridge.is_file() || !runtime_dir.is_dir()) {
            println!("coverage: skipping {module} (run make stage)");
            continue;
        }
        let profile = output_dir.join(format!("{name}.cover"));
        let mut go = Command::new("go");
        go.current_dir(workspace_root.join(module))
            .args(["test", "-count=1", "-covermode=atomic"])
            .arg(format!("-coverprofile={}", profile.display()));
        if host != HostTarget::MacosArm64 {
            go.arg("-race");
        }
        if needs_stage {
            go.env("CGO_ENABLED", "1")
                .env("SILO_GO_FFI_PATH", &bridge)
                .env("SILO_TEST_RUNTIME_ROOT", &runtime_dir)
                .env("SILO_RUNTIME_DIR", &runtime_dir)
                .env("SILO_TEST_BIN_DIR", &binary_dir)
                .env("SILO_TEST_CLI", binary_dir.join("silo"));
        }
        go.arg("./...");
        command::run(go)?;
        let mut functions = Command::new("go");
        functions
            .current_dir(workspace_root.join(module))
            .args(["tool", "cover"])
            .arg(format!("-func={}", profile.display()));
        let functions = command::output(functions)?;
        let functions_path = output_dir.join(format!("{name}.func.txt"));
        let text =
            std::str::from_utf8(&functions.stdout).map_err(|source| CoverageError::Utf8 {
                path: functions_path.clone(),
                source,
            })?;
        fs::write(&functions_path, text)
            .map_err(|error| CoverageError::io(&functions_path, error))?;
        go_summary.insert(
            name.to_owned(),
            json!({"statements_pct": parse_go_total(text).map_err(|error| error.with_path(&functions_path))?}),
        );
    }

    let mut summary = Map::new();
    summary.insert(
        "rust".to_owned(),
        read_lcov_summary(&output_dir.join("rust.lcov"))?,
    );
    summary.insert("go".to_owned(), Value::Object(go_summary));
    if workspace_root.join("sdk/node/node_modules").is_dir() {
        let node_output = output_dir.join("node");
        let mut node = Command::new("npm");
        node.current_dir(workspace_root)
            .args(["--prefix", "sdk/node", "run", "test:coverage", "--"])
            .arg(format!(
                "--coverage.reportsDirectory={}",
                node_output.display()
            ));
        command::run(node)?;
        summary.insert(
            "node".to_owned(),
            read_lcov_summary(&node_output.join("lcov.info"))?,
        );
    } else {
        println!("coverage: skipping sdk/node (run npm --prefix sdk/node ci)");
    }
    let summary = Value::Object(summary);
    let summary_path = output_dir.join("summary.json");
    fs::write(&summary_path, serde_json::to_vec_pretty(&summary)?)
        .map_err(|error| CoverageError::io(&summary_path, error))?;
    print_summary(&summary);
    Ok(())
}

/// Rust coverage follows cargo-llvm-cov's "external tests" workflow instead of
/// `cargo llvm-cov nextest`: the supervisor tests spawn `silo-vmm` as a separate
/// process, and only binaries built under `show-env`'s instrumentation (and run
/// with its `LLVM_PROFILE_FILE`) report back. Everything is confined to
/// `<target>/llvm-cov-target` so the regular `target/debug` artifacts stay clean.
fn rust_lane(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
    output_dir: &Path,
) -> Result<(), CoverageError> {
    let coverage_target = target_dir.join("llvm-cov-target");
    let environment = instrumentation_environment(workspace_root, &coverage_target)?;
    let cargo = |args: &[&str]| {
        let mut cargo = standard_cargo_command(workspace_root, &coverage_target);
        cargo
            .envs(environment.iter().map(|(k, v)| (k, v)))
            .args(args);
        cargo
    };

    // `cargo llvm-cov clean --workspace` reaches into the workspace's regular target
    // dir as well; only the previous run's profiles must go.
    remove_profiles(&coverage_target)?;
    command::run(cargo(&[
        "build",
        "--locked",
        "-p",
        "silo-vmm",
        "--features",
        "mock-backend",
    ]))?;

    let mut tests = cargo(&[
        "nextest",
        "run",
        "--locked",
        "--workspace",
        "--lib",
        "--bins",
        "--tests",
        "--all-features",
    ]);
    tests.env(
        "SILO_TEST_MOCK_VMM_BINARY",
        coverage_target.join("debug").join("silo-vmm"),
    );
    for member in host.workspace_excludes() {
        tests.args(["--exclude", member]);
    }
    command::run(tests)?;
    command::run(cargo(&[
        "nextest",
        "run",
        "--locked",
        "-p",
        "rprobe",
        "--lib",
        "--no-default-features",
    ]))?;

    gather_stray_profiles(workspace_root, &coverage_target)?;

    // Supervisor tests SIGKILL mock monitors mid-flush, which leaves a truncated
    // profraw; the default `any` failure mode would then discard every profile.
    let mut lcov = cargo(&[
        "llvm-cov",
        "report",
        "--failure-mode",
        "all",
        "--lcov",
        "--output-path",
    ]);
    lcov.arg(output_dir.join("rust.lcov"));
    command::run(lcov)?;
    let mut html = cargo(&[
        "llvm-cov",
        "report",
        "--failure-mode",
        "all",
        "--html",
        "--output-dir",
    ]);
    html.arg(output_dir.join("rust-html"));
    command::run(html)?;
    Ok(())
}

/// Tests that spawn product binaries with a cleared environment leave the
/// children without `LLVM_PROFILE_FILE`, so their profiles land as
/// `default_*.profraw` in the crate directory that was the child's cwd. Move them
/// next to the others so they count and never show up as untracked files.
fn gather_stray_profiles(
    workspace_root: &Path,
    coverage_target: &Path,
) -> Result<(), CoverageError> {
    let mut pending = vec![workspace_root.to_path_buf()];
    let mut moved = 0usize;
    while let Some(directory) = pending.pop() {
        let entries =
            fs::read_dir(&directory).map_err(|error| CoverageError::io(&directory, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| CoverageError::io(&directory, error))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| CoverageError::io(&path, error))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if file_type.is_dir() {
                if !matches!(&*name, "target" | ".git" | "node_modules" | ".venv") {
                    pending.push(path);
                }
            } else if file_type.is_file()
                && name.starts_with("default_")
                && name.ends_with(".profraw")
            {
                moved += 1;
                let destination = coverage_target.join(format!("stray-{moved}-{name}"));
                fs::rename(&path, &destination)
                    .map_err(|error| CoverageError::io(&destination, error))?;
            }
        }
    }
    if moved > 0 {
        println!("coverage: gathered {moved} profiles from environment-cleared child processes");
    }
    Ok(())
}

/// Deletes the `.profraw`/`.profdata` files a previous run left in the coverage
/// target dir so stale counters never leak into the new report.
fn remove_profiles(coverage_target: &Path) -> Result<(), CoverageError> {
    let entries = match fs::read_dir(coverage_target) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CoverageError::io(coverage_target, error)),
    };
    for entry in entries {
        let path = entry
            .map_err(|error| CoverageError::io(coverage_target, error))?
            .path();
        let is_profile = matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("profraw" | "profdata")
        );
        if is_profile {
            fs::remove_file(&path).map_err(|error| CoverageError::io(&path, error))?;
        }
    }
    Ok(())
}

/// The variables `cargo llvm-cov show-env` prints (rustc wrapper, profile file
/// pattern, cfg flags), plus the target-dir pins that keep build artifacts,
/// profiles and the report lookup in the same directory.
fn instrumentation_environment(
    workspace_root: &Path,
    coverage_target: &Path,
) -> Result<Vec<(String, String)>, CoverageError> {
    let mut show_env = standard_cargo_command(workspace_root, coverage_target);
    show_env
        .env("CARGO_LLVM_COV_TARGET_DIR", coverage_target)
        .args(["llvm-cov", "show-env"]);
    let output = command::output(show_env)?;
    let text = std::str::from_utf8(&output.stdout).map_err(|source| CoverageError::Utf8 {
        path: PathBuf::from("cargo llvm-cov show-env"),
        source,
    })?;
    let mut environment = parse_show_env(text);
    let pinned = coverage_target.to_string_lossy().into_owned();
    environment.push(("CARGO_TARGET_DIR".to_owned(), pinned.clone()));
    environment.push(("CARGO_LLVM_COV_TARGET_DIR".to_owned(), pinned));
    Ok(environment)
}

/// `show-env` prints one `KEY=VALUE` per line, single-quoting values that need it.
fn parse_show_env(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            let value = value
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
                .map(|inner| inner.replace("'\\''", "'"))
                .unwrap_or_else(|| value.to_owned());
            (key.to_owned(), value)
        })
        .collect()
}

fn read_lcov_summary(path: &Path) -> Result<Value, CoverageError> {
    let input = fs::read_to_string(path).map_err(|error| CoverageError::io(path, error))?;
    lcov_summary(&input).map_err(|error| error.with_path(path))
}

fn lcov_summary(input: &str) -> Result<Value, CoverageError> {
    let files = parse_lcov(input)?;
    Ok(summarize_files(&files))
}

fn summarize_files(files: &BTreeMap<String, FileCoverage>) -> Value {
    let mut covered_lines = 0;
    let mut total_lines = 0;
    let mut covered_functions = 0;
    let mut total_functions = 0;
    for file in files.values() {
        covered_lines += file.lines.0;
        total_lines += file.lines.1;
        covered_functions += file.functions.values().filter(|hits| **hits > 0).count() as u64;
        total_functions += file.functions.len() as u64;
    }
    json!({
        "lines": {"covered": covered_lines, "total": total_lines},
        "functions": {"covered": covered_functions, "total": total_functions},
    })
}

fn print_summary(summary: &Value) {
    println!(
        "{:<12} {:<12} {:>12} {:>12}",
        "Lane", "Metric", "Covered", "Total"
    );
    for lane in ["rust", "node"] {
        if let Some(metrics) = summary.get(lane) {
            for metric in ["lines", "functions"] {
                println!(
                    "{lane:<12} {metric:<12} {:>12} {:>12}",
                    metrics[metric]["covered"], metrics[metric]["total"]
                );
            }
        }
    }
    if let Some(modules) = summary.get("go").and_then(Value::as_object) {
        for (name, metrics) in modules {
            println!("{name:<12} statements   {:>11}%", metrics["statements_pct"]);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::coverage::collect::{lcov_summary, parse_show_env};
    use crate::coverage::diff::parse_go_total;
    use serde_json::json;

    #[test]
    fn show_env_values_are_unquoted() {
        let parsed = parse_show_env(
            "LLVM_PROFILE_FILE='/t/silo-%p-%12m.profraw'\nCARGO_LLVM_COV=1\nX='it'\\''s'\n",
        );
        assert_eq!(
            parsed,
            vec![
                (
                    "LLVM_PROFILE_FILE".to_owned(),
                    "/t/silo-%p-%12m.profraw".to_owned()
                ),
                ("CARGO_LLVM_COV".to_owned(), "1".to_owned()),
                ("X".to_owned(), "it's".to_owned()),
            ]
        );
    }

    #[test]
    fn summary_counts_records_across_files() {
        let input = "SF:src/a.rs\nFNDA:2,covered\nFNDA:0,missed\nDA:1,2\nDA:2,0\nend_of_record\nSF:src/b.rs\nFNDA:1,other\nDA:3,1\nend_of_record\n";
        assert_eq!(
            lcov_summary(input).unwrap(),
            json!({
                "lines": {"covered": 2, "total": 3},
                "functions": {"covered": 2, "total": 3},
            })
        );
    }

    #[test]
    fn empty_summary_has_zero_totals() {
        assert_eq!(
            lcov_summary("").unwrap(),
            json!({
                "lines": {"covered": 0, "total": 0},
                "functions": {"covered": 0, "total": 0},
            })
        );
    }

    #[test]
    fn go_total_accepts_report_whitespace() {
        assert_eq!(
            parse_go_total("example/file.go:10:\twork\t100.0%\ntotal:\t(statements)\t73.5%\n")
                .unwrap(),
            73.5
        );
        assert_eq!(
            parse_go_total("total:   (statements)   0.0%\n").unwrap(),
            0.0
        );
        assert_eq!(
            parse_go_total("total:\t(statements)\t100%\n").unwrap(),
            100.0
        );
    }

    #[test]
    fn go_total_requires_valid_percentage() {
        for input in [
            "",
            "total: (statements) nope%",
            "total: (statements) 101%",
            "total: (statements) 20",
        ] {
            assert!(parse_go_total(input).is_err(), "{input}");
        }
    }
}
