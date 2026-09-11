#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    const RUNTIME_BOUND_TOKENS: &[&str] = &[
        "Runtime::",
        "ReadOnlyRuntime",
        "MachineBuilder",
        "machine: &Machine,",
        "machine: &libvm::Machine",
        "Result<libvm::Machine>",
        "runtime: &Runtime",
        "runtime: &libvm::Runtime",
        "ExecutionStdin",
    ];

    // This is the phase-one migration inventory. Remove entries as commands move
    // behind AppApi; adding a new direct-call site requires an explicit review.
    const TRANSITIONAL_FILES: &[&str] = &[
        "commands/cleanup.rs",
        "commands/forward.rs",
        "commands/logs.rs",
        "commands/run.rs",
        "commands/shell.rs",
        "commands/start_options.rs",
        "context.rs",
        "guest.rs",
    ];

    #[test]
    fn runtime_bound_handles_do_not_spread_beyond_the_migration_inventory() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("lib");
        let allowed = TRANSITIONAL_FILES.iter().copied().collect::<BTreeSet<_>>();
        let mut violations = Vec::new();

        for path in rust_files(&source_root) {
            let relative = path
                .strip_prefix(&source_root)
                .expect("source path is below CLI library root");
            let relative = relative.to_string_lossy();
            if relative.starts_with("api/")
                || relative == "boundary.rs"
                || allowed.contains(relative.as_ref())
            {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read CLI source");
            for token in RUNTIME_BOUND_TOKENS {
                if source.contains(token) {
                    violations.push(format!("{relative}: contains {token}"));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "new runtime-bound command coupling:\n{}",
            violations.join("\n")
        );
    }

    fn rust_files(root: &Path) -> Vec<PathBuf> {
        let mut pending = vec![root.to_path_buf()];
        let mut files = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(directory).expect("read CLI source directory") {
                let path = entry.expect("read CLI source entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    files.push(path);
                }
            }
        }
        files
    }
}
