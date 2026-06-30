use std::path::{Path, PathBuf};

/// Resolve `~` and `~/...` prefixes in mount paths to the user's home directory.
pub fn resolve_mount_location(path: &Path) -> Result<PathBuf, String> {
    let raw = path.to_string_lossy();
    if raw == "~" {
        return home_dir().ok_or_else(|| "failed to resolve home directory for '~' mount".into());
    }

    if let Some(rest) = raw.strip_prefix("~/") {
        let mut home = home_dir()
            .ok_or_else(|| "failed to resolve home directory for '~' mount".to_string())?;
        if !rest.is_empty() {
            home.push(rest);
        }
        return Ok(home);
    }

    if raw.starts_with('~') {
        return Err(format!(
            "invalid mount path '{}': only '~' and '~/...' are supported",
            path.display()
        ));
    }

    Ok(path.to_path_buf())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
