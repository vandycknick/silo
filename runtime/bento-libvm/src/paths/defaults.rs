use std::ffi::OsString;
use std::path::PathBuf;

use crate::LibVmError;

const APP_DIR_NAME: &str = "bento";

pub(crate) fn resolve_default_data_dir() -> Result<PathBuf, LibVmError> {
    let home = env_absolute_path("HOME")?;
    let data_home = env_absolute_path("XDG_DATA_HOME")?
        .or_else(|| home.as_ref().map(|path| path.join(".local/share")));

    data_home
        .map(|path| path.join(APP_DIR_NAME))
        .ok_or(LibVmError::DataDirUnavailable)
}

pub(crate) fn resolve_default_config_dir() -> Result<PathBuf, LibVmError> {
    let home = env_absolute_path("HOME")?;
    let config_home = env_absolute_path("XDG_CONFIG_HOME")?
        .or_else(|| home.as_ref().map(|path| path.join(".config")));

    config_home
        .map(|path| path.join(APP_DIR_NAME))
        .ok_or(LibVmError::ConfigDirUnavailable)
}

fn env_absolute_path(name: &'static str) -> Result<Option<PathBuf>, LibVmError> {
    match std::env::var_os(name) {
        Some(value) => absolute_path(name, value).map(Some),
        None => Ok(None),
    }
}

fn absolute_path(name: &'static str, value: OsString) -> Result<PathBuf, LibVmError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(LibVmError::RelativeEnvironmentPath { name, path })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::absolute_path;
    use crate::LibVmError;

    #[test]
    fn absolute_path_rejects_relative_env_values() {
        let err = absolute_path("XDG_DATA_HOME", OsString::from("relative"))
            .expect_err("relative path should be rejected");

        assert!(matches!(
            err,
            LibVmError::RelativeEnvironmentPath {
                name: "XDG_DATA_HOME",
                path
            } if path == Path::new("relative")
        ));
    }
}
