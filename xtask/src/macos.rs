use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use thiserror::Error;

use crate::app;
use crate::command;

const APP_NAME: &str = "Silo.app";

#[derive(Debug, Error)]
pub enum MacosError {
    #[error(transparent)]
    App(#[from] app::AppError),
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid macOS packaging input {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

pub fn package(
    workspace_root: &Path,
    target_dir: &Path,
    identity: Option<&str>,
) -> Result<(), MacosError> {
    let output = target_dir.join("package/macos");
    let app_bundle = output.join(APP_NAME);
    let version = app::product_version(workspace_root)?;
    app::verify_distribution(&app_bundle, &output)?;
    let create_dmg = ensure_create_dmg(workspace_root)?;
    let temporary_output = temporary_directory(&output, "dmg-output")?;
    let result = (|| {
        let mut create = Command::new(&create_dmg);
        create.arg("--overwrite");
        match identity {
            Some(identity) => create.arg(format!("--identity={identity}")),
            None => create.arg("--no-code-sign"),
        };
        create.arg(&app_bundle).arg(&temporary_output);
        command::run(create)?;

        let dmg = only_dmg(&temporary_output)?;
        let normalized = output.join(format!("silo-{version}-darwin-arm64.dmg"));
        if normalized.exists() {
            fs::remove_file(&normalized).map_err(|source| MacosError::Io {
                action: "remove prior normalized DMG",
                path: normalized.clone(),
                source,
            })?;
        }
        fs::rename(&dmg, &normalized).map_err(|source| MacosError::Io {
            action: "normalize DMG filename",
            path: normalized.clone(),
            source,
        })?;
        validate_regular_file(&normalized)?;
        verify_dmg(&normalized, &output)?;
        println!("package: {}", normalized.display());
        Ok(())
    })();
    remove_directory(&temporary_output, "remove temporary DMG output")?;
    result
}

pub fn install(target_dir: &Path, appdir: &Path, bindir: &Path) -> Result<(), MacosError> {
    require_absolute(appdir)?;
    require_absolute(bindir)?;
    create_directory(appdir)?;
    create_directory(bindir)?;

    let package_output = target_dir.join("package/macos");
    let source = package_output.join(APP_NAME);
    app::verify_distribution(&source, &package_output)?;
    let destination = appdir.join(APP_NAME);
    validate_replaced_app(&destination)?;
    let cli = bindir.join("silo");
    validate_replaced_cli(&cli)?;

    let temporary = temporary_path(appdir, "Silo.app-install")?;
    let result = (|| {
        let mut copy = Command::new("/usr/bin/ditto");
        copy.arg(&source).arg(&temporary);
        command::run(copy)?;
        app::verify_signed_bundle(&temporary)?;
        app::replace_bundle(&temporary, &destination)?;
        app::verify_distribution(&destination, &package_output)?;

        let temporary_link = temporary_path(bindir, "silo-link")?;
        symlink(destination.join("Contents/MacOS/silo"), &temporary_link).map_err(|source| {
            MacosError::Io {
                action: "create temporary Silo CLI symlink",
                path: temporary_link.clone(),
                source,
            }
        })?;
        fs::rename(&temporary_link, &cli).map_err(|source| MacosError::Io {
            action: "install Silo CLI symlink",
            path: cli.clone(),
            source,
        })?;
        if !app::is_owned_cli_symlink(&cli)? {
            return invalid(
                &cli,
                "does not resolve to the installed Silo.app CLI".to_string(),
            );
        }
        println!("install: {} and {}", destination.display(), cli.display());
        Ok(())
    })();
    if temporary.exists() {
        remove_directory(&temporary, "remove failed temporary app installation")?;
    }
    result
}

fn ensure_create_dmg(workspace_root: &Path) -> Result<PathBuf, MacosError> {
    let packaging = workspace_root.join("packaging/macos");
    let manifest = packaging.join("package.json");
    let lockfile = packaging.join("package-lock.json");
    let executable = packaging.join("node_modules/.bin/create-dmg");
    validate_regular_file(&manifest)?;
    validate_regular_file(&lockfile)?;
    let manifest_contents = fs::read_to_string(&manifest).map_err(|source| MacosError::Io {
        action: "read macOS packaging manifest",
        path: manifest.clone(),
        source,
    })?;
    if manifest_contents.contains("\"scripts\"") {
        return invalid(&manifest, "must not define package scripts".to_string());
    }

    if node_modules_stale(&manifest, &lockfile, &executable)? {
        let mut npm = Command::new("npm");
        npm.current_dir(&packaging)
            .args(["ci", "--prefer-offline", "--no-audit", "--no-fund"]);
        command::run(npm)?;
    }
    validate_local_create_dmg(&executable, &packaging.join("node_modules"))?;
    Ok(executable)
}

fn validate_local_create_dmg(executable: &Path, node_modules: &Path) -> Result<(), MacosError> {
    let resolved = fs::canonicalize(executable).map_err(|source| MacosError::Io {
        action: "resolve local create-dmg executable",
        path: executable.to_path_buf(),
        source,
    })?;
    let node_modules = fs::canonicalize(node_modules).map_err(|source| MacosError::Io {
        action: "resolve local node_modules directory",
        path: node_modules.to_path_buf(),
        source,
    })?;
    if !resolved.starts_with(&node_modules) {
        return invalid(
            executable,
            format!(
                "resolves outside local node_modules to {}",
                resolved.display()
            ),
        );
    }
    validate_regular_file(&resolved)
}

fn node_modules_stale(
    manifest: &Path,
    lockfile: &Path,
    executable: &Path,
) -> Result<bool, MacosError> {
    let installed_lockfile = executable
        .parent()
        .and_then(Path::parent)
        .map(|directory| directory.join(".package-lock.json"))
        .ok_or_else(|| MacosError::Invalid {
            path: executable.to_path_buf(),
            reason: "has no node_modules parent".to_string(),
        })?;
    if !executable.is_file() || !installed_lockfile.is_file() {
        return Ok(true);
    }
    let source_modified = newest_modified(&[manifest, lockfile])?;
    let installed_modified = modified(&installed_lockfile)?;
    Ok(installed_modified < source_modified)
}

fn newest_modified(paths: &[&Path]) -> Result<SystemTime, MacosError> {
    let mut newest = SystemTime::UNIX_EPOCH;
    for path in paths {
        newest = newest.max(modified(path)?);
    }
    Ok(newest)
}

fn modified(path: &Path) -> Result<SystemTime, MacosError> {
    fs::metadata(path)
        .map_err(|source| MacosError::Io {
            action: "read file metadata",
            path: path.to_path_buf(),
            source,
        })?
        .modified()
        .map_err(|source| MacosError::Io {
            action: "read file modification time",
            path: path.to_path_buf(),
            source,
        })
}

fn verify_dmg(dmg: &Path, temporary_parent: &Path) -> Result<(), MacosError> {
    let mounted = mount_dmg(dmg)?;
    let result = (|| {
        let app_bundle = mounted.mount_point.join(APP_NAME);
        app::verify_distribution(&app_bundle, temporary_parent)?;
        let applications = mounted.mount_point.join("Applications");
        let metadata = fs::symlink_metadata(&applications).map_err(|source| MacosError::Io {
            action: "read DMG Applications link",
            path: applications.clone(),
            source,
        })?;
        if !metadata.file_type().is_symlink()
            || fs::read_link(&applications).ok().as_deref() != Some(Path::new("/Applications"))
        {
            return invalid(
                &applications,
                "is not the expected /Applications symlink".to_string(),
            );
        }
        Ok(())
    })();
    let detach = detach_dmg(&mounted.device);
    match (result, detach) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(detach_error)) => Err(MacosError::Invalid {
            path: dmg.to_path_buf(),
            reason: format!("{error}; additionally failed to detach image: {detach_error}"),
        }),
    }
}

struct MountedDmg {
    device: String,
    mount_point: PathBuf,
}

fn mount_dmg(dmg: &Path) -> Result<MountedDmg, MacosError> {
    let mut attach = Command::new("/usr/bin/hdiutil");
    attach
        .args(["attach", "-readonly", "-nobrowse", "-plist"])
        .arg(dmg);
    let output = command::output(attach)?;
    let response = String::from_utf8_lossy(&output.stdout);
    let device = plist_string(&response, "dev-entry").ok_or_else(|| MacosError::Invalid {
        path: dmg.to_path_buf(),
        reason: "hdiutil response has no device entry".to_string(),
    })?;
    let result = (|| {
        let mount_point =
            plist_string(&response, "mount-point").ok_or_else(|| MacosError::Invalid {
                path: dmg.to_path_buf(),
                reason: "hdiutil response has no mount point".to_string(),
            })?;
        if !device.starts_with("/dev/") || !Path::new(&mount_point).is_absolute() {
            return invalid(dmg, "hdiutil returned an unsafe mount record".to_string());
        }
        Ok(MountedDmg {
            device: device.clone(),
            mount_point: PathBuf::from(mount_point),
        })
    })();
    if result.is_err() {
        detach_dmg(&device)?;
    }
    result
}

fn detach_dmg(device: &str) -> Result<(), MacosError> {
    let mut detach = Command::new("/usr/bin/hdiutil");
    detach.args(["detach", device]);
    command::run(detach)?;
    Ok(())
}

fn plist_string(response: &str, key: &str) -> Option<String> {
    let key = format!("<key>{key}</key>");
    let after_key = response.split_once(&key)?.1;
    let before_end = after_key.split_once("</string>")?.0;
    let value = before_end.split_once("<string>")?.1;
    Some(
        value
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">"),
    )
}

fn validate_replaced_app(path: &Path) -> Result<(), MacosError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || !app::has_bundle_identifier(path)?
            {
                return invalid(
                    path,
                    "refusing to replace an app not owned by Silo".to_string(),
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(MacosError::Io {
            action: "read existing app metadata",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_replaced_cli(path: &Path) -> Result<(), MacosError> {
    match fs::symlink_metadata(path) {
        Ok(_) if app::is_owned_cli_symlink(path)? => Ok(()),
        Ok(_) => invalid(
            path,
            "refusing to replace a CLI path not owned by Silo".to_string(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(MacosError::Io {
            action: "read existing CLI metadata",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn only_dmg(directory: &Path) -> Result<PathBuf, MacosError> {
    let entries = fs::read_dir(directory).map_err(|source| MacosError::Io {
        action: "read create-dmg output directory",
        path: directory.to_path_buf(),
        source,
    })?;
    let mut dmgs = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|source| MacosError::Io {
                action: "read create-dmg output entry",
                path: directory.to_path_buf(),
                source,
            })?
            .path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("dmg") {
            validate_regular_file(&path)?;
            dmgs.push(path);
        }
    }
    match dmgs.as_slice() {
        [dmg] => Ok(dmg.clone()),
        _ => invalid(
            directory,
            format!("create-dmg produced {} DMG files, expected one", dmgs.len()),
        ),
    }
}

fn require_absolute(path: &Path) -> Result<(), MacosError> {
    if path.is_absolute() {
        Ok(())
    } else {
        invalid(path, "must be an absolute path".to_string())
    }
}

fn create_directory(path: &Path) -> Result<(), MacosError> {
    fs::create_dir_all(path).map_err(|source| MacosError::Io {
        action: "create directory",
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| MacosError::Io {
        action: "read directory metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return invalid(path, "is not a real directory".to_string());
    }
    Ok(())
}

fn temporary_directory(parent: &Path, name: &str) -> Result<PathBuf, MacosError> {
    create_directory(parent)?;
    for attempt in 0..128 {
        let path = parent.join(format!(".{name}-{}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(MacosError::Io {
                    action: "create temporary directory",
                    path,
                    source,
                });
            }
        }
    }
    invalid(parent, "could not create a temporary directory".to_string())
}

fn temporary_path(parent: &Path, name: &str) -> Result<PathBuf, MacosError> {
    create_directory(parent)?;
    for attempt in 0..128 {
        let path = parent.join(format!(".{name}-{}-{attempt}", std::process::id()));
        match File::options().write(true).create_new(true).open(&path) {
            Ok(_) => {
                fs::remove_file(&path).map_err(|source| MacosError::Io {
                    action: "prepare temporary path",
                    path: path.clone(),
                    source,
                })?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(MacosError::Io {
                    action: "allocate temporary path",
                    path,
                    source,
                });
            }
        }
    }
    invalid(parent, "could not allocate a temporary path".to_string())
}

fn remove_directory(path: &Path, action: &'static str) -> Result<(), MacosError> {
    fs::remove_dir_all(path).map_err(|source| MacosError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })
}

fn validate_regular_file(path: &Path) -> Result<(), MacosError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| MacosError::Io {
        action: "read file metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return invalid(path, "is not a regular non-symlink file".to_string());
    }
    Ok(())
}

fn invalid<T>(path: &Path, reason: String) -> Result<T, MacosError> {
    Err(MacosError::Invalid {
        path: path.to_path_buf(),
        reason,
    })
}
