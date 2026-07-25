use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

const APPLICATIONS_LINK: &str = "Applications";
const FILESYSTEM_BLOCK_SIZE: u64 = 4096;
const FILE_MODE: u32 = 0o644;
const IMAGE_OVERHEAD_BYTES: u64 = 128 * 1024 * 1024;
const RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];
const VOLUME_FINDER_INFO: &str = "0000000000000000040000000000000000000000000000000000000000000000";

#[derive(Clone, Copy)]
pub(crate) struct DmgSpec<'a> {
    pub(crate) root: &'a Path,
    pub(crate) app: &'a Path,
    pub(crate) volume_icon: &'a Path,
    pub(crate) finder_layout: &'a Path,
    pub(crate) volume_name: &'a str,
    pub(crate) output: &'a Path,
}

#[derive(Debug, Error)]
pub(crate) enum DmgError {
    #[error("required disk image input is missing or has the wrong type: {path}")]
    MissingInput { path: PathBuf },
    #[error("invalid disk image input at {path}: {reason}")]
    InvalidInput { path: PathBuf, reason: String },
    #[error("failed to {operation} {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("failed to run {command}")]
    RunCommand { command: String, source: io::Error },
    #[error("command failed ({command}): {output}")]
    CommandFailed { command: String, output: String },
}

struct WritableImage {
    mount_point: PathBuf,
    attached: bool,
}

impl WritableImage {
    fn attach(image: &Path, mount_point: PathBuf) -> Result<Self, DmgError> {
        fs::create_dir(&mount_point).map_err(|source| DmgError::Io {
            operation: "create writable disk image mount point",
            path: mount_point.clone(),
            source,
        })?;
        let mut command = Command::new("/usr/bin/hdiutil");
        command
            .env("LC_ALL", "C")
            .args([
                "attach",
                "-quiet",
                "-nobrowse",
                "-noverify",
                "-noautoopen",
                "-owners",
                "off",
                "-mountpoint",
            ])
            .arg(&mount_point)
            .arg(image);
        let mounted = Self {
            mount_point,
            attached: true,
        };
        run(command)?;
        Ok(mounted)
    }

    fn detach(mut self) -> Result<(), DmgError> {
        let mount_point = self.mount_point.clone();
        run_hdiutil_with_retries("detach", &mount_point, || {
            let mut command = Command::new("/usr/bin/hdiutil");
            command
                .env("LC_ALL", "C")
                .args(["detach", "-quiet"])
                .arg(&mount_point);
            command
        })?;
        self.attached = false;
        Ok(())
    }
}

impl Drop for WritableImage {
    fn drop(&mut self) {
        if self.attached {
            let _ = Command::new("/usr/bin/hdiutil")
                .env("LC_ALL", "C")
                .args(["detach", "-quiet", "-force"])
                .arg(&self.mount_point)
                .status();
        }
    }
}

pub(crate) fn create(spec: DmgSpec<'_>) -> Result<(), DmgError> {
    require_directory(spec.root)?;
    require_directory(spec.app)?;
    require_regular_file(spec.volume_icon)?;
    require_regular_file(spec.finder_layout)?;

    let image_size = image_size(spec.app)?;
    let writable = spec.root.join(format!("{}.dmg", nonce("writable-dmg")));
    run_hdiutil_with_retries("create", &writable, || {
        hdiutil_create_command(&writable, spec.volume_name, &image_size)
    })?;

    let mounted = WritableImage::attach(&writable, spec.root.join(nonce("writable-dmg-mount")))?;
    populate(&mounted.mount_point, spec)?;
    mounted.detach()?;

    run_hdiutil_with_retries("convert", spec.output, || {
        hdiutil_convert_command(&writable, spec.output)
    })?;
    fs::remove_file(&writable).map_err(|source| DmgError::Io {
        operation: "remove writable disk image",
        path: writable,
        source,
    })
}

fn populate(mount_point: &Path, spec: DmgSpec<'_>) -> Result<(), DmgError> {
    let app_name = spec.app.file_name().ok_or_else(|| DmgError::InvalidInput {
        path: spec.app.to_path_buf(),
        reason: "application bundle has no file name".to_string(),
    })?;
    let app_destination = mount_point.join(app_name);
    let mut ditto = Command::new("/usr/bin/ditto");
    ditto.arg(spec.app).arg(&app_destination);
    run(ditto)?;

    let applications = mount_point.join(APPLICATIONS_LINK);
    symlink("/Applications", &applications).map_err(|source| DmgError::Io {
        operation: "create Applications link",
        path: applications,
        source,
    })?;

    let volume_icon = mount_point.join(".VolumeIcon.icns");
    copy_file(
        spec.volume_icon,
        &volume_icon,
        "copy disk image volume icon",
    )?;
    let mut xattr = Command::new("/usr/bin/xattr");
    xattr
        .args(["-w", "-x", "com.apple.FinderInfo", VOLUME_FINDER_INFO])
        .arg(mount_point);
    run(xattr)?;

    copy_file(
        spec.finder_layout,
        &mount_point.join(".DS_Store"),
        "copy disk image Finder layout",
    )
}

fn image_size(app: &Path) -> Result<String, DmgError> {
    let mut size = IMAGE_OVERHEAD_BYTES;
    let mut directories = vec![app.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| DmgError::Io {
            operation: "read application bundle while sizing disk image",
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| DmgError::Io {
                operation: "read application bundle entry while sizing disk image",
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| DmgError::Io {
                operation: "inspect application bundle entry while sizing disk image",
                path: path.clone(),
                source,
            })?;
            if metadata.is_dir() {
                directories.push(path);
                size = add_size(size, FILESYSTEM_BLOCK_SIZE, app)?;
            } else if metadata.is_file() && !metadata.file_type().is_symlink() {
                let rounded = metadata
                    .len()
                    .checked_add(FILESYSTEM_BLOCK_SIZE - 1)
                    .map(|size| size / FILESYSTEM_BLOCK_SIZE * FILESYSTEM_BLOCK_SIZE)
                    .ok_or_else(|| image_too_large(app))?;
                size = add_size(size, rounded, app)?;
            } else {
                return Err(DmgError::InvalidInput {
                    path,
                    reason: "application bundle contains a symlink or special file".to_string(),
                });
            }
        }
    }

    let size_kib = size
        .checked_add(1023)
        .map(|size| size / 1024)
        .ok_or_else(|| image_too_large(app))?;
    Ok(format!("{size_kib}k"))
}

fn add_size(current: u64, additional: u64, app: &Path) -> Result<u64, DmgError> {
    current
        .checked_add(additional)
        .ok_or_else(|| image_too_large(app))
}

fn image_too_large(app: &Path) -> DmgError {
    DmgError::InvalidInput {
        path: app.to_path_buf(),
        reason: "application bundle is too large to represent as a disk image".to_string(),
    }
}

fn hdiutil_create_command(image: &Path, volume_name: &str, size: &str) -> Command {
    let mut command = Command::new("/usr/bin/hdiutil");
    command
        .env("LC_ALL", "C")
        .args([
            "create",
            "-ov",
            "-type",
            "UDIF",
            "-volname",
            volume_name,
            "-fs",
            "HFS+",
            "-fsargs",
            "-c c=64,a=16,e=16",
            "-nospotlight",
            "-size",
            size,
        ])
        .arg(image);
    command
}

fn hdiutil_convert_command(writable: &Path, output: &Path) -> Command {
    let mut command = Command::new("/usr/bin/hdiutil");
    command
        .env("LC_ALL", "C")
        .arg("convert")
        .arg(writable)
        .args(["-format", "UDZO", "-imagekey", "zlib-level=9", "-ov", "-o"])
        .arg(output);
    command
}

fn run_hdiutil_with_retries<F>(operation: &str, path: &Path, mut command: F) -> Result<(), DmgError>
where
    F: FnMut() -> Command,
{
    let attempts = RETRY_DELAYS
        .iter()
        .copied()
        .map(Some)
        .chain(std::iter::once(None));
    for (attempt, retry_delay) in attempts.enumerate() {
        let (rendered, output) = capture_command(command())?;
        if output.status.success() {
            return Ok(());
        }

        let delay = match (is_transient_hdiutil_error(&output), retry_delay) {
            (true, Some(delay)) => delay,
            _ => {
                return Err(DmgError::CommandFailed {
                    command: rendered,
                    output: command_output(&output),
                });
            }
        };
        eprintln!(
            "hdiutil {operation} for {} was temporarily unavailable; retrying attempt {} of {} in {} seconds",
            path.display(),
            attempt + 2,
            RETRY_DELAYS.len() + 1,
            delay.as_secs(),
        );
        thread::sleep(delay);
    }

    Err(DmgError::InvalidInput {
        path: path.to_path_buf(),
        reason: format!("hdiutil {operation} exhausted its retry loop"),
    })
}

fn is_transient_hdiutil_error(output: &Output) -> bool {
    [&output.stdout, &output.stderr].iter().any(|stream| {
        let stream = String::from_utf8_lossy(stream);
        stream.contains("Resource temporarily unavailable") || stream.contains("Resource busy")
    })
}

fn copy_file(source: &Path, destination: &Path, operation: &'static str) -> Result<(), DmgError> {
    fs::copy(source, destination).map_err(|source| DmgError::Io {
        operation,
        path: destination.to_path_buf(),
        source,
    })?;
    fs::set_permissions(destination, fs::Permissions::from_mode(FILE_MODE)).map_err(|source| {
        DmgError::Io {
            operation: "set disk image metadata mode",
            path: destination.to_path_buf(),
            source,
        }
    })
}

fn require_directory(path: &Path) -> Result<(), DmgError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DmgError::MissingInput {
        path: path.to_path_buf(),
    })?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(DmgError::MissingInput {
            path: path.to_path_buf(),
        })
    }
}

fn require_regular_file(path: &Path) -> Result<(), DmgError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DmgError::MissingInput {
        path: path.to_path_buf(),
    })?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(DmgError::MissingInput {
            path: path.to_path_buf(),
        })
    }
}

fn run(command: Command) -> Result<(), DmgError> {
    run_capture(command).map(|_| ())
}

fn run_capture(command: Command) -> Result<Output, DmgError> {
    let (rendered, output) = capture_command(command)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(DmgError::CommandFailed {
            command: rendered,
            output: command_output(&output),
        })
    }
}

fn capture_command(mut command: Command) -> Result<(String, Output), DmgError> {
    let rendered = format!("{command:?}");
    let output = command.output().map_err(|source| DmgError::RunCommand {
        command: rendered.clone(),
        source,
    })?;
    Ok((rendered, output))
}

fn command_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    match (stdout.trim(), stderr.trim()) {
        ("", "") => "no command output".to_string(),
        (stdout, "") => stdout.to_string(),
        ("", stderr) => stderr.to_string(),
        (stdout, stderr) => format!("stdout: {stdout}; stderr: {stderr}"),
    }
}

fn nonce(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(".{kind}-{}-{nanos}", std::process::id())
}
