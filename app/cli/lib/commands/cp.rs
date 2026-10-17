use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use clap::Args;
use eyre::{bail, ensure};
use libvm::{FileWriteDisposition, MachineEntryKind, MachineFileUploadOptions};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::api::{files, streams};
use crate::context::Context;
use crate::ui::{self, OutputFormat};

#[derive(Debug, Args)]
#[command(about = "Copy a regular file between the host and a running VM")]
pub struct Cmd {
    #[arg(value_name = "SRC")]
    source: String,
    #[arg(value_name = "DST")]
    destination: String,
    /// File mode for uploads, in octal.
    #[arg(long, value_parser = parse_octal)]
    mode: Option<u32>,
    /// Numeric owner for uploads.
    #[arg(long, value_name = "UID[:GID]")]
    owner: Option<String>,
    /// Create missing guest parent directories for uploads.
    #[arg(long, short = 'p')]
    parents: bool,
    /// Fail if the guest destination exists (best effort, not atomic).
    #[arg(long, short = 'n')]
    no_clobber: bool,
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

#[derive(Debug, PartialEq, Eq)]
enum Endpoint {
    Stdio,
    Local(PathBuf),
    Guest { vm: String, path: String },
}

fn parse_endpoint(value: &str) -> eyre::Result<Endpoint> {
    if value == "-" {
        return Ok(Endpoint::Stdio);
    }
    if !value.starts_with("./") && !value.starts_with('/') {
        if let Some((vm, path)) = value.split_once(':') {
            ensure!(
                !vm.is_empty() && !path.contains(':'),
                "ambiguous endpoint; use VM:/absolute/path or prefix a local path with ./"
            );
            ensure!(
                path.starts_with('/'),
                "guest paths must be absolute (VM:/path)"
            );
            return Ok(Endpoint::Guest {
                vm: vm.to_string(),
                path: path.to_string(),
            });
        }
    }
    ensure!(
        !value.is_empty(),
        "ambiguous endpoint; use VM:/absolute/path or prefix a local path with ./"
    );
    Ok(Endpoint::Local(PathBuf::from(value)))
}

fn endpoints(source: &str, destination: &str) -> eyre::Result<(Endpoint, Endpoint)> {
    let source = parse_endpoint(source)?;
    let destination = parse_endpoint(destination)?;
    match (&source, &destination) {
        (Endpoint::Guest { .. }, Endpoint::Guest { .. }) => {
            bail!("cp copies between the host and one VM")
        }
        (Endpoint::Guest { .. }, _) | (_, Endpoint::Guest { .. }) => Ok((source, destination)),
        _ => bail!("cp requires a VM endpoint (VM:/path)"),
    }
}

fn parse_octal(value: &str) -> Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err("mode must be octal (0000-7777)".to_string());
    }
    u32::from_str_radix(value, 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
        .ok_or_else(|| "mode must be octal (0000-7777)".to_string())
}

fn parse_owner(value: &str) -> eyre::Result<(u32, Option<u32>)> {
    fn numeric(value: &str) -> eyre::Result<u32> {
        ensure!(
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
            "owner must be numeric UID[:GID]"
        );
        value
            .parse()
            .map_err(|_| eyre::eyre!("owner must be numeric UID[:GID]"))
    }
    match value.split_once(':') {
        Some((uid, gid)) => Ok((numeric(uid)?, Some(numeric(gid)?))),
        None => Ok((numeric(value)?, None)),
    }
}

#[derive(Default)]
struct TransferDigest {
    bytes: u64,
    hash: Sha256,
}

struct HashReader<R> {
    reader: R,
    digest: Arc<Mutex<TransferDigest>>,
}

impl<R: AsyncRead + Unpin> AsyncRead for HashReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.reader).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes = &buf.filled()[before..];
                let mut digest = match self.digest.lock() {
                    Ok(digest) => digest,
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::other("transfer digest lock poisoned")))
                    }
                };
                digest.bytes += bytes.len() as u64;
                digest.hash.update(bytes);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

#[derive(Serialize)]
struct Summary<'a> {
    direction: &'static str,
    vm: &'a str,
    path: &'a str,
    bytes: u64,
    sha256: String,
    disposition: Option<&'static str>,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let (source, destination) = endpoints(&self.source, &self.destination)?;
        let (upload, vm, path, local) = match (&source, &destination) {
            (_, Endpoint::Guest { vm, path }) => (true, vm, path, &source),
            (Endpoint::Guest { vm, path }, _) => (false, vm, path, &destination),
            _ => bail!("cp requires a VM endpoint (VM:/path)"),
        };
        ensure!(
            upload
                || (self.mode.is_none()
                    && self.owner.is_none()
                    && !self.parents
                    && !self.no_clobber),
            "--mode, --owner, --parents and --no-clobber are upload-only"
        );
        // File bytes and a JSON object cannot share stdout without corrupting the download.
        ensure!(
            !(matches!(self.format, OutputFormat::Json)
                && !upload
                && matches!(local, Endpoint::Stdio)),
            "--format json cannot be used when downloading to stdout"
        );
        let (uid, gid) = self
            .owner
            .as_deref()
            .map(parse_owner)
            .transpose()?
            .map_or((None, None), |(uid, gid)| (Some(uid), gid));
        let (_, machine) = context.machine(Some(vm)).await?;
        let inspect = machine.inspect().await?;
        streams::ensure_running(&inspect)?;
        streams::ensure_guest_ready(&inspect)?;
        let digest = Arc::new(Mutex::new(TransferDigest::default()));
        let disposition = if upload {
            let reader: Box<dyn AsyncRead + Unpin + Send> = match local {
                Endpoint::Stdio => Box::new(tokio::io::stdin()),
                Endpoint::Local(source) => {
                    let metadata = tokio::fs::metadata(source).await?;
                    ensure!(
                        !metadata.is_dir(),
                        "{} is a directory; use: exec {} -- tar -xC DIR < bundle.tar",
                        source.display(),
                        vm
                    );
                    ensure!(
                        metadata.is_file(),
                        "{} is not a regular file",
                        source.display()
                    );
                    let file = tokio::fs::File::open(source).await?;
                    ensure!(
                        file.metadata().await?.is_file(),
                        "{} is not a regular file",
                        source.display()
                    );
                    Box::new(file)
                }
                Endpoint::Guest { .. } => bail!("cp copies between the host and one VM"),
            };
            match files::stat(&machine, path).await {
                Ok(entry) => {
                    ensure!(!self.no_clobber, "{}:{} exists", vm, path);
                    ensure!(
                        entry.kind != MachineEntryKind::Directory,
                        "destination is a directory; give the full target path"
                    );
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<libvm::LibVmError>(),
                        Some(libvm::LibVmError::GuestPathNotFound { .. })
                    ) => {}
                Err(error) => return Err(error),
            }
            if self.parents {
                let parent = Path::new(path)
                    .parent()
                    .and_then(Path::to_str)
                    .ok_or_else(|| eyre::eyre!("guest paths must be absolute (VM:/path)"))?;
                files::mkdir_parents(&machine, parent).await?;
            }
            let result = files::upload(
                &machine,
                path,
                HashReader {
                    reader,
                    digest: Arc::clone(&digest),
                },
                MachineFileUploadOptions {
                    path: path.clone(),
                    mode: self.mode,
                    uid,
                    gid,
                },
            )
            .await?;
            Some(match result {
                FileWriteDisposition::Created => "created",
                FileWriteDisposition::Replaced => "replaced",
            })
        } else {
            let entry = files::stat(&machine, path).await?;
            ensure!(
                entry.kind == MachineEntryKind::File,
                "{}:{} is a directory; use: exec {} -- tar -cC DIR . > bundle.tar",
                vm,
                path,
                vm
            );
            let mut reader = HashReader {
                reader: files::download(&machine, path).await?,
                digest: Arc::clone(&digest),
            };
            match local {
                Endpoint::Stdio => copy_chunks(&mut reader, &mut tokio::io::stdout()).await?,
                Endpoint::Local(target) => download_local(&mut reader, target).await?,
                Endpoint::Guest { .. } => bail!("cp copies between the host and one VM"),
            }
            None
        };
        let digest = digest
            .lock()
            .map_err(|_| eyre::eyre!("transfer digest lock poisoned"))?;
        let summary = Summary {
            direction: if upload { "upload" } else { "download" },
            vm,
            path,
            bytes: digest.bytes,
            sha256: digest_hex(&digest.hash.clone().finalize()),
            disposition,
        };
        match self.format {
            OutputFormat::Json => ui::print_json(&summary),
            OutputFormat::Plain => {
                if let Some(disposition) = summary.disposition {
                    eprintln!(
                        "copied {} bytes to {}:{} ({}, sha256 {})",
                        summary.bytes, vm, path, disposition, summary.sha256
                    );
                } else {
                    eprintln!(
                        "copied {} bytes from {}:{} (sha256 {})",
                        summary.bytes, vm, path, summary.sha256
                    );
                }
                Ok(())
            }
        }
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0xf] {
            hex.push(char::from(if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            }));
        }
    }
    hex
}

async fn copy_chunks(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
) -> eyre::Result<()> {
    let mut chunk = [0_u8; 65536];
    loop {
        let size = reader.read(&mut chunk).await?;
        if size == 0 {
            break;
        }
        writer.write_all(&chunk[..size]).await?;
    }
    writer.flush().await?;
    Ok(())
}

struct TemporaryDownload(PathBuf);

impl Drop for TemporaryDownload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn download_local(reader: &mut (impl AsyncRead + Unpin), target: &Path) -> eyre::Result<()> {
    let directory = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .ok_or_else(|| eyre::eyre!("destination is a directory; give the full target path"))?;
    let mut temp_name = std::ffi::OsString::from(format!(".silo-cp-{}-", std::process::id()));
    temp_name.push(name);
    let temp_path = directory.join(temp_name);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp_path)
        .await?;
    let temp = TemporaryDownload(temp_path);
    copy_chunks(reader, &mut file).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temp.0, target).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};

    use crate::app::Cli;
    use crate::commands::cp::{
        digest_hex, download_local, endpoints, parse_endpoint, parse_octal, parse_owner, Endpoint,
        HashReader, TransferDigest,
    };
    use crate::commands::Command;

    #[test]
    fn cp_digest_uses_lowercase_sha256() {
        assert_eq!(
            digest_hex(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn cp_endpoint_parsing() {
        for value in ["file", "./file:name", "/tmp/file:name"] {
            assert_eq!(
                parse_endpoint(value).unwrap(),
                Endpoint::Local(value.into())
            );
        }
        assert_eq!(parse_endpoint("-").unwrap(), Endpoint::Stdio);
        assert_eq!(
            parse_endpoint("vm:/root/x").unwrap(),
            Endpoint::Guest {
                vm: "vm".into(),
                path: "/root/x".into()
            }
        );
        for value in ["vm:relative", "vm:", "file:name"] {
            assert_eq!(
                parse_endpoint(value).unwrap_err().to_string(),
                "guest paths must be absolute (VM:/path)"
            );
        }
        for value in [":/x", "", "vm:/x:y", "a:b:c"] {
            assert_eq!(
                parse_endpoint(value).unwrap_err().to_string(),
                "ambiguous endpoint; use VM:/absolute/path or prefix a local path with ./"
            );
        }
        assert_eq!(
            endpoints("a:/x", "b:/y").unwrap_err().to_string(),
            "cp copies between the host and one VM"
        );
        for (source, destination) in [("-", "-"), ("./a", "./b")] {
            assert_eq!(
                endpoints(source, destination).unwrap_err().to_string(),
                "cp requires a VM endpoint (VM:/path)"
            );
        }
    }

    #[test]
    fn cp_options_parse() {
        let cli = Cli::try_parse_from([
            "silo",
            "cp",
            "-",
            "dev:/opt/x",
            "--mode",
            "0755",
            "--owner",
            "1000:1001",
            "-p",
            "-n",
            "--format",
            "json",
        ])
        .unwrap();
        let Command::Cp(cmd) = cli.command else {
            panic!("expected cp");
        };
        assert_eq!(cmd.mode, Some(0o755));
        assert!(cmd.parents && cmd.no_clobber);
        assert_eq!(
            parse_owner(cmd.owner.as_deref().unwrap()).unwrap(),
            (1000, Some(1001))
        );
        assert_eq!(parse_owner("1000").unwrap(), (1000, None));
        for value in ["", "8", "10000", "-1", "0o644"] {
            assert!(parse_octal(value).is_err());
        }
        for value in ["", "1000:", ":1000", "root", "1:2:3", "4294967296", "+1"] {
            assert!(parse_owner(value).is_err());
        }
        assert!(Cli::try_parse_from(["silo", "cp", "-", "vm:/x", "--mode", "8"]).is_err());
        assert!(Cli::try_parse_from(["silo", "cp", "vm:/x"]).is_err());
    }

    #[tokio::test]
    async fn cp_download_is_hashed_and_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");
        tokio::fs::write(&target, b"old").await.unwrap();
        let bytes: Vec<u8> = (0..300 * 1024).map(|index| (index % 251) as u8).collect();
        let digest = Arc::new(Mutex::new(TransferDigest::default()));
        let mut reader = HashReader {
            reader: std::io::Cursor::new(&bytes),
            digest: Arc::clone(&digest),
        };
        download_local(&mut reader, &target).await.unwrap();
        assert_eq!(tokio::fs::read(&target).await.unwrap(), bytes);
        let Ok(digest) = digest.lock() else {
            panic!("digest lock poisoned");
        };
        assert_eq!(digest.bytes, bytes.len() as u64);
        assert_eq!(digest.hash.clone().finalize(), Sha256::digest(&bytes));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn cp_failed_rename_removes_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("existing-directory");
        tokio::fs::create_dir(&target).await.unwrap();
        let mut reader = std::io::Cursor::new(b"contents");
        assert!(download_local(&mut reader, &target).await.is_err());
        assert!(target.is_dir());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
