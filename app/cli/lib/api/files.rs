use libvm::{
    FileWriteDisposition, MachineFileDownload, MachineFileEntry, MachineFileUploadOptions,
};
use tokio::io::AsyncRead;

use crate::api::machine::AppMachine;

pub(crate) async fn upload(
    machine: &AppMachine,
    path: &str,
    reader: impl AsyncRead + Unpin + Send + 'static,
    mut options: MachineFileUploadOptions,
) -> eyre::Result<FileWriteDisposition> {
    options.path = path.to_string();
    Ok(machine
        .session_machine()
        .await?
        .upload_file(options, reader)
        .await?)
}

pub(crate) async fn download(
    machine: &AppMachine,
    path: &str,
) -> eyre::Result<MachineFileDownload> {
    Ok(machine.session_machine().await?.download_file(path).await?)
}

pub(crate) async fn stat(machine: &AppMachine, path: &str) -> eyre::Result<MachineFileEntry> {
    Ok(machine
        .session_machine()
        .await?
        .get_file_entry(path)
        .await?)
}

pub(crate) async fn mkdir_parents(machine: &AppMachine, path: &str) -> eyre::Result<()> {
    // Creating the guest root is forbidden, but it already exists.
    if path != "/" {
        machine
            .session_machine()
            .await?
            .create_directory(path, true, None, None, None)
            .await?;
    }
    Ok(())
}
