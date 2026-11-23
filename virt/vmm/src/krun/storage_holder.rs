//! Durable run-bound process provenance, published before attachment admission.

use std::io;
use std::path::Path;

use protocol::shutdown::{
    StorageHolder, StorageHolderRecord, StorageHolderRole, WorkerStorageContext,
};

pub(crate) fn publish(
    path: &Path,
    context: &WorkerStorageContext,
    worker: Option<u32>,
) -> io::Result<()> {
    context.validate().map_err(io::Error::other)?;
    let identity = |role, pid: u32| -> io::Result<StorageHolder> {
        let pid_number = i32::try_from(pid).map_err(io::Error::other)?;
        let started = utils::process::start_time(pid_number)?
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                io::Error::other("attachment holder has no stable process-start identity")
            })?;
        Ok(StorageHolder {
            role,
            pid,
            started_at: started,
        })
    };
    let mut holders = vec![identity(StorageHolderRole::Monitor, std::process::id())?];
    if let Some(pid) = worker {
        holders.push(identity(StorageHolderRole::KrunWorker, pid)?);
    }
    let record = StorageHolderRecord {
        schema_version: 1,
        machine_id: context.machine_id.clone(),
        run_id: context.run_id.clone(),
        operation_id: context.storage_lease.operation_id.clone(),
        holders,
    };
    let bytes = record.encode().map_err(io::Error::other)?;
    crate::durable_file::write(path, &bytes).map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Command, Stdio};

    use crate::krun::storage_holder::publish;
    use protocol::shutdown::{
        StorageHolderRecord, StorageHolderRole, StorageLeaseBinding, WorkerStorageContext,
    };

    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn durable_record_binds_actual_monitor_and_worker_start_identities() {
        let directory = std::env::temp_dir().join(format!("silo-holders-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("holder directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let worker = Process(
            Command::new("sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("actual child"),
        );
        let context = WorkerStorageContext {
            version: 1,
            machine_id: "11111111-1111-4111-8111-111111111111".to_string(),
            run_id: "22222222-2222-4222-8222-222222222222".to_string(),
            storage_lease: StorageLeaseBinding {
                operation_id: "33333333-3333-4333-8333-333333333333".to_string(),
                file_device: 1,
                file_inode: 2,
            },
            raw_handles: Vec::new(),
        };
        let path = directory.join("vm.storage-holder.json");
        publish(&path, &context, None).expect("monitor-only durable registration");
        let monitor = StorageHolderRecord::decode(&std::fs::read(&path).expect("read holder"))
            .expect("decode monitor");
        assert_eq!(monitor.holders.len(), 1);
        publish(&path, &context, Some(worker.0.id())).expect("register worker before config");
        let bytes = std::fs::read(&path).expect("durable holder");
        assert!(bytes.len() <= protocol::shutdown::MAX_HOLDER_BYTES);
        let record = StorageHolderRecord::decode(&bytes).expect("strict current holder");
        record
            .validate_binding(
                &context.machine_id,
                &context.run_id,
                &context.storage_lease.operation_id,
            )
            .expect("exact run binding");
        assert_eq!(record.holders.len(), 2);
        let holder = record
            .holders
            .iter()
            .find(|holder| holder.role == StorageHolderRole::KrunWorker)
            .expect("worker provenance");
        assert_eq!(holder.pid, worker.0.id());
        assert_eq!(
            Some(holder.started_at as i64),
            utils::process::start_time(worker.0.id() as i32).expect("OS identity")
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("make publication unsafe");
        assert!(publish(&path, &context, Some(worker.0.id())).is_err());
        assert_eq!(std::fs::read(&path).expect("prior durable record"), bytes);
        drop(worker);
        std::fs::remove_dir_all(directory).expect("remove fixture");
    }
}
