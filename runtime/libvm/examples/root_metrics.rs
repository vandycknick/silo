//! Read root capacity through the normal public libvm monitor relay.
use libvm::{MachineRef, MachineTemporaryDirectoryKind, Runtime};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let reference = args.next().ok_or("usage: root_metrics NAME")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let runtime = Runtime::from_env().await?;
    let machine = runtime.get_machine(&MachineRef::parse(reference)?).await?;
    let metrics = machine.metrics().await?;
    let observation = metrics.metrics.ok_or("guest metrics unavailable")?;
    let observed_at = observation
        .report
        .observed_at
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let received_at = observation
        .received_at
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let stale_at = observation
        .stale_at
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let root = observation
        .report
        .snapshot
        .root_storage
        .ok_or("root-storage metrics unavailable")?;
    let temporary = &root.temporary_directory;
    let kind = match temporary.kind {
        MachineTemporaryDirectoryKind::Upper => "upper",
        MachineTemporaryDirectoryKind::Tmpfs => "tmpfs",
        MachineTemporaryDirectoryKind::Other => "other",
    };
    let json = serde_json::json!({
        "machineId": metrics.machine_id,
        "agentInstanceId": observation.agent_instance_id,
        "freshness": format!("{:?}", observation.freshness),
        "observedAtUnixMillis": observed_at,
        "receivedAtUnixMillis": received_at,
        "staleAtUnixMillis": stale_at,
        "rootStorage": {
            "kind": "linux-flat-overlay-v1",
            "upperProfile": root.upper_profile,
            "upperUuid": root.upper_uuid,
            "upperBackingBytes": root.upper_backing_bytes,
            "upperFilesystemBytes": root.upper_filesystem_bytes,
            "unusableTailBytes": root.unusable_tail_bytes,
            "filesystemOverheadBytes": root.filesystem_overhead_bytes,
            "upperUsableBytes": root.upper_usable_bytes,
            "upperUsedBytes": root.upper_used_bytes,
            "upperFreeBytes": root.upper_free_bytes,
            "upperAvailableBytes": root.upper_available_bytes,
            "upperTotalInodes": root.upper_total_inodes,
            "upperFreeInodes": root.upper_free_inodes,
            "upperAvailableInodes": root.upper_available_inodes,
            "sharedLowerLogicalBytes": root.shared_lower_logical_bytes,
            "temporaryDirectory": {
                "kind": kind,
                "capacityBytes": temporary.capacity_bytes,
                "usedBytes": temporary.used_bytes,
                "freeBytes": temporary.free_bytes,
                "availableBytes": temporary.available_bytes,
                "persistent": temporary.persistent,
                "memoryCharged": temporary.memory_charged,
            },
        },
    });
    println!("{}", serde_json::to_string(&json)?);
    Ok(())
}
