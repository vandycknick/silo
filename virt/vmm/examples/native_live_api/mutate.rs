//! Explicit smoke-only negative inputs derived from a real captured envelope.
//! Use the public native decoder/encoder, never patch an opaque binary layout.
use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use eyre::ensure;
use libkrun::live::{kvm, CpuExecutionState, ExecutionEnvelope, VmExecutionState};
use serde_json::json;
use sha2::{Digest, Sha256};

pub(crate) fn run(arguments: Vec<OsString>) -> eyre::Result<()> {
    ensure!(
        arguments.len() == 3,
        "usage: native-live-api mutate-execution INPUT OUTPUT cpu|producer|profile|xsave|tsc-rate|msr"
    );
    let input = Path::new(&arguments[0]);
    let output = Path::new(&arguments[1]);
    let kind = arguments[2]
        .to_str()
        .ok_or_else(|| eyre::eyre!("mutation name is UTF-8"))?;
    let original = crate::entry::bounded(input, 16 << 20)?;
    let mut saved = ExecutionEnvelope::decode(&original)?;
    let subject = match kind {
        "cpu" => {
            for state in &mut saved.cpus {
                let CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu)) = state else {
                    eyre::bail!("CPU mutation requires an actual captured KVM x86 CPU");
                };
                let leaf = cpu
                    .cpuid
                    .iter_mut()
                    .find(|leaf| leaf.function == 1 && leaf.index == 0)
                    .ok_or_else(|| eyre::eyre!("captured CPUID leaf 1 is absent"))?;
                leaf.values[0] ^= 1;
            }
            "kvm/cpuid/destination-family-model-stepping"
        }
        "producer" => {
            saved.binding.native_producer.push_str("-incompatible");
            "exact native producer mismatch: exact build identity"
        }
        "profile" => {
            let VmExecutionState::Kvm(kvm::KvmVmState::X86(vm)) = &mut saved.vm else {
                eyre::bail!("profile mutation requires an actual captured KVM x86 VM");
            };
            ensure!(
                vm.host_kernel.len() + "-incompatible".len() <= 256,
                "bounded host profile mutation"
            );
            vm.host_kernel.push_str("-incompatible");
            "kvm/clock/destination-host-semantics-profile"
        }
        "xsave" => {
            for state in &mut saved.cpus {
                let CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu)) = state else {
                    eyre::bail!("XSAVE mutation requires an actual captured KVM x86 CPU");
                };
                ensure!(cpu.xsave.len() <= 65532, "bounded captured XSAVE mutation");
                cpu.xsave.extend_from_slice(&[0; 4]);
            }
            "kvm/xsave2/destination-layout"
        }
        "tsc-rate" => {
            for state in &mut saved.cpus {
                let CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu)) = state else {
                    eyre::bail!("TSC mutation requires an actual captured KVM x86 CPU");
                };
                cpu.tsc_khz = cpu
                    .tsc_khz
                    .checked_add(1)
                    .ok_or_else(|| eyre::eyre!("captured TSC rate overflow"))?;
            }
            "kvm/clock/unscaled-rate-mismatch"
        }
        "msr" => {
            for state in &mut saved.cpus {
                let CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu)) = state else {
                    eyre::bail!("MSR mutation requires an actual captured KVM x86 CPU");
                };
                let model = cpu
                    .model_msrs
                    .first_mut()
                    .ok_or_else(|| eyre::eyre!("captured model MSR inventory is empty"))?;
                model.value ^= 1;
            }
            "kvm/msr/destination-model-values"
        }
        _ => eyre::bail!("unknown explicit execution mutation"),
    };
    let bytes = saved.encode()?;
    // A malformed codec fixture must never masquerade as host compatibility.
    ensure!(
        ExecutionEnvelope::decode(&bytes)? == saved,
        "native mutation round-trip"
    );
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let mut destination = crate::entry::new_output(output)?;
    destination.write_all(&bytes)?;
    destination.sync_all()?;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        json!({
            "mutation": kind, "subject": subject, "length": bytes.len(), "sha256": digest,
            "nativeProducer": saved.binding.native_producer,
            "codec": "public ExecutionEnvelope decode/encode",
        })
    )?;
    Ok(())
}

pub(crate) fn inspect(arguments: Vec<OsString>) -> eyre::Result<()> {
    ensure!(
        arguments.len() == 1,
        "usage: native-live-api inspect-execution INPUT"
    );
    let bytes = crate::entry::bounded(Path::new(&arguments[0]), 16 << 20)?;
    let saved = ExecutionEnvelope::decode(&bytes)?;
    let mut cpus = Vec::with_capacity(saved.cpus.len());
    for state in &saved.cpus {
        let CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu)) = state else {
            eyre::bail!("execution observation requires an actual KVM x86 CPU");
        };
        cpus.push(json!({
            "id": cpu.id, "registers": cpu.regs, "events": cpu.events,
            "mpState": cpu.mp_state, "tscOffset": cpu.tsc_offset,
            "tscKhz": cpu.tsc_khz, "tscObserved": cpu.tsc_observed,
            "deadline": cpu.deadline, "lapic": cpu.lapic,
            "xsaveSha256": <[u8;32]>::from(Sha256::digest(&cpu.xsave)),
            "xsave": cpu.xsave,
            "xstate": cpu.xstate.iter().map(|component| json!({
                "id": component.id, "offset": component.offset, "size": component.size,
            })).collect::<Vec<_>>(),
        }));
    }
    let VmExecutionState::Kvm(kvm::KvmVmState::X86(vm)) = &saved.vm else {
        eyre::bail!("execution observation requires an actual KVM x86 VM");
    };
    writeln!(
        std::io::stdout().lock(),
        "{}",
        json!({
            "codec": "public ExecutionEnvelope::decode", "lane": format!("{:?}", saved.lane),
            "cpus": cpus, "pitProfile": vm.pit_profile, "clock": vm.clock,
            "clockFlags": vm.clock_flags, "hostTsc": vm.host_tsc, "realtime": vm.realtime,
        })
    )?;
    Ok(())
}

pub(crate) fn inspect_devices(arguments: Vec<OsString>) -> eyre::Result<()> {
    ensure!(
        arguments.len() == 1,
        "usage: native-live-api inspect-devices INPUT"
    );
    let bytes = crate::entry::bounded(Path::new(&arguments[0]), 32 << 20)?;
    let devices = libkrun::live::inspection::decode_device_transports(&bytes)?;
    let devices: Vec<_> = devices
        .into_iter()
        .map(|device| {
            let state = device.transport;
            let queues: Vec<_> = state.queues.iter().enumerate().map(|(index, queue)| json!({
            "index":index, "size":queue.size, "ready":queue.ready,
            "descTable":queue.desc_table, "availRing":queue.avail_ring,
            "usedRing":queue.used_ring, "nextAvail":queue.next_avail, "nextUsed":queue.next_used,
        })).collect();
            json!({"configuredId":device.configured_id, "deviceType":state.device_type,
            "ackedFeatures":state.acked_features, "queues":queues})
        })
        .collect();
    writeln!(
        std::io::stdout().lock(),
        "{}",
        json!({
            "codec":"existing bounded native DeviceEnvelope::decode", "devices":devices,
        })
    )?;
    Ok(())
}
