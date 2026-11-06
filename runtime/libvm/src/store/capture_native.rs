//! Correlation of the native v1 public envelopes, not a hypervisor-state decoder.
//! Native restore must still validate every opaque VM/device payload.
//!
//! Layout follows libkrun's execution.rs StateBinding/ExecutionEnvelope and
//! execution/device_restore.rs DeviceEnvelope (little-endian utils::state codec).
//! Device identities must match execution order exactly; bounded transport/queue
//! framing and payload lengths must consume the whole device file. Only native
//! restore interprets transport values, queue geometry and opaque payload bytes.
use std::fs::File;
use std::os::unix::fs::FileExt;

use uuid::Uuid;
use vm_spec::capture::{CapturePlan, CaptureStateBinding};

use crate::store::capture::Layout;
use crate::store::models::snapshot::invalid;
use crate::LibVmError;

pub(crate) const MAX_EXECUTION_BYTES: u64 = 16 << 20;
pub(crate) const MAX_DEVICE_BYTES: u64 = 32 << 20;
const MAX_ATTACHMENTS: usize = 256;
const MAX_DEVICE_PAYLOAD: usize = 262_144;

pub(crate) fn verify_headers(
    execution: &File,
    devices: &File,
    binding: &CaptureStateBinding,
    plan: &CapturePlan,
    layout: &Layout,
) -> Result<(), LibVmError> {
    let mut execution = HeaderReader::new(execution, MAX_EXECUTION_BYTES)?;
    if execution.fixed::<8>()? != *b"KRUNEXEC" || execution.u16()? != 1 || execution.u32()? != 1 {
        return Err(invalid(
            "native execution magic, format version or ABI mismatch",
        ));
    }
    let lane = execution.u8()?;
    if !matches!(
        (lane, layout.architecture.as_str()),
        (1, "x86_64") | (2 | 3, "aarch64")
    ) {
        return Err(invalid(
            "native execution lane differs from the RAM architecture",
        ));
    }
    execution.binding(binding)?;
    let cpus = execution.count(255, 9)?;
    if cpus != usize::from(plan.configuration.cpus) || cpus == 0 {
        return Err(invalid(
            "native CPU topology differs from capture configuration",
        ));
    }
    let mut architectural_ids = [0u64; 255];
    for index in 0..cpus {
        if usize::from(execution.u8()?) != index {
            return Err(invalid(
                "native CPU topology is not in canonical logical order",
            ));
        }
        let architectural_id = execution.u64()?;
        let previous = architectural_ids
            .get(..index)
            .ok_or_else(|| invalid("native CPU count exceeds its fixed bound"))?;
        if previous.contains(&architectural_id) {
            return Err(invalid(
                "native CPU topology repeats an architectural identity",
            ));
        }
        let slot = architectural_ids
            .get_mut(index)
            .ok_or_else(|| invalid("native CPU count exceeds its fixed bound"))?;
        *slot = architectural_id;
    }
    if execution.u32()? != layout.page_granule {
        return Err(invalid(
            "native execution page granule differs from RAM layout",
        ));
    }
    let regions = execution.count(512, 16)?;
    if regions != layout.regions.len() {
        return Err(invalid(
            "native execution RAM region count differs from layout",
        ));
    }
    for region in &layout.regions {
        if execution.u64()? != region.guest_physical_address || execution.u64()? != region.length {
            return Err(invalid("native execution RAM region differs from layout"));
        }
    }
    let count = execution.count(MAX_ATTACHMENTS, 20)?;
    let mut attachments: Vec<(u32, String, u64, u32)> = Vec::with_capacity(count);
    let mut previous_address = None;
    let mut text = [0; 256];
    for _ in 0..count {
        let kind = execution.u32()?;
        let id = execution.text(&mut text, 256)?.to_owned();
        let address = execution.u64()?;
        let irq = execution.u32()?;
        if kind == 0
            || id.is_empty()
            || previous_address.is_some_and(|previous| previous >= address)
            || attachments
                .iter()
                .any(|(previous_kind, previous_id, _, _)| {
                    *previous_kind == kind && previous_id == &id
                })
        {
            return Err(invalid(
                "native execution attachment identities are not canonical",
            ));
        }
        previous_address = Some(address);
        attachments.push((kind, id, address, irq));
    }
    let block_count = attachments
        .iter()
        .filter(|(kind, _, _, _)| *kind == 2)
        .count();
    if block_count != plan.configuration.attachments.len()
        || plan.configuration.attachments.iter().any(|expected| {
            !attachments
                .iter()
                .any(|(kind, id, _, _)| *kind == 2 && id == expected.block_id.as_str())
        })
    {
        return Err(invalid(
            "native execution block identities differ from capture attachments",
        ));
    }
    let routes = execution.count(512, 8)?;
    if lane == 3 && routes != 0 {
        return Err(invalid("HVF execution has unexpected IRQ routes"));
    }
    let mut total_members = 0usize;
    for _ in 0..routes {
        let gsi = execution.u32()?;
        let members = execution.count(512, 8)?;
        total_members = total_members
            .checked_add(members)
            .filter(|total| *total <= 512)
            .ok_or_else(|| invalid("native IRQ membership exceeds its bound"))?;
        if gsi > 1023 || members == 0 {
            return Err(invalid("native IRQ route header is invalid"));
        }
        for _ in 0..members {
            execution.u64()?;
        }
    }
    if execution.remaining() == 0 {
        return Err(invalid("native execution has no opaque payload"));
    }
    verify_devices(devices, binding, &attachments)
}

fn verify_devices(
    devices: &File,
    binding: &CaptureStateBinding,
    attachments: &[(u32, String, u64, u32)],
) -> Result<(), LibVmError> {
    let mut devices = HeaderReader::new(devices, MAX_DEVICE_BYTES)?;
    if devices.fixed::<8>()? != *b"KRUNDEVS" || devices.u16()? != 1 {
        return Err(invalid("native device magic or format version mismatch"));
    }
    devices.binding(binding)?;
    if devices.count(MAX_ATTACHMENTS, 79)? != attachments.len() {
        return Err(invalid(
            "native device count differs from execution attachment inventory",
        ));
    }
    let mut text = [0; 256];
    for (kind, id, address, irq) in attachments {
        if devices.text(&mut text, 256)? != id || devices.u32()? != *kind {
            return Err(invalid(
                "native device identity differs from execution attachment inventory",
            ));
        }
        if devices.text(&mut text, 256)?.is_empty() {
            return Err(invalid("native device transport name is empty"));
        }
        if devices.u64()? != *address || devices.u32()? != *irq {
            return Err(invalid(
                "native device address or IRQ differs from execution attachment inventory",
            ));
        }
        // Two feature masks and seven u32 transport fields. Their semantics,
        // like queue geometry and the payload contents, belong to native restore.
        devices.skip(2 * 8 + 7 * 4)?;
        devices.boolean()?;
        let queues = devices.count(256, 36)?;
        for _ in 0..queues {
            devices.skip(2 * 2)?;
            devices.boolean()?;
            devices.skip(3 * 8 + 2 * 2)?;
            devices.boolean()?;
            devices.skip(2)?;
        }
        // These are the public codec's length bounds, not payload decoders.
        let payload_limit = match *kind {
            1 => 131_072,
            2 | 5 => 4096,
            3 => MAX_DEVICE_PAYLOAD,
            4 => 22,
            19 => 65_536,
            0x5347 => 256, // Silo generation device STATE_LIMIT.
            _ => return Err(invalid("native device provider kind is unsupported")),
        };
        let payload = devices.count(payload_limit, 1)?;
        devices.skip(payload as u64)?;
    }
    if devices.remaining() != 0 {
        return Err(invalid("native device envelope has trailing bytes"));
    }
    Ok(())
}

struct HeaderReader<'a> {
    file: &'a File,
    offset: u64,
    length: u64,
}
impl<'a> HeaderReader<'a> {
    fn new(file: &'a File, maximum: u64) -> Result<Self, LibVmError> {
        let length = file.metadata()?.len();
        if length == 0 || length > maximum {
            return Err(invalid("native envelope exceeds its format bound"));
        }
        Ok(Self {
            file,
            offset: 0,
            length,
        })
    }
    fn remaining(&self) -> u64 {
        self.length - self.offset
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], LibVmError> {
        let end = self
            .offset
            .checked_add(N as u64)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| invalid("native envelope header is truncated"))?;
        let mut bytes = [0; N];
        self.file.read_exact_at(&mut bytes, self.offset)?;
        self.offset = end;
        Ok(bytes)
    }
    fn skip(&mut self, count: u64) -> Result<(), LibVmError> {
        self.offset = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| invalid("native envelope record is truncated"))?;
        Ok(())
    }
    fn boolean(&mut self) -> Result<(), LibVmError> {
        if self.u8()? > 1 {
            return Err(invalid("native envelope boolean is not canonical"));
        }
        Ok(())
    }
    fn u8(&mut self) -> Result<u8, LibVmError> {
        Ok(u8::from_le_bytes(self.fixed()?))
    }
    fn u16(&mut self) -> Result<u16, LibVmError> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32, LibVmError> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, LibVmError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn count(&mut self, maximum: usize, minimum_bytes: u64) -> Result<usize, LibVmError> {
        let count = self.u32()? as usize;
        if count > maximum
            || (count as u64)
                .checked_mul(minimum_bytes)
                .is_none_or(|bytes| bytes > self.remaining())
        {
            return Err(invalid(
                "native envelope count exceeds bounds or remaining bytes",
            ));
        }
        Ok(count)
    }
    fn text<'b>(
        &mut self,
        bytes: &'b mut [u8; 256],
        maximum: usize,
    ) -> Result<&'b str, LibVmError> {
        let count = self.count(maximum, 1)?;
        let output = bytes
            .get_mut(..count)
            .ok_or_else(|| invalid("native header string exceeds its public bound"))?;
        self.file.read_exact_at(output, self.offset)?;
        self.offset += count as u64;
        std::str::from_utf8(output).map_err(invalid)
    }
    fn binding(&mut self, expected: &CaptureStateBinding) -> Result<(), LibVmError> {
        let count = self.count(vm_spec::capture::MAX_NATIVE_PRODUCER_BYTES, 1)?;
        if count != expected.native_producer.len() || count == 0 {
            return Err(invalid(
                "native state producer differs from capture evidence",
            ));
        }
        let mut buffer = [0; 256];
        for expected_chunk in expected.native_producer.as_bytes().chunks(buffer.len()) {
            let actual = &mut buffer[..expected_chunk.len()];
            self.file.read_exact_at(actual, self.offset)?;
            self.offset += actual.len() as u64;
            if actual != expected_chunk {
                return Err(invalid(
                    "native state producer differs from capture evidence",
                ));
            }
        }
        for digest in [
            &expected.silo_producer,
            &expected.profile,
            &expected.topology,
            &expected.ram_layout,
        ] {
            if digest.as_bytes() == &[0; 32] || &self.fixed::<32>()? != digest.as_bytes() {
                return Err(invalid(
                    "native state binding digest differs from capture evidence",
                ));
            }
        }
        if self.fixed::<16>()?
            != *Uuid::parse_str(expected.source_run.as_str())
                .map_err(invalid)?
                .as_bytes()
            || self.u64()? != expected.pause_generation.get()
            || self.fixed::<16>()?
                != *Uuid::parse_str(expected.capture.as_str())
                    .map_err(invalid)?
                    .as_bytes()
        {
            return Err(invalid(
                "native state run, pause generation or capture identity differs from evidence",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::num::NonZeroU64;

    use uuid::Uuid;
    use vm_spec::capture::{CaptureStateBinding, Sha256Digest};
    use vm_spec::lifecycle::LiveId;

    use crate::store::capture_native::{verify_devices, MAX_DEVICE_PAYLOAD};
    use crate::LibVmError;

    type Identity = (u32, String, u64, u32);

    fn identity() -> Identity {
        (2, "root-device".into(), 0x1000, 5)
    }

    fn binding() -> CaptureStateBinding {
        CaptureStateBinding {
            native_producer: "device-envelope-unit-test".into(),
            silo_producer: Sha256Digest::of_bytes(b"silo"),
            profile: Sha256Digest::of_bytes(b"profile"),
            topology: Sha256Digest::of_bytes(b"topology"),
            ram_layout: Sha256Digest::of_bytes(b"layout"),
            source_run: LiveId::parse(&Uuid::from_u128(1).to_string()).unwrap(),
            pause_generation: NonZeroU64::new(1).unwrap(),
            capture: LiveId::parse(&Uuid::from_u128(2).to_string()).unwrap(),
        }
    }

    fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }

    // Native DeviceEnvelope::encode field order, not a device payload fixture.
    // Arbitrary payload/queue values here make no claim of native restore validity.
    fn record_prefix(identity: &Identity, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        text(&mut bytes, &identity.1);
        bytes.extend_from_slice(&identity.0.to_le_bytes());
        text(&mut bytes, name);
        bytes.extend_from_slice(&identity.2.to_le_bytes());
        bytes.extend_from_slice(&identity.3.to_le_bytes());
        bytes.extend_from_slice(&[0; 2 * 8 + 7 * 4]);
        bytes
    }

    fn record(identity: &Identity, queues: &[[u8; 36]], payload: &[u8]) -> Vec<u8> {
        let mut bytes = record_prefix(identity, &identity.1);
        bytes.push(0); // activated
        bytes.extend_from_slice(&(queues.len() as u32).to_le_bytes());
        for queue in queues {
            bytes.extend_from_slice(queue);
        }
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn envelope(records: &[Vec<u8>]) -> Vec<u8> {
        let binding = binding();
        let mut bytes = b"KRUNDEVS".to_vec();
        bytes.extend_from_slice(&1u16.to_le_bytes());
        text(&mut bytes, &binding.native_producer);
        for digest in [
            binding.silo_producer,
            binding.profile,
            binding.topology,
            binding.ram_layout,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(
            Uuid::parse_str(binding.source_run.as_str())
                .unwrap()
                .as_bytes(),
        );
        bytes.extend_from_slice(&binding.pause_generation.get().to_le_bytes());
        bytes.extend_from_slice(
            Uuid::parse_str(binding.capture.as_str())
                .unwrap()
                .as_bytes(),
        );
        bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    fn file(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn verify(bytes: &[u8], attachments: &[Identity]) -> Result<(), LibVmError> {
        verify_devices(&file(bytes), &binding(), attachments)
    }

    #[test]
    fn device_envelope_preserves_full_native_producer_and_rejects_overflow() {
        for length in [
            8239,
            vm_spec::capture::MAX_NATIVE_PRODUCER_BYTES,
            vm_spec::capture::MAX_NATIVE_PRODUCER_BYTES + 1,
        ] {
            let mut expected = binding();
            let mut bytes = envelope(&[]);
            let old_length = expected.native_producer.len();
            expected.native_producer = "p".repeat(length);
            let mut producer = Vec::new();
            text(&mut producer, &expected.native_producer);
            bytes.splice(10..14 + old_length, producer);
            assert_eq!(
                verify_devices(&file(&bytes), &expected, &[]).is_ok(),
                length <= vm_spec::capture::MAX_NATIVE_PRODUCER_BYTES
            );
            bytes[14 + length - 1] = b'q';
            assert!(verify_devices(&file(&bytes), &expected, &[]).is_err());
        }
    }

    #[test]
    fn device_envelope_correlates_inventory_without_interpreting_payload() {
        let attachments = [identity(), (1, "network".into(), 0x2000, 6)];
        let mut queue = [0xff; 36];
        queue[4] = 1; // ready
        queue[33] = 0; // event_idx_enabled
        let bytes = envelope(&[
            record(&attachments[0], &[queue], b"\xff\0opaque block bytes"),
            record(&attachments[1], &[], b"not a native network payload"),
        ]);
        verify(&bytes, &attachments).unwrap();
        verify(&envelope(&[]), &[]).unwrap();
    }

    #[test]
    fn device_envelope_rejects_each_foreign_identity_field() {
        let expected = identity();
        let foreign = [
            (expected.0, "foreign".into(), expected.2, expected.3),
            (1, expected.1.clone(), expected.2, expected.3),
            (expected.0, expected.1.clone(), 0x2000, expected.3),
            (expected.0, expected.1.clone(), expected.2, 6),
        ];
        for changed in foreign {
            let bytes = envelope(&[record(&changed, &[], b"opaque")]);
            assert!(verify(&bytes, std::slice::from_ref(&expected)).is_err());
        }
    }

    #[test]
    fn device_envelope_rejects_reordered_or_absent_records() {
        let attachments = [identity(), (5, "balloon".into(), 0x2000, 6)];
        let first = record(&attachments[0], &[], b"opaque");
        let second = record(&attachments[1], &[], b"opaque");
        assert!(verify(&envelope(&[second, first]), &attachments).is_err());
        assert!(verify(&envelope(&[]), &attachments).is_err());
        assert!(verify(&envelope(&[vec![0; 79], vec![0; 79]]), &attachments).is_err());
    }

    #[test]
    fn device_envelope_rejects_every_truncation_including_queues_and_payload() {
        let expected = identity();
        let bytes = envelope(&[record(&expected, &[[0; 36]], b"opaque payload")]);
        let file = file(&bytes);
        verify_devices(&file, &binding(), std::slice::from_ref(&expected)).unwrap();
        for length in (0..bytes.len()).rev() {
            file.set_len(length as u64).unwrap();
            assert!(
                verify_devices(&file, &binding(), std::slice::from_ref(&expected)).is_err(),
                "accepted truncated device file of {length} bytes"
            );
        }
    }

    #[test]
    fn device_envelope_rejects_noncanonical_transport_and_queue_booleans() {
        let expected = identity();
        let original = record(&expected, &[[0; 36]], b"opaque");
        let activated = record_prefix(&expected, &expected.1).len();
        let queue = activated + 1 + 4;
        for offset in [activated, queue + 4, queue + 33] {
            let mut changed = original.clone();
            changed[offset] = 2;
            assert!(verify(&envelope(&[changed]), std::slice::from_ref(&expected)).is_err());
        }
    }

    #[test]
    fn device_envelope_enforces_queue_and_payload_length_bounds() {
        let expected = (3, "console".into(), 0x1000, 5);
        let payload = vec![0xff; MAX_DEVICE_PAYLOAD];
        verify(
            &envelope(&[record(&expected, &[[0; 36]; 256], &payload)]),
            std::slice::from_ref(&expected),
        )
        .unwrap();
        assert!(verify(
            &envelope(&[record(&expected, &[[0; 36]; 257], b"opaque")]),
            std::slice::from_ref(&expected),
        )
        .is_err());
        let too_large = vec![0; MAX_DEVICE_PAYLOAD + 1];
        assert!(verify(
            &envelope(&[record(&expected, &[], &too_large)]),
            std::slice::from_ref(&expected),
        )
        .is_err());
        let mut overflow = record(&expected, &[], b"");
        let payload_length = overflow.len() - 4;
        overflow[payload_length..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(verify(&envelope(&[overflow]), std::slice::from_ref(&expected)).is_err());
    }

    #[test]
    fn device_envelope_enforces_identity_and_transport_name_framing() {
        let expected = (2, "x".repeat(256), 0x1000, 5);
        let original = record(&expected, &[], b"opaque");
        verify(
            &envelope(std::slice::from_ref(&original)),
            std::slice::from_ref(&expected),
        )
        .unwrap();
        let oversized = (2, "x".repeat(257), 0x1000, 5);
        assert!(verify(
            &envelope(&[record(&oversized, &[], b"opaque")]),
            std::slice::from_ref(&oversized),
        )
        .is_err());
        let mut invalid_id = original.clone();
        invalid_id[4] = 0xff;
        assert!(verify(&envelope(&[invalid_id]), std::slice::from_ref(&expected)).is_err());
        let name_length = 4 + expected.1.len() + 4;
        let mut invalid_name = original.clone();
        invalid_name[name_length + 4] = 0xff;
        assert!(verify(&envelope(&[invalid_name]), std::slice::from_ref(&expected)).is_err());
        let mut oversized_name = original.clone();
        oversized_name[name_length..name_length + 4].copy_from_slice(&257u32.to_le_bytes());
        assert!(verify(
            &envelope(&[oversized_name]),
            std::slice::from_ref(&expected)
        )
        .is_err());
        let mut empty_name = record_prefix(&expected, "");
        empty_name.extend_from_slice(&[0; 9]); // activated, no queues, empty payload
        assert!(verify(&envelope(&[empty_name]), std::slice::from_ref(&expected)).is_err());
    }

    #[test]
    fn device_envelope_enforces_record_count_bound_and_complete_framing() {
        let attachments: Vec<_> = (0..256)
            .map(|index| (2, format!("disk-{index}"), 0x1000 * (index + 1), 5))
            .collect();
        let records: Vec<_> = attachments
            .iter()
            .map(|identity| record(identity, &[], b"opaque"))
            .collect();
        let mut bytes = envelope(&records);
        verify(&bytes, &attachments).unwrap();
        bytes.push(0);
        assert!(verify(&bytes, &attachments).is_err());
        let mut excess = records;
        excess.push(record(&identity(), &[], b"opaque"));
        assert!(verify(&envelope(&excess), &attachments).is_err());
        let mut empty_with_tail = envelope(&[]);
        empty_with_tail.push(0);
        assert!(verify(&empty_with_tail, &[]).is_err());
    }

    #[test]
    fn device_envelope_enforces_public_per_provider_payload_bounds() {
        for (kind, maximum) in [
            (1, 131_072),
            (2, 4096),
            (3, MAX_DEVICE_PAYLOAD),
            (4, 22),
            (5, 4096),
            (19, 65_536),
            (0x5347, 256),
        ] {
            let expected = (kind, "device".into(), 0x1000, 5);
            let mut payload = vec![0xff; maximum];
            verify(
                &envelope(&[record(&expected, &[], &payload)]),
                std::slice::from_ref(&expected),
            )
            .unwrap();
            payload.push(0);
            assert!(
                verify(
                    &envelope(&[record(&expected, &[], &payload)]),
                    std::slice::from_ref(&expected),
                )
                .is_err(),
                "accepted oversized payload for device kind {kind}"
            );
        }
        let unsupported = (6, "unrecognized".into(), 0x1000, 5);
        assert!(verify(
            &envelope(&[record(&unsupported, &[], b"")]),
            std::slice::from_ref(&unsupported),
        )
        .is_err());
    }
}
