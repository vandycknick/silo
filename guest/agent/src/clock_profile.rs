//! Positive same-boot kernel observations for native retired-PIT admission.
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use protocol::v1::{
    GuestBroadcastClockeventKind, GuestClockProfile, GuestClockeventDevice, GuestClocksource,
    GuestModulesEvidence, GuestOnlineClockevent,
};

const MAX_ATTRIBUTE: usize = 4096;
const MAX_INVENTORY: usize = 1024 * 1024;
const MAX_CONFIG: usize = 16 * 1024 * 1024;
const MAX_CPUS: usize = 4096;

pub(crate) fn observe(boot_id: &str) -> io::Result<GuestClockProfile> {
    observe_at(Path::new("/"), boot_id)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn bounded_bytes(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("oversized clock-profile evidence"));
    }
    Ok(bytes)
}

fn bounded(reader: impl Read, limit: usize) -> io::Result<String> {
    String::from_utf8(bounded_bytes(reader, limit)?)
        .map_err(|_| invalid("non-UTF8 clock-profile evidence"))
}

fn read(root: &Path, path: &str, limit: usize) -> io::Result<String> {
    bounded(File::open(root.join(path))?, limit)
}

fn online_cpus(text: &str) -> io::Result<Vec<u32>> {
    let mut cpus = Vec::new();
    for group in text.trim().split(',') {
        let (first, last) = group.split_once('-').unwrap_or((group, group));
        let first: u32 = first
            .parse()
            .map_err(|_| invalid("invalid online CPU list"))?;
        let last: u32 = last
            .parse()
            .map_err(|_| invalid("invalid online CPU list"))?;
        if last < first || last >= MAX_CPUS as u32 {
            return Err(invalid("online CPU range outside evidence bound"));
        }
        for cpu in first..=last {
            if cpus.last().is_some_and(|previous| *previous >= cpu) {
                return Err(invalid("unordered or duplicate online CPU"));
            }
            cpus.push(cpu);
        }
    }
    if cpus.is_empty() {
        return Err(invalid("no online CPUs"));
    }
    Ok(cpus)
}

fn modules_disabled(config: &str) -> io::Result<bool> {
    let mut decision = None;
    for line in config.lines() {
        let value = match line {
            "CONFIG_MODULES=y" => true,
            "# CONFIG_MODULES is not set" => false,
            value if value.starts_with("CONFIG_MODULES=") => {
                return Err(invalid("unsupported CONFIG_MODULES value"));
            }
            _ => continue,
        };
        if decision.replace(value).is_some() {
            return Err(invalid("ambiguous CONFIG_MODULES evidence"));
        }
    }
    decision
        .map(|enabled| !enabled)
        .ok_or_else(|| invalid("missing CONFIG_MODULES evidence"))
}

fn module_evidence(root: &Path) -> io::Result<GuestModulesEvidence> {
    match read(root, "proc/modules", MAX_INVENTORY) {
        Ok(modules) => {
            for line in modules.lines() {
                let mut fields = line.split_ascii_whitespace();
                let name = fields
                    .next()
                    .ok_or_else(|| invalid("malformed module record"))?;
                let size = fields.next().and_then(|value| value.parse::<u64>().ok());
                let refs = fields
                    .next()
                    .is_some_and(|value| value == "-" || value.parse::<u32>().is_ok());
                let dependencies = fields.next();
                let state = fields.next();
                let address = fields
                    .next()
                    .and_then(|value| value.strip_prefix("0x"))
                    .and_then(|value| u64::from_str_radix(value, 16).ok());
                if !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    || size.is_none()
                    || !refs
                    || dependencies.is_none()
                    || !matches!(state, Some("Live" | "Loading" | "Unloading"))
                    || address.is_none()
                {
                    return Err(invalid("malformed module record"));
                }
                if matches!(name, "pcspkr" | "snd_pcsp") {
                    return Err(invalid("active speaker module consumer"));
                }
            }
            Ok(GuestModulesEvidence::ProcModules)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // /proc/config.gz is emitted by the running kernel (IKCONFIG_PROC),
            // not a pathname-selected config from a different kernel build.
            let compressed =
                bounded_bytes(File::open(root.join("proc/config.gz"))?, MAX_INVENTORY)?;
            let decoder = flate2::read::MultiGzDecoder::new(compressed.as_slice());
            let config = bounded(decoder, MAX_CONFIG)?;
            if !modules_disabled(&config)? {
                return Err(invalid(
                    "absent /proc/modules contradicts running kernel config",
                ));
            }
            Ok(GuestModulesEvidence::BuiltInDisabled)
        }
        Err(error) => Err(error),
    }
}

fn no_speaker_consumers(root: &Path) -> io::Result<()> {
    for driver in [
        "sys/devices/platform/pcspkr/driver",
        "sys/devices/platform/pcspkr.0/driver",
    ] {
        match std::fs::symlink_metadata(root.join(driver)) {
            Ok(_) => return Err(invalid("bound speaker driver consumer")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let entries = match std::fs::read_dir(root.join("sys/class/input")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for (index, entry) in entries.enumerate() {
        if index >= MAX_CPUS {
            return Err(invalid("oversized input inventory"));
        }
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("input") {
            continue;
        }
        let name = bounded(File::open(entry.path().join("name"))?, MAX_ATTRIBUTE)?;
        if name
            .as_bytes()
            .windows(7)
            .any(|name| name.eq_ignore_ascii_case(b"speaker"))
            || name
                .as_bytes()
                .windows(4)
                .any(|name| name.eq_ignore_ascii_case(b"pcsp"))
        {
            return Err(invalid("active speaker input consumer"));
        }
    }
    Ok(())
}

fn observe_at(root: &Path, expected_boot: &str) -> io::Result<GuestClockProfile> {
    let boot_id = read(root, "proc/sys/kernel/random/boot_id", MAX_ATTRIBUTE)?
        .trim()
        .to_owned();
    let boot = uuid::Uuid::parse_str(&boot_id)
        .map_err(|_| invalid("invalid clock-profile boot identity"))?;
    if boot.is_nil() || boot_id != expected_boot {
        return Err(invalid("clock-profile boot identity mismatch"));
    }
    let kernel_identity = read(root, "proc/version", MAX_ATTRIBUTE)?;
    if kernel_identity.trim().is_empty() || kernel_identity.contains('\0') {
        return Err(invalid("missing kernel identity"));
    }
    if read(
        root,
        "sys/devices/system/clocksource/clocksource0/current_clocksource",
        MAX_ATTRIBUTE,
    )?
    .trim()
        != "tsc"
    {
        return Err(invalid("running clocksource is not tsc"));
    }
    let online = read(root, "sys/devices/system/cpu/online", MAX_ATTRIBUTE)?;
    let mut online_clockevents = Vec::new();
    for cpu in online_cpus(&online)? {
        let path = format!("sys/devices/system/clockevents/clockevent{cpu}/current_device");
        if read(root, &path, MAX_ATTRIBUTE)?.trim() != "lapic-deadline" {
            return Err(invalid("online CPU clockevent is not lapic-deadline"));
        }
        online_clockevents.push(GuestOnlineClockevent {
            cpu,
            device: GuestClockeventDevice::LapicDeadline as i32,
        });
    }
    let broadcast = read(
        root,
        "sys/devices/system/clockevents/broadcast/current_device",
        MAX_ATTRIBUTE,
    )?;
    let (broadcast_kind, broadcast_device) = if broadcast.is_empty() {
        (GuestBroadcastClockeventKind::NoDevice, String::new())
    } else {
        let device = broadcast.trim();
        if device.is_empty()
            || device.len() > 256
            || device.contains(char::is_whitespace)
            || device
                .as_bytes()
                .windows(3)
                .any(|name| name.eq_ignore_ascii_case(b"pit"))
        {
            return Err(invalid("broadcast clockevent is PIT or malformed"));
        }
        (GuestBroadcastClockeventKind::NonPit, device.to_owned())
    };
    let modules = module_evidence(root)?;
    no_speaker_consumers(root)?;
    if read(root, "sys/devices/system/cpu/online", MAX_ATTRIBUTE)? != online
        || read(root, "proc/sys/kernel/random/boot_id", MAX_ATTRIBUTE)?.trim() != boot_id
    {
        return Err(invalid(
            "boot or online CPU set changed during clock observations",
        ));
    }
    Ok(GuestClockProfile {
        boot_id,
        kernel_identity,
        clocksource: GuestClocksource::Tsc as i32,
        online_clockevents,
        broadcast_kind: broadcast_kind as i32,
        broadcast_device,
        modules: modules as i32,
        no_speaker_consumers: true,
    })
}

#[cfg(test)]
mod tests {
    use crate::clock_profile::{bounded, modules_disabled, observe_at, online_cpus};
    use protocol::v1::{GuestBroadcastClockeventKind, GuestModulesEvidence};
    use std::io::Write;
    use std::path::Path;

    fn put(root: &Path, path: &str, value: impl AsRef<[u8]>) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, value).unwrap();
    }

    fn fixture(root: &Path) -> String {
        let boot = uuid::Uuid::new_v4().to_string();
        for (path, value) in [
            ("proc/sys/kernel/random/boot_id", boot.as_str()),
            ("proc/version", "Linux version actual-test-kernel\n"),
            ("sys/devices/system/cpu/online", "0,2-3\n"),
            (
                "sys/devices/system/clocksource/clocksource0/current_clocksource",
                "tsc\n",
            ),
            (
                "sys/devices/system/clockevents/broadcast/current_device",
                "",
            ),
            ("proc/modules", ""),
        ] {
            put(root, path, value);
        }
        for cpu in [0, 2, 3] {
            put(
                root,
                &format!("sys/devices/system/clockevents/clockevent{cpu}/current_device"),
                "lapic-deadline\n",
            );
        }
        boot
    }

    #[test]
    fn actual_sparse_online_cpus_and_empty_broadcast_eof_admit() {
        let root = tempfile::tempdir().unwrap();
        let boot = fixture(root.path());
        let profile = observe_at(root.path(), &boot).unwrap();
        assert_eq!(profile.boot_id, boot);
        assert_eq!(
            profile
                .online_clockevents
                .iter()
                .map(|event| event.cpu)
                .collect::<Vec<_>>(),
            [0, 2, 3]
        );
        assert_eq!(
            profile.broadcast_kind,
            GuestBroadcastClockeventKind::NoDevice as i32
        );
        assert_eq!(profile.modules, GuestModulesEvidence::ProcModules as i32);
        put(
            root.path(),
            "sys/devices/system/clockevents/broadcast/current_device",
            "hpet\n",
        );
        assert_eq!(
            observe_at(root.path(), &boot).unwrap().broadcast_device,
            "hpet"
        );
    }

    #[test]
    fn missing_modules_requires_actual_unambiguous_builtin_config() {
        let root = tempfile::tempdir().unwrap();
        let boot = fixture(root.path());
        std::fs::remove_file(root.path().join("proc/modules")).unwrap();
        assert!(observe_at(root.path(), &boot).is_err());
        for (config, valid) in [
            ("# CONFIG_MODULES is not set\n", true),
            ("CONFIG_MODULES=y\n", false),
            ("", false),
            ("CONFIG_MODULES=y\n# CONFIG_MODULES is not set\n", false),
        ] {
            let mut gzip =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gzip.write_all(config.as_bytes()).unwrap();
            put(root.path(), "proc/config.gz", gzip.finish().unwrap());
            let profile = observe_at(root.path(), &boot);
            assert_eq!(profile.is_ok(), valid, "{config}");
            if valid {
                assert_eq!(
                    profile.unwrap().modules,
                    GuestModulesEvidence::BuiltInDisabled as i32
                );
            }
        }
        put(root.path(), "proc/config.gz", "not gzip");
        assert!(observe_at(root.path(), &boot).is_err());
        put(root.path(), "proc/config.gz", vec![0_u8; 1024 * 1024 + 1]);
        assert!(
            observe_at(root.path(), &boot).is_err(),
            "compressed input is bounded"
        );
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(b"# CONFIG_MODULES is not set\n").unwrap();
        gzip.write_all(&vec![b'\n'; 16 * 1024 * 1024]).unwrap();
        put(root.path(), "proc/config.gz", gzip.finish().unwrap());
        assert!(
            observe_at(root.path(), &boot).is_err(),
            "decoded input is bounded"
        );
    }

    #[test]
    fn unsafe_missing_malformed_and_oversized_observations_fail_closed() {
        for (path, value) in [
            ("proc/version", ""),
            ("sys/devices/system/cpu/online", "0,2,2"),
            (
                "sys/devices/system/clocksource/clocksource0/current_clocksource",
                "hpet",
            ),
            (
                "sys/devices/system/clockevents/clockevent2/current_device",
                "pit",
            ),
            (
                "sys/devices/system/clockevents/broadcast/current_device",
                "pit\n",
            ),
            (
                "sys/devices/system/clockevents/broadcast/current_device",
                "\n",
            ),
            ("proc/modules", "pcspkr 1 0 - Live 0x0\n"),
            ("proc/modules", "snd_pcsp 1 0 - Live 0x0\n"),
            ("proc/modules", "not-a-kernel-module-record\n"),
            ("sys/class/input/input0/name", "PC Speaker\n"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let boot = fixture(root.path());
            put(root.path(), path, value);
            assert!(observe_at(root.path(), &boot).is_err(), "{path}: {value}");
        }
        let root = tempfile::tempdir().unwrap();
        let boot = fixture(root.path());
        assert!(observe_at(root.path(), &uuid::Uuid::new_v4().to_string()).is_err());
        put(root.path(), "proc/version", [b'x'; 4097]);
        assert!(observe_at(root.path(), &boot).is_err());
        assert!(bounded(&b"\xff"[..], 4).is_err());
        assert!(bounded(&b"12345"[..], 4).is_err());
        for text in ["", "1-0", "0-4096", "0,0", "2,1", "0-1-2", "a"] {
            assert!(online_cpus(text).is_err());
        }
        assert!(
            modules_disabled("# CONFIG_MODULES is not set\n# CONFIG_MODULES is not set").is_err()
        );
        let root = tempfile::tempdir().unwrap();
        let boot = fixture(root.path());
        std::fs::remove_file(
            root.path()
                .join("sys/devices/system/clockevents/clockevent3/current_device"),
        )
        .unwrap();
        assert!(
            observe_at(root.path(), &boot).is_err(),
            "every online CPU must be observed"
        );
        let root = tempfile::tempdir().unwrap();
        let boot = fixture(root.path());
        let driver = root.path().join("sys/devices/platform/pcspkr/driver");
        std::fs::create_dir_all(driver.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/absent/speaker-driver", driver).unwrap();
        assert!(
            observe_at(root.path(), &boot).is_err(),
            "a driver link is a consumer even when unreadable"
        );
    }
}
