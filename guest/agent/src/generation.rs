//! Read-only boot admission, not proof of a later generation acknowledgement.
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(crate) fn driver_ready() -> bool {
    match observe(Path::new("/sys/bus/virtio/devices")) {
        Ok(ready) => ready,
        Err(error) => {
            tracing::debug!(%error, "VM generation driver admission unavailable");
            false
        }
    }
}

fn observe(devices: &Path) -> io::Result<bool> {
    let mut found = false;
    let mut buffer = [0_u8; 4097];
    for entry in std::fs::read_dir(devices)? {
        let path = entry?.path();
        let id = attribute(&path.join("device"), &mut buffer)?.trim();
        if id != "0x5347" {
            continue;
        }
        if found {
            return Ok(false);
        }
        found = true;
        let driver = std::fs::read_link(path.join("driver"))?;
        if driver.file_name() != Some(std::ffi::OsStr::new("virtio_silo_vmgenid")) {
            return Ok(false);
        }
        let state = attribute(&path.join("generation_state"), &mut buffer)?;
        let mut version = None;
        let mut error = None;
        for field in state.split_ascii_whitespace() {
            let Some((key, value)) = field.split_once('=') else {
                return Ok(false);
            };
            let target = match key {
                "version" => &mut version,
                "error" => &mut error,
                _ => continue,
            };
            if target.replace(value).is_some() {
                return Ok(false);
            }
        }
        if version != Some("1") || error != Some("0") {
            return Ok(false);
        }
    }
    Ok(found)
}

fn attribute<'a>(path: &Path, buffer: &'a mut [u8; 4097]) -> io::Result<&'a str> {
    let mut file = File::open(path)?;
    let mut count = 0;
    while count < buffer.len() {
        let read = match file.read(&mut buffer[count..]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            return std::str::from_utf8(&buffer[..count])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
        count += read;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "oversized generation attribute",
    ))
}

#[cfg(test)]
mod tests {
    use crate::generation::observe;
    use std::path::Path;

    fn device(root: &Path, name: &str, id: &str, state: &str) -> std::path::PathBuf {
        let path = root.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("device"), id).unwrap();
        std::fs::write(path.join("generation_state"), state).unwrap();
        std::os::unix::fs::symlink("../../drivers/virtio_silo_vmgenid", path.join("driver"))
            .unwrap();
        path
    }

    #[test]
    fn only_one_bound_healthy_generation_driver_admits() {
        let root = tempfile::tempdir().unwrap();
        assert!(!observe(root.path()).unwrap());
        device(root.path(), "virtio0", "0x0004\n", "version=1 error=0\n");
        assert!(!observe(root.path()).unwrap());
        let actual = device(
            root.path(),
            "virtio19",
            "0x5347\n",
            "version=1 request_sequence=0 error=0\n",
        );
        assert!(observe(root.path()).unwrap());
        for state in [
            "version=2 error=0",
            "version=1 error=-22",
            "version=1",
            "error=0",
            "version=1 error=0 error=0",
            "version=1 version=1 error=0",
            "version=1 error=0 broken",
        ] {
            std::fs::write(actual.join("generation_state"), state).unwrap();
            assert!(!observe(root.path()).unwrap(), "{state}");
        }
        std::fs::write(actual.join("generation_state"), "version=1 error=0").unwrap();
        device(root.path(), "virtio20", "0x5347", "version=1 error=0");
        assert!(!observe(root.path()).unwrap());
    }

    #[test]
    fn unbound_wrong_driver_and_unreadable_evidence_never_admit() {
        let root = tempfile::tempdir().unwrap();
        let actual = device(root.path(), "virtio7", "0x5347", "version=1 error=0");
        std::fs::remove_file(actual.join("driver")).unwrap();
        assert!(observe(root.path()).is_err());
        std::os::unix::fs::symlink("../../drivers/virtio_rng", actual.join("driver")).unwrap();
        assert!(!observe(root.path()).unwrap());
        std::fs::remove_file(actual.join("driver")).unwrap();
        std::os::unix::fs::symlink("../../drivers/virtio_silo_vmgenid", actual.join("driver"))
            .unwrap();
        std::fs::write(actual.join("generation_state"), [b' '; 4097]).unwrap();
        assert!(observe(root.path()).is_err());
        std::fs::write(actual.join("generation_state"), [0xff]).unwrap();
        assert!(observe(root.path()).is_err());
        std::fs::remove_file(actual.join("generation_state")).unwrap();
        assert!(observe(root.path()).is_err());
    }
}
