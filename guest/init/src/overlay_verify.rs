//! Qualified `linux-overlayfs-mountinfo-v1` verifier, also used by native probes.
//! Inputs are actual mountinfo and current built-in module parameters, never the
//! mount request. This module deliberately has no allocation or syscall dependency.

pub const RENDERING_ABI: &str = "linux-overlayfs-mountinfo-v1";

#[derive(Clone, Copy, Debug)]
pub struct ModuleDefaults {
    pub index: bool,
    pub metacopy: bool,
    pub redirect_dir: bool,
    pub redirect_always_follow: bool,
    pub xino_auto: bool,
    pub nfs_export: bool,
}

#[derive(Clone, Copy)]
pub struct MountPaths<'a> {
    pub target: &'a [u8],
    pub lower: &'a [u8],
    pub upper: &'a [u8],
    pub work: &'a [u8],
}

pub fn sysfs_bool(bytes: &[u8]) -> Result<bool, &'static str> {
    match bytes.strip_suffix(b"\n").unwrap_or(bytes) {
        b"Y" | b"1" => Ok(true),
        b"N" | b"0" => Ok(false),
        _ => Err("overlay: invalid module parameter"),
    }
}

fn unescaped_eq(encoded: &[u8], expected: &[u8]) -> bool {
    let mut input = encoded.iter().copied();
    for &wanted in expected {
        let byte = match input.next() {
            Some(b'\\') => match (input.next(), input.next(), input.next()) {
                (Some(b'0'), Some(b'4'), Some(b'0')) => b' ',
                (Some(b'0'), Some(b'1'), Some(b'1')) => b'\t',
                (Some(b'0'), Some(b'1'), Some(b'2')) => b'\n',
                (Some(b'1'), Some(b'3'), Some(b'4')) => b'\\',
                _ => return false,
            },
            Some(byte) => byte,
            None => return false,
        };
        if byte != wanted {
            return false;
        }
    }
    input.next().is_none()
}

fn writable(options: &[u8]) -> Result<(), &'static str> {
    let mut rw = false;
    for option in options.split(|byte| *byte == b',') {
        if option == b"ro" {
            return Err("overlay: read-only mount");
        }
        if option == b"rw" {
            if rw {
                return Err("overlay: duplicate rw option");
            }
            rw = true;
        }
    }
    if rw {
        Ok(())
    } else {
        Err("overlay: missing writable evidence")
    }
}

struct MountInfo<'a> {
    device: (u32, u32),
    root: &'a [u8],
    target: &'a [u8],
    flags: &'a [u8],
    filesystem: &'a [u8],
    options: &'a [u8],
}

fn mountinfo_decimal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))
    })
}

fn parse_mountinfo(line: &[u8]) -> Result<MountInfo<'_>, &'static str> {
    if line.iter().any(|byte| byte.is_ascii_control()) {
        return Err("overlay: control byte in mountinfo");
    }
    let mut fields = line.split(|byte| *byte == b' ');
    let mut next = || {
        fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or("overlay: truncated mountinfo record")
    };
    let id = next()?;
    let parent = next()?;
    let number = next()?;
    let root = next()?;
    let target = next()?;
    let flags = next()?;
    if mountinfo_decimal(id).is_none()
        || mountinfo_decimal(parent).is_none()
        || !root.starts_with(b"/")
        || !target.starts_with(b"/")
    {
        return Err("overlay: malformed mountinfo identity");
    }
    let colon = number
        .iter()
        .position(|byte| *byte == b':')
        .ok_or("overlay: malformed mountinfo device")?;
    let major = mountinfo_decimal(&number[..colon]).ok_or("overlay: malformed mountinfo major")?;
    let minor =
        mountinfo_decimal(&number[colon + 1..]).ok_or("overlay: malformed mountinfo minor")?;
    loop {
        match fields.next() {
            Some(b"-") => break,
            Some(field) if !field.is_empty() => {}
            _ => return Err("overlay: missing mountinfo separator"),
        }
    }
    let filesystem = fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or("overlay: missing mountinfo filesystem")?;
    let _source = fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or("overlay: missing mountinfo source")?;
    let options = fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or("overlay: missing mountinfo super options")?;
    if fields.next().is_some() {
        return Err("overlay: extra mountinfo fields");
    }
    Ok(MountInfo {
        device: (major, minor),
        root,
        target,
        flags,
        filesystem,
        options,
    })
}

pub fn verify(
    abi: &str,
    mountinfo: &[u8],
    defaults: ModuleDefaults,
    paths: MountPaths<'_>,
) -> Result<(), &'static str> {
    if abi != RENDERING_ABI {
        return Err("overlay: unknown rendering ABI");
    }
    if !mountinfo.is_empty() && !mountinfo.ends_with(b"\n") {
        return Err("overlay: incomplete mountinfo final record");
    }
    let mut matched = false;
    for line in mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        // Parse the entire record even when it is not the requested target.
        // A truncated final record must not be hidden by an earlier match.
        let entry = parse_mountinfo(line)?;
        if !unescaped_eq(entry.target, paths.target) {
            continue;
        }
        if matched {
            return Err("overlay: duplicate target mount");
        }
        matched = true;
        if entry.root != b"/" {
            return Err("overlay: unexpected mount root");
        }
        writable(entry.flags)?;
        if entry.filesystem != b"overlay" {
            return Err("overlay: wrong filesystem type");
        }
        let options = entry.options;
        writable(options)?;
        let mut seen = 0u16;
        let mut index = defaults.index;
        let mut metacopy = defaults.metacopy;
        let mut redirect = !defaults.redirect_dir && !defaults.redirect_always_follow;
        // The module default is AUTO or OFF, never ON. With distinct ext4
        // layer superblocks, the qualified renderer must print xino=on.
        let mut xino = false;
        let mut nfs_export = defaults.nfs_export;
        let mut uuid_null = false;
        for option in options.split(|byte| *byte == b',') {
            let (key, value) = match option.iter().position(|byte| *byte == b'=') {
                Some(at) => (&option[..at], &option[at + 1..]),
                None => (option, b"".as_slice()),
            };
            let bit = match key {
                b"lowerdir" => {
                    if !unescaped_eq(value, paths.lower) {
                        return Err("overlay: lower path mismatch");
                    }
                    1
                }
                b"upperdir" => {
                    if !unescaped_eq(value, paths.upper) {
                        return Err("overlay: upper path mismatch");
                    }
                    2
                }
                b"workdir" => {
                    if !unescaped_eq(value, paths.work) {
                        return Err("overlay: work path mismatch");
                    }
                    4
                }
                b"index" => {
                    index = on_off(value)?;
                    8
                }
                b"metacopy" => {
                    metacopy = on_off(value)?;
                    16
                }
                b"redirect_dir" => {
                    redirect = value == b"nofollow";
                    if !matches!(value, b"on" | b"off" | b"follow" | b"nofollow") {
                        return Err("overlay: unknown redirect mode");
                    }
                    32
                }
                b"xino" => {
                    xino = value == b"on";
                    if !matches!(value, b"on" | b"off" | b"auto") {
                        return Err("overlay: unknown xino mode");
                    }
                    64
                }
                b"nfs_export" => {
                    nfs_export = on_off(value)?;
                    128
                }
                b"uuid" => {
                    uuid_null = value == b"null";
                    256
                }
                b"rw" | b"relatime" | b"seclabel" => continue,
                _ => return Err("overlay: unknown or forbidden effective option"),
            };
            if seen & bit != 0 {
                return Err("overlay: duplicate effective option");
            }
            seen |= bit;
        }
        if seen & 7 != 7 || !index || metacopy || !redirect || !xino || nfs_export || !uuid_null {
            return Err("overlay: effective persistence profile downgraded");
        }
    }
    if matched {
        Ok(())
    } else {
        Err("overlay: target mount missing")
    }
}

fn on_off(value: &[u8]) -> Result<bool, &'static str> {
    match value {
        b"on" => Ok(true),
        b"off" => Ok(false),
        _ => Err("overlay: unknown boolean option"),
    }
}

/// Verify the underlying maintenance mount independently of overlay's paths.
pub fn verify_ext4_mount(
    mountinfo: &[u8],
    target: &[u8],
    device: (u32, u32),
    read_only: bool,
) -> Result<(), &'static str> {
    if !mountinfo.is_empty() && !mountinfo.ends_with(b"\n") {
        return Err("overlay: incomplete mountinfo final record");
    }
    let mut found = false;
    for line in mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let entry = parse_mountinfo(line)?;
        if !unescaped_eq(entry.target, target) {
            continue;
        }
        if found {
            return Err("overlay: duplicate maintenance mount");
        }
        found = true;
        if entry.root != b"/" || entry.device != device {
            return Err("overlay: maintenance mount identity mismatch");
        }
        if entry.filesystem != b"ext4" {
            return Err("overlay: maintenance mount not ext4");
        }
        let flags = entry.flags;
        let options = entry.options;
        for options in [flags, options] {
            let expected = if read_only {
                b"ro".as_slice()
            } else {
                b"rw".as_slice()
            };
            let forbidden = if read_only {
                b"rw".as_slice()
            } else {
                b"ro".as_slice()
            };
            let mut count = 0;
            for option in options.split(|byte| *byte == b',') {
                if option == forbidden {
                    return Err("overlay: maintenance access mismatch");
                }
                if option == expected {
                    count += 1;
                }
            }
            if count != 1 {
                return Err("overlay: missing maintenance access evidence");
            }
        }
        if read_only
            && !options
                .split(|byte| *byte == b',')
                .any(|option| matches!(option, b"noload" | b"norecovery"))
        {
            return Err("overlay: lower journal suppression missing");
        }
    }
    if found {
        Ok(())
    } else {
        Err("overlay: maintenance mount missing")
    }
}

#[cfg(test)]
mod tests {
    use crate::overlay_verify::{verify, ModuleDefaults, MountPaths, RENDERING_ABI};

    fn defaults() -> ModuleDefaults {
        ModuleDefaults {
            index: true,
            metacopy: false,
            redirect_dir: false,
            redirect_always_follow: false,
            xino_auto: true,
            nfs_export: false,
        }
    }
    fn paths() -> MountPaths<'static> {
        MountPaths {
            target: b"/mnt/root",
            lower: b"/lower",
            upper: b"/upper",
            work: b"/work",
        }
    }
    const GOOD: &[u8] = b"20 1 0:20 / /mnt/root rw,relatime - overlay overlay rw,lowerdir=/lower,upperdir=/upper,workdir=/work,xino=on,uuid=null\n";

    #[test]
    fn qualified_omitted_defaults_require_observed_parameters() {
        assert!(verify(RENDERING_ABI, GOOD, defaults(), paths()).is_ok());
        let mut weakened = defaults();
        weakened.index = false;
        assert!(verify(RENDERING_ABI, GOOD, weakened, paths()).is_err());
        let mut weakened = defaults();
        weakened.redirect_always_follow = true;
        assert!(verify(RENDERING_ABI, GOOD, weakened, paths()).is_err());
        let mut changed = defaults();
        changed.xino_auto = false;
        assert!(verify(RENDERING_ABI, GOOD, changed, paths()).is_ok());
        let mut weakened = defaults();
        weakened.metacopy = true;
        assert!(verify(RENDERING_ABI, GOOD, weakened, paths()).is_err());
        let mut weakened = defaults();
        weakened.nfs_export = true;
        assert!(verify(RENDERING_ABI, GOOD, weakened, paths()).is_err());
        let mut weakened = defaults();
        weakened.redirect_dir = true;
        assert!(verify(RENDERING_ABI, GOOD, weakened, paths()).is_err());
    }
    #[test]
    fn omitted_xino_is_never_on_even_with_auto_default() {
        let omitted = b"20 1 0:20 / /mnt/root rw - overlay overlay rw,lowerdir=/lower,upperdir=/upper,workdir=/work,uuid=null\n";
        assert!(verify(RENDERING_ABI, omitted, defaults(), paths()).is_err());
        let mut off = defaults();
        off.xino_auto = false;
        assert!(verify(RENDERING_ABI, omitted, off, paths()).is_err());
    }
    #[test]
    fn module_parameters_use_exact_kernel_boolean_spelling() {
        use crate::overlay_verify::sysfs_bool;
        assert_eq!(sysfs_bool(b"Y\n"), Ok(true));
        assert_eq!(sysfs_bool(b"N\n"), Ok(false));
        for wrong in [b"true".as_slice(), b" Y\n", b"Y \n", b"Y\r\n", b""] {
            assert!(sysfs_bool(wrong).is_err());
        }
    }
    #[test]
    fn explicit_downgrade_duplicate_and_unknown_options_fail() {
        for option in [
            b",index=off".as_slice(),
            b",metacopy=on",
            b",redirect_dir=follow",
            b",xino=off",
            b",nfs_export=on",
            b",uuid=null",
            b",volatile",
            b",userxattr",
            b",fsync=auto",
        ] {
            let mut input = GOOD[..GOOD.len() - 1].to_vec();
            input.extend_from_slice(option);
            input.push(b'\n');
            assert!(verify(RENDERING_ABI, &input, defaults(), paths()).is_err());
        }
    }
    #[test]
    fn malformed_wrong_mount_and_unknown_abi_fail() {
        assert!(verify("future", GOOD, defaults(), paths()).is_err());
        assert!(verify(RENDERING_ABI, b"", defaults(), paths()).is_err());
        let mut duplicate = GOOD.to_vec();
        duplicate.extend_from_slice(GOOD);
        assert!(verify(RENDERING_ABI, &duplicate, defaults(), paths()).is_err());
        let paths = MountPaths {
            target: b"/mnt/root",
            lower: b"/wrong",
            ..paths()
        };
        assert!(verify(RENDERING_ABI, GOOD, defaults(), paths).is_err());
    }
    #[test]
    fn truncated_or_malformed_final_record_rejects_an_earlier_valid_match() {
        use crate::overlay_verify::verify_ext4_mount;
        let unrelated = b"21 1 0:21 / /unrelated rw - tmpfs tmpfs rw";
        let mut complete = GOOD.to_vec();
        complete.extend_from_slice(unrelated);
        assert!(verify(RENDERING_ABI, &complete, defaults(), paths()).is_err());
        complete.push(b'\n');
        assert!(verify(RENDERING_ABI, &complete, defaults(), paths()).is_ok());
        for cut in [1, 5, 10, unrelated.len() - 3] {
            let mut truncated = GOOD.to_vec();
            truncated.extend_from_slice(&unrelated[..cut]);
            assert!(verify(RENDERING_ABI, &truncated, defaults(), paths()).is_err());
            truncated.push(b'\n');
            assert!(verify(RENDERING_ABI, &truncated, defaults(), paths()).is_err());
            let mut maintenance =
                b"12 1 254:0 / /lower ro - ext4 /dev/vda ro,norecovery\n".to_vec();
            maintenance.extend_from_slice(&unrelated[..cut]);
            assert!(verify_ext4_mount(&maintenance, b"/lower", (254, 0), true).is_err());
            maintenance.push(b'\n');
            assert!(verify_ext4_mount(&maintenance, b"/lower", (254, 0), true).is_err());
        }
        for malformed in [
            b"21 1 0:x / /unrelated rw - tmpfs tmpfs rw".as_slice(),
            b"21 1 0:21 / /unrelated rw - tmpfs tmpfs rw extra",
            b"21 1 0:21 / /unrelated rw - tmpfs  rw",
        ] {
            let mut input = GOOD.to_vec();
            input.extend_from_slice(malformed);
            input.push(b'\n');
            assert!(verify(RENDERING_ABI, &input, defaults(), paths()).is_err());
        }
    }
    #[test]
    fn mountinfo_paths_decode_only_kernel_escapes() {
        let input = b"20 1 0:20 / /mnt/root rw - overlay overlay rw,lowerdir=/low\\040er,upperdir=/upper,workdir=/work,xino=on,uuid=null\n";
        let paths = MountPaths {
            lower: b"/low er",
            ..paths()
        };
        assert!(verify(RENDERING_ABI, input, defaults(), paths).is_ok());
    }
    #[test]
    fn maintenance_mount_identity_access_and_noload_are_required() {
        use crate::overlay_verify::verify_ext4_mount;
        let good = b"12 1 254:0 / /lower ro - ext4 /dev/vda ro,norecovery\n";
        assert!(verify_ext4_mount(good, b"/lower", (254, 0), true).is_ok());
        assert!(verify_ext4_mount(good, b"/lower", (254, 1), true).is_err());
        assert!(verify_ext4_mount(good, b"/lower", (254, 0), false).is_err());
        assert!(verify_ext4_mount(
            b"12 1 254:0 / /lower ro - ext4 /dev/vda ro\n",
            b"/lower",
            (254, 0),
            true
        )
        .is_err());
    }
}
