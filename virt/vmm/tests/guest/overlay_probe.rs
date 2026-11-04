//! Standalone guest utility, built by the smoke controller, never a Cargo VM test.
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::os::fd::AsRawFd;
use std::path::Path;

#[path = "../../../../guest/init/src/overlay_verify.rs"]
mod overlay_verify;

// This standalone rustc utility has no crate dependencies; nix is unavailable.
unsafe extern "C" {
    fn getxattr(path: *const std::ffi::c_char, name: *const std::ffi::c_char, value: *mut u8, size: usize) -> isize;
    fn ioctl(fd: i32, request: usize, ...) -> i32;
    fn fallocate(fd: i32, mode: i32, offset: i64, length: i64) -> i32;
    fn syncfs(fd: i32) -> i32;
    fn name_to_handle_at(dirfd: i32, path: *const std::ffi::c_char, handle: *mut std::ffi::c_void, mount_id: *mut i32, flags: i32) -> i32;
}

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(io::Error::other(message)) }
}
fn serial(role: &str) -> io::Result<String> {
    serial_id(&format!("silo-root-{role}"))
}
fn serial_id(expected: &str) -> io::Result<String> {
    let mut found = None;
    for entry in fs::read_dir("/sys/block")? {
        let entry = entry?;
        if let Ok(value) = fs::read_to_string(entry.path().join("serial")) {
            if value.strip_suffix('\n').unwrap_or(&value) == expected {
                require(found.is_none(), "duplicate serial")?;
                found = Some(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    found.ok_or_else(|| io::Error::other("missing serial"))
}
fn read_lower(offset: u64, length: usize) -> io::Result<()> {
    require(length > 0 && length <= 65536, "read bound")?;
    let name = serial("lower")?;
    let mut bytes = vec![0; length];
    File::open(format!("/dev/{name}"))?.read_exact_at(&mut bytes, offset)?;
    print!("{{\"offset\":{offset},\"hex\":\"");
    for byte in bytes { print!("{byte:02x}"); }
    println!("\"}}");
    Ok(())
}
fn lower_ro() -> io::Result<()> {
    let name = serial("lower")?;
    require(fs::read_to_string(format!("/sys/block/{name}/ro"))?.trim() == "1", "lower sysfs writable")?;
    let result = OpenOptions::new().write(true).open(format!("/dev/{name}"))
        .and_then(|f| f.write_at(&[0; 512], 0).map(|_| ()));
    match result {
        Err(error) => {
            let errno = error.raw_os_error().ok_or_else(|| io::Error::other("missing lower write errno"))?;
            require(matches!(errno, 1 | 13 | 30), "lower denial not a read-only/access error")?;
            println!("{{\"write_errno\":{errno}}}");
            Ok(())
        }
        Ok(()) => Err(io::Error::other("lower write succeeded")),
    }
}
fn xattr(path: &str, name: &str) -> io::Result<Vec<u8>> {
    let path = CString::new(path)?;
    let name = CString::new(name)?;
    let mut buffer = vec![0; 4096];
    let length = unsafe { getxattr(path.as_ptr(), name.as_ptr(), buffer.as_mut_ptr(), buffer.len()) };
    if length < 0 {
        let error = io::Error::last_os_error();
        eprintln!("getxattr path={} name={} failed: {error}", path.to_string_lossy(), name.to_string_lossy());
        return Err(error);
    }
    buffer.truncate(length as usize);
    Ok(buffer)
}
fn metadata() -> io::Result<()> {
    let a = "/overlay-fixture/a";
    let b = "/overlay-fixture/b";
    let before = [xattr(a, "user.near-limit")?, xattr(a, "system.posix_acl_access")?];
    require(before[0].len() == 2750 && before[0].iter().all(|byte|*byte == b'x'), "lower user xattr differs from fixture bytes")?;
    let access_acl: [u8; 44] = [
        0x02, 0, 0, 0,
        0x01, 0, 0x06, 0, 0xff, 0xff, 0xff, 0xff,
        0x02, 0, 0x04, 0, 0xd2, 0x04, 0, 0,
        0x04, 0, 0x04, 0, 0xff, 0xff, 0xff, 0xff,
        0x10, 0, 0x04, 0, 0xff, 0xff, 0xff, 0xff,
        0x20, 0, 0x04, 0, 0xff, 0xff, 0xff, 0xff,
    ];
    require(before[1] == access_acl, "lower named-user ACL differs from fixture bytes")?;
    OpenOptions::new().write(true).open(a)?.write_all_at(b"changed", 0)?;
    require(fs::read(b)?.starts_with(b"changed"), "newly opened hardlink lost copy-up")?;
    let ma = fs::metadata(a)?;
    let mb = fs::metadata(b)?;
    require(ma.ino() == mb.ino() && ma.dev() == mb.dev(), "copy-up split hardlink identity")?;
    require(xattr(a,"user.near-limit")? == before[0] && xattr(a,"system.posix_acl_access")? == before[1], "copy-up lost metadata")?;
    let cap_path = "/overlay-fixture/capability";
    let capability = xattr(cap_path, "security.capability")?;
    let expected_capability: [u8; 20] = [0x01, 0, 0, 0x02, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    require(capability == expected_capability, "lower capability differs from fixture bytes")?;
    let cap_file = OpenOptions::new().write(true).open(cap_path)?;
    cap_file.sync_all()?;
    require(xattr(cap_path, "security.capability")? == capability, "copy-up lost capability")?;
    // Direct rename is the EXDEV oracle. Shell mv may hide it by copying.
    let error = fs::rename("/overlay-fixture/lower-dir", "/overlay-fixture/renamed-lower").err()
        .ok_or_else(|| io::Error::other("lower directory rename succeeded"))?;
    require(error.raw_os_error() == Some(18), "lower rename not EXDEV")?;
    fs::create_dir("/upper-only")?;
    fs::rename("/upper-only", "/upper-renamed")?;
    fs::remove_file("/overlay-fixture/deleted")?;
    fs::remove_file("/overlay-fixture/opaque/old")?;
    fs::remove_dir("/overlay-fixture/opaque")?;
    fs::create_dir("/overlay-fixture/opaque")?;
    fs::write("/overlay-fixture/opaque/new", b"new")?;
    fs::remove_file(a)?;
    File::open("/")?.sync_all()?;
    println!("{{\"hardlinks\":true,\"metadata\":true,\"rename_errno\":18}}");
    Ok(())
}
fn persist_check() -> io::Result<()> {
    require(fs::read("/overlay-fixture/b")?.starts_with(b"changed"), "hardlink data lost on restart")?;
    require(!Path::new("/overlay-fixture/a").exists() && !Path::new("/overlay-fixture/deleted").exists(), "whiteout lost")?;
    require(!Path::new("/overlay-fixture/opaque/old").exists(), "opacity lost")?;
    require(fs::read("/overlay-fixture/opaque/new")? == b"new", "opacity new entry lost")?;
    require(xattr("/overlay-fixture/b", "user.near-limit")?.len() >= 2700, "index metadata lost")?;
    println!("{{\"persistent\":true}}"); Ok(())
}
fn fill(kind: &str) -> io::Result<()> {
    // Stderr is carried by the real exec stream; stdout remains the errno oracle.
    // Bound diagnostics to the first MiB rather than logging each fill iteration.
    let stage = |value: &str| {
        if kind == "host" { eprintln!("SILO_HOST_ENOSPC stage={value}"); }
    };
    stage("mkdir");
    fs::create_dir_all("/fill")?;
    stage("mkdir-complete");
    let mut count = 0u64;
    let failure = loop {
        let path = format!("/fill/{count}");
        let result = match kind {
            // Empty-file creation is the inode exhaustion workload, not a
            // per-inode journal commit benchmark. Flush the whole filesystem
            // once below before the host observes exhaustion.
            "inodes" => File::create(path).map(drop),
            "blocks" | "host" => (|| {
                if count == 0 { stage("create"); }
                let mut f = File::create(path)?;
                if count == 0 { stage("write"); }
                for _ in 0..16 { f.write_all(&[0x5a; 65536])?; }
                if count == 0 { stage("fsync"); }
                f.sync_all()?;
                if count == 0 { stage("fsync-complete"); }
                Ok::<(), io::Error>(())
            })(),
            "copyup" => OpenOptions::new().write(true).open("/overlay-fixture/large").and_then(|f| { f.write_all_at(b"x",0)?; f.sync_all() }),
            _ => return Err(io::Error::other("unknown fill mode")),
        };
        if let Err(error) = result { break error; }
        count += 1;
        if kind == "copyup" { return Err(io::Error::other("copy-up unexpectedly fit")); }
        require(count < 2_000_000, "fill safety bound")?;
    };
    let errno = failure.raw_os_error().ok_or_else(|| io::Error::other("missing actual errno"))?;
    require(if kind == "host" { errno == 5 || errno == 28 } else { errno == 28 }, "unexpected exhaustion errno")?;
    if kind == "inodes" {
        let directory = File::open("/fill")?;
        if unsafe { syncfs(directory.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    println!("{{\"errno\":{errno},\"completed\":{count}}}"); Ok(())
}
fn directories() -> io::Result<()> {
    fs::create_dir("/directory-scale")?;
    for index in 0..66000 { fs::create_dir(format!("/directory-scale/d{index:05}"))?; }
    require(fs::read_dir("/directory-scale")?.count() == 66000, "directory count")?;
    for index in [0, 32000, 64999, 65999] { require(fs::metadata(format!("/directory-scale/d{index:05}"))?.is_dir(), "directory lookup")?; }
    File::open("/directory-scale")?.sync_all()?;
    println!("{{\"directories\":66000,\"links\":{}}}", fs::metadata("/directory-scale")?.nlink()); Ok(())
}
fn discard(device: &str, operation: &str, offset: u64, length: u64) -> io::Result<()> {
    require(device.starts_with("/dev/") && !device.contains(".."), "scratch block path")?;
    let name = device.trim_start_matches("/dev/");
    let id = fs::read_to_string(format!("/sys/block/{name}/serial"))?;
    require(id.strip_suffix('\n').unwrap_or(&id) == "silo-data-0", "discard requires dedicated scratch data identity")?;
    let f = OpenOptions::new().read(true).write(true).open(device)?;
    let range = [offset, length];
    let result = match operation {
        "discard" => unsafe { ioctl(f.as_raw_fd(), 0x1277usize, range.as_ptr()) },
        "zero" => unsafe { ioctl(f.as_raw_fd(), 0x127fusize, range.as_ptr()) },
        "zero-unmap" => {
            let offset = i64::try_from(offset).map_err(io::Error::other)?;
            let length = i64::try_from(length).map_err(io::Error::other)?;
            // Actual block-device fallocate: PUNCH_HOLE|KEEP_SIZE selects
            // BLKDEV_ZERO_NOFALLBACK without NOUNMAP in the qualified kernel.
            unsafe { fallocate(f.as_raw_fd(), 0x03, offset, length) }
        }
        _ => return Err(io::Error::other("unknown block operation")),
    };
    if result != 0 { return Err(io::Error::last_os_error()); }
    f.sync_all()?;
    println!("{{\"operation\":\"{operation}\",\"offset\":{offset},\"length\":{length}}}"); Ok(())
}
fn range_request(value: &str) -> io::Result<()> {
    let mut parts = value.split(':');
    let operation = parts.next().ok_or_else(||io::Error::other("range operation"))?;
    let number = |part: Option<&str>| -> io::Result<u64> { part.ok_or_else(||io::Error::other("range argument"))?.parse().map_err(io::Error::other) };
    let offset = number(parts.next())?;
    let length = number(parts.next())?;
    require(parts.next().is_none() && length > 0 && offset % 512 == 0 && length % 512 == 0 && offset.checked_add(length).is_some_and(|end|end <= 4 * 1024 * 1024), "bounded range")?;
    let device = format!("/dev/{}",serial_id("silo-data-0")?);
    require(fs::metadata(&device)?.file_type().is_block_device(), "actual Data block device")?;
    discard(&device,operation,offset,length)?;
    let file = File::open(&device)?;
    let mut bytes = [0u8;65536];
    let mut done = 0;
    while done < length {
        let count = (length - done).min(bytes.len() as u64) as usize;
        file.read_exact_at(&mut bytes[..count], offset + done)?;
        require(bytes[..count].iter().all(|byte|*byte == 0), "range did not read zero")?;
        done += count as u64;
    }
    println!("SILO_RANGE_RESULT operation={operation} offset={offset} length={length}");
    Ok(())
}
fn export_handle(path: &str) -> io::Result<()> {
    #[repr(C)]
    struct Handle { bytes: u32, kind: i32, payload: [u8; 128] }
    let mut handle = Handle { bytes: 128, kind: 0, payload: [0;128] };
    let mut mount_id = 0;
    let path = CString::new(path)?;
    let result = unsafe { name_to_handle_at(-100, path.as_ptr(), (&mut handle as *mut Handle).cast(), &mut mount_id, 0) };
    let errno = if result == 0 { 0 } else { io::Error::last_os_error().raw_os_error().ok_or_else(||io::Error::other("handle errno"))? };
    println!("{{\"errno\":{errno},\"mountId\":{mount_id},\"handleBytes\":{}}}", handle.bytes);
    Ok(())
}
fn downgrade() -> io::Result<()> {
    use overlay_verify::{ModuleDefaults, MountPaths};
    let parameter = |name| -> io::Result<bool> {
        let bytes = fs::read(format!("/sys/module/overlay/parameters/{name}"))?;
        overlay_verify::sysfs_bool(&bytes).map_err(io::Error::other)
    };
    let defaults = ModuleDefaults { index: parameter("index")?, metacopy: parameter("metacopy")?, redirect_dir: parameter("redirect_dir")?, redirect_always_follow: parameter("redirect_always_follow")?, xino_auto: parameter("xino_auto")?, nfs_export: parameter("nfs_export")? };
    let mountinfo = fs::read("/proc/self/mountinfo")?;
    overlay_verify::verify("linux-overlayfs-mountinfo-v1", &mountinfo, defaults,
        MountPaths { target: b"/", lower: b"/run/silo/rootfs/lower", upper: b"/run/silo/rootfs/upperfs/upper", work: b"/run/silo/rootfs/upperfs/work" }).map_err(io::Error::other)?;
    let text = std::str::from_utf8(&mountinfo).map_err(io::Error::other)?;
    let line = text.lines().find(|line| line.split(' ').nth(4) == Some("/downgrade/merged"))
        .ok_or_else(||io::Error::other("scratch mount did not succeed"))?;
    let super_options = line.split_once(" - overlay ").and_then(|(_,tail)|tail.split(' ').nth(1))
        .ok_or_else(||io::Error::other("scratch overlay mountinfo malformed"))?;
    let effective_index = match super_options.split(',').find(|item|item.starts_with("index=")) {
        Some("index=on") => true,
        Some("index=off") => false,
        Some(_) => return Err(io::Error::other("unknown actual index rendering")),
        None => defaults.index,
    };
    require(!effective_index, "scratch mount did not actually downgrade index")?;
    let result = overlay_verify::verify("linux-overlayfs-mountinfo-v1", &mountinfo, defaults,
        MountPaths { target: b"/downgrade/merged", lower: b"/downgrade/lower", upper: b"/run/silo/rootfs/upperfs/downgrade-upper", work: b"/run/silo/rootfs/upperfs/downgrade-work" });
    require(result == Err("overlay: effective persistence profile downgraded"), "verifier failed for a reason other than effective downgrade")?;
    println!("{{\"effective_index\":false,\"production_positive_control\":true,\"verifier_rejected\":true,\"reason\":\"effective persistence profile downgraded\"}}"); Ok(())
}
fn mapping(positions: &str) -> io::Result<()> {
    require(positions.len() <= 4096, "mapping position list bound")?;
    let name = serial("lower")?;
    let file = File::open(format!("/dev/{name}"))?;
    let mut bytes = [0u8; 65536];
    let mut count = 0;
    for position in positions.split(',') {
        count += 1;
        require(count <= 64, "mapping probe count bound")?;
        let (offset, length) = position.split_once(':').ok_or_else(||io::Error::other("mapping position"))?;
        let offset = offset.parse::<u64>().map_err(io::Error::other)?;
        let length = length.parse::<usize>().map_err(io::Error::other)?;
        require(length > 0 && length <= bytes.len(), "mapping length bound")?;
        file.read_exact_at(&mut bytes[..length], offset)?;
        print!("SILO_MAP_RESULT {{\"offset\":{offset},\"hex\":\"");
        for byte in &bytes[..length] { print!("{byte:02x}"); }
        println!("\"}}");
    }
    require(count > 0, "empty mapping probes")
}

fn data_io(write: bool) -> io::Result<()> {
    const DEVICES: usize = 14;
    const ROUNDS: usize = 8;
    const BYTES: usize = 65536;
    let mut files = Vec::with_capacity(DEVICES);
    for index in 0..DEVICES {
        let name = serial_id(&format!("silo-data-{index}"))?;
        let file = OpenOptions::new().read(true).write(true).open(format!("/dev/{name}"))?;
        require(file.metadata()?.file_type().is_block_device(), "Data I/O requires real block devices")?;
        let mut capacity = 0u64;
        if unsafe { ioctl(file.as_raw_fd(), 0x80081272usize, &mut capacity as *mut u64) } != 0 {
            return Err(io::Error::last_os_error());
        }
        require(capacity == 8 * 1024 * 1024, "dedicated Data capacity changed")?;
        files.push(file);
    }
    let barrier = std::sync::Barrier::new(DEVICES);
    let start = (std::sync::Mutex::new(None::<bool>), std::sync::Condvar::new());
    let (completed, bytes) = std::thread::scope(|scope| -> io::Result<(usize, u64)> {
        let mut handles = Vec::with_capacity(DEVICES);
        let mut failure = None;
        for (index, file) in files.into_iter().enumerate() {
            let barrier = &barrier;
            let start = &start;
            let spawned = std::thread::Builder::new().spawn_scoped(scope, move || -> io::Result<u64> {
                let mut ready = start.0.lock().map_err(|_|io::Error::other("Data start gate poisoned"))?;
                while ready.is_none() {
                    ready = start.1.wait(ready).map_err(|_|io::Error::other("Data start gate poisoned"))?;
                }
                let proceed = (*ready).ok_or_else(||io::Error::other("Data start gate missing"))?;
                drop(ready);
                if !proceed { return Ok(0); }
                let mut first_error = None;
                let mut written = [0u8; BYTES];
                let mut actual = [0u8; BYTES];
                let mut verified = 0u64;
                for round in 0..ROUNDS {
                    for (position, byte) in written.iter_mut().enumerate() {
                        *byte = (index * 17 + round * 29 + position) as u8;
                    }
                    let offset = (1024 * 1024 + round * 512 * 1024 + index * 4096) as u64;
                    barrier.wait();
                    if write && first_error.is_none() {
                        if let Err(error) = file.write_all_at(&written, offset).and_then(|()|file.sync_all()) {
                            first_error = Some(error);
                        }
                    }
                    barrier.wait();
                    if first_error.is_none() {
                        let checked = (|| -> io::Result<()> {
                            // Dedicated scratch Data only: invalidate guest block
                            // cache so the following read must reach virtio again.
                            if unsafe { ioctl(file.as_raw_fd(), 0x1261usize, 0usize) } != 0 {
                                return Err(io::Error::last_os_error());
                            }
                            file.read_exact_at(&mut actual, offset)?;
                            require(actual == written, "concurrent Data bytes mismatch")
                        })();
                        match checked {
                            Ok(()) => verified += BYTES as u64,
                            Err(error) => first_error = Some(error),
                        }
                    }
                    // Failed workers still participate in every round, so one
                    // genuine I/O failure cannot strand the other barrier users.
                }
                match first_error { Some(error) => Err(error), None => Ok(verified) }
            });
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(error) => { failure = Some(error); break; }
            }
        }
        // Do not release any worker until all threads exist. A failed spawn
        // cancels startup before barriers and all scoped workers are reaped.
        *start.0.lock().map_err(|_|io::Error::other("Data start gate poisoned"))? = Some(failure.is_none());
        start.1.notify_all();
        let mut completed = 0;
        let mut bytes = 0;
        for handle in handles {
            match handle.join() {
                Ok(Ok(verified)) => { if verified != 0 { completed += 1; } bytes += verified; }
                Ok(Err(error)) => { if failure.is_none() { failure = Some(error); } }
                Err(_) => { if failure.is_none() { failure = Some(io::Error::other("Data I/O worker panicked")); } }
            }
        }
        if let Some(error) = failure { return Err(error); }
        Ok((completed, bytes))
    })?;
    require(completed == DEVICES && bytes == (DEVICES * ROUNDS * BYTES) as u64, "concurrent Data completion coverage")?;
    println!("{{\"completedDevices\":{completed},\"rounds\":{ROUNDS},\"bytesPerRange\":{BYTES},\"verifiedBytes\":{bytes},\"wrote\":{write}}}");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let arg = |n: usize| args.get(n).map(String::as_str).ok_or_else(|| io::Error::other("missing argument"));
    match arg(1)? {
        "read" => read_lower(arg(2)?.parse()?, arg(3)?.parse()?)?,
        "lower-ro" => lower_ro()?,
        "mapping" => mapping(arg(2)?)?,
        "metadata" => metadata()?,
        "persist-check" => persist_check()?,
        "fill" => fill(arg(2)?)?,
        "dirs" => directories()?,
        "discard" => discard(arg(2)?,arg(3)?,arg(4)?.parse()?,arg(5)?.parse()?)?,
        "data-io" => data_io(match arg(2)? { "write-read" => true, "read" => false, _ => return Err(io::Error::other("Data I/O mode").into()) })?,
        "range-request" => range_request(arg(2)?)?,
        "downgrade" => downgrade()?,
        "export-handle" => export_handle(arg(2)?)?,
        "durable" => { let mut f=File::create(arg(2)?)?; f.write_all(b"committed\n")?; f.sync_all()?; File::open(Path::new(arg(2)?).parent().ok_or_else(||io::Error::other("parent"))?)?.sync_all()?; }
        "write-loop" => { let mut n=0u64; let mut bytes=[0u8;65536]; loop { bytes.fill(n as u8); let mut f=File::create(format!("/dirty-{}", n%32))?; f.write_all(&bytes)?; if n%8==0 {f.sync_all()?;} if n==16 { println!("SILO_DIRTY_WRITER_STARTED"); io::stdout().flush()?; } n+=1; } }
        "syncfs" => { let f=File::open("/run/silo/rootfs/upperfs")?; if unsafe{syncfs(f.as_raw_fd())} != 0 {return Err(io::Error::last_os_error().into());} }
        "read-file" => { let mut f=File::open(arg(2)?)?; f.seek(SeekFrom::Start(arg(3)?.parse()?))?; let mut b=[0;512]; f.read_exact(&mut b)?; for v in b { print!("{v:02x}"); } println!(); }
        _ => return Err(io::Error::other("unknown probe command").into()),
    }
    Ok(())
}
