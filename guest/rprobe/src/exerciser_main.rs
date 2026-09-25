#![cfg_attr(
    not(all(target_os = "linux", target_arch = "aarch64", target_env = "musl")),
    allow(dead_code, unused_imports)
)]

#[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_env = "musl")))]
compile_error!("silo-rosetta-exerciser only supports aarch64-unknown-linux-musl");

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::time::{Duration, Instant};

use rprobe::exerciser::{
    encode, CHECK_FILE_IDENTITY, CHECK_METADATA_REJECTED, CHECK_MMAP_READ, CHECK_NAMESPACE,
    CHECK_READ_ONLY_MOUNT, CHECK_RENAME_REJECTED, CHECK_REPEATED_READ, CHECK_TRANSLATED_WORKLOAD,
    CHECK_TRUNCATE_REJECTED, CHECK_WRITE_REJECTED, PAYLOAD_LEN,
};

const ROOT: &str = "/mnt/rosetta";
const TRANSLATOR: &str = "/mnt/rosetta/rosetta";
const X86_WORKLOAD: &str = "/x86_64-static";
const WORKLOAD_STDOUT: &[u8] = b"SILO_X86_STATIC_OK\n";
const WORKLOAD_EXIT: i32 = 37;
const IOCTL_REQUEST: u32 = 0x8045_6122;
const DEV_INPUT_DIR: &str = "/dev/input";
const INPUT_EVENT_PREFIX: &str = "event";
const EV_KEY: u16 = 0x01;
const KEY_POWER: u16 = 116;
const KEY_RESTART: u16 = 408;

#[repr(C)]
#[derive(Clone, Copy)]
struct InputEvent64 {
    _seconds: i64,
    _microseconds: i64,
    event_type: u16,
    code: u16,
    value: i32,
}

const _: [(); 24] = [(); std::mem::size_of::<InputEvent64>()];

fn main() {
    if let Err(error) = run_with_console() {
        eprintln!("rosetta exerciser failed: {error}");
    }
    poweroff()
}

fn run_with_console() -> io::Result<()> {
    mount_filesystems()?;
    let mut console = open_console()?;
    if let Err(error) = run(&mut console) {
        let _ = writeln!(console, "rosetta exerciser failed: {error}");
        return Err(error);
    }
    Ok(())
}

fn run(console: &mut File) -> io::Result<()> {
    mount_rosetta()?;

    let mut checks = 0;
    checks |= verify_read_only_mount()?;
    checks |= verify_namespace()?;

    let mut translator = File::open(TRANSLATOR)?;
    let before = translator.metadata()?;
    if !before.file_type().is_file()
        || before.permissions().mode() & 0o111 == 0
        || before.len() == 0
    {
        return Err(io::Error::other("translator metadata is invalid"));
    }

    let sample_len = usize::try_from(before.len().min(4096))
        .map_err(|_| io::Error::other("translator sample length overflow"))?;
    let mut first = vec![0; sample_len];
    translator.read_exact(&mut first)?;
    translator.seek(SeekFrom::Start(0))?;
    let mut second = vec![0; sample_len];
    translator.read_exact(&mut second)?;
    if first != second {
        return Err(io::Error::other("repeated translator reads differ"));
    }
    checks |= CHECK_REPEATED_READ;

    // libc is used directly because this static guest exerciser has no nix dependency.
    let mapping = unsafe {
        libc::mmap(
            ptr::null_mut(),
            sample_len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            std::os::fd::AsRawFd::as_raw_fd(&translator),
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mapped = unsafe { std::slice::from_raw_parts(mapping.cast::<u8>(), sample_len) };
    let mapping_matches = mapped == first;
    let unmap_result = unsafe { libc::munmap(mapping, sample_len) };
    if unmap_result != 0 {
        return Err(io::Error::last_os_error());
    }
    if !mapping_matches {
        return Err(io::Error::other("mmap-backed translator read differs"));
    }
    checks |= CHECK_MMAP_READ;

    checks |= rejected(
        OpenOptions::new().write(true).open(TRANSLATOR).map(|_| ()),
        CHECK_WRITE_REJECTED,
    )?;
    checks |= rejected(truncate_translator(), CHECK_TRUNCATE_REJECTED)?;
    checks |= rejected(
        fs::set_permissions(TRANSLATOR, fs::Permissions::from_mode(0o700)),
        CHECK_METADATA_REJECTED,
    )?;
    checks |= rejected(
        fs::rename(TRANSLATOR, "/mnt/rosetta/renamed"),
        CHECK_RENAME_REJECTED,
    )?;

    let after = translator.metadata()?;
    if identity(&before) != identity(&after) {
        return Err(io::Error::other(
            "translator identity changed during exercise",
        ));
    }
    checks |= CHECK_FILE_IDENTITY;

    if Path::new(X86_WORKLOAD).try_exists()? {
        checks |= run_translated_workload(console)?;
    }

    let mut payload = [0xaa; PAYLOAD_LEN];
    // libc's musl binding uses Ioctl; the cast preserves the request's exact low 32 bits.
    let ioctl_result = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&translator),
            IOCTL_REQUEST as libc::Ioctl,
            payload.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    if ioctl_result < 0 {
        return Err(io::Error::last_os_error());
    }
    let power_inputs = open_power_inputs()?;
    let frame = encode(checks, ioctl_result, &payload)
        .map_err(|_| io::Error::other("failed to encode exerciser frame"))?;
    console.write_all(&frame)?;
    wait_for_shutdown(power_inputs)
}

fn run_translated_workload(console: &mut File) -> io::Result<u32> {
    writeln!(console, "translated_workload_start")?;
    console.flush()?;
    let output = Command::new(TRANSLATOR).arg(X86_WORKLOAD).output()?;
    writeln!(
        console,
        "translated_workload_result {} stdout_bytes={} stderr_bytes={} stderr={}",
        exit_description(&output.status),
        output.stdout.len(),
        output.stderr.len(),
        String::from_utf8_lossy(&output.stderr).escape_debug()
    )?;
    console.flush()?;
    if output.status.code() != Some(WORKLOAD_EXIT) {
        return Err(io::Error::other(format!(
            "translated workload exit differed; {}",
            exit_description(&output.status)
        )));
    }
    if output.stdout != WORKLOAD_STDOUT {
        return Err(io::Error::other(format!(
            "translated workload stdout differed; bytes={}",
            output.stdout.len()
        )));
    }
    if !output.stderr.is_empty() {
        return Err(io::Error::other(format!(
            "translated workload wrote stderr; bytes={}",
            output.stderr.len()
        )));
    }
    Ok(CHECK_TRANSLATED_WORKLOAD)
}

fn exit_description(status: &std::process::ExitStatus) -> String {
    format!("exit={:?} signal={:?}", status.code(), status.signal())
}

fn open_power_inputs() -> io::Result<Vec<File>> {
    let mut paths = Vec::<PathBuf>::new();
    for entry in fs::read_dir(DEV_INPUT_DIR)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(suffix) = name.strip_prefix(INPUT_EVENT_PREFIX) else {
            continue;
        };
        if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no input event devices",
        ));
    }
    paths.into_iter().map(File::open).collect()
}

fn wait_for_shutdown(mut inputs: Vec<File>) -> io::Result<()> {
    let mut poll_fds = inputs
        .iter()
        .map(|input| libc::pollfd {
            fd: input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect::<Vec<_>>();
    let poll_fd_count = libc::nfds_t::try_from(poll_fds.len())
        .map_err(|_| io::Error::other("too many input event devices"))?;
    loop {
        let count = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fd_count, -1) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        for (input, poll_fd) in inputs.iter_mut().zip(&poll_fds) {
            if poll_fd.revents & libc::POLLIN != 0 {
                let event = read_input_event(input)?;
                if event.event_type == EV_KEY
                    && matches!(event.code, KEY_POWER | KEY_RESTART)
                    && event.value == 1
                {
                    return Ok(());
                }
            }
            if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("input event device stopped"));
            }
        }
    }
}

fn read_input_event(input: &mut File) -> io::Result<InputEvent64> {
    let mut event = MaybeUninit::<InputEvent64>::uninit();
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            event.as_mut_ptr().cast::<u8>(),
            std::mem::size_of::<InputEvent64>(),
        )
    };
    input.read_exact(bytes)?;
    Ok(unsafe { event.assume_init() })
}

fn mount_filesystems() -> io::Result<()> {
    for path in ["/dev", "/mnt", ROOT] {
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    mount("devtmpfs", "/dev", "devtmpfs", 0)?;
    mount("proc", "/proc", "proc", 0)
}

fn mount_rosetta() -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let flags = libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOATIME;
    loop {
        match mount("rosetta", ROOT, "virtiofs", flags) {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT) | Some(libc::ENODEV)
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn mount(source: &str, target: &str, filesystem: &str, flags: libc::c_ulong) -> io::Result<()> {
    let source = std::ffi::CString::new(source).map_err(|_| io::Error::other("invalid source"))?;
    let target = std::ffi::CString::new(target).map_err(|_| io::Error::other("invalid target"))?;
    let filesystem =
        std::ffi::CString::new(filesystem).map_err(|_| io::Error::other("invalid filesystem"))?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags,
            ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn open_console() -> io::Result<File> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
            .open("/dev/hvc0")
        {
            Ok(file) => {
                configure_raw(&file)?;
                return Ok(file);
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT) | Some(libc::ENODEV)
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn configure_raw(file: &File) -> io::Result<()> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(file);
    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::cfmakeraw(&mut termios) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_read_only_mount() -> io::Result<u32> {
    let path = std::ffi::CString::new(ROOT).map_err(|_| io::Error::other("invalid root"))?;
    let mut stats = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if stats.f_flag & libc::ST_RDONLY == 0 {
        return Err(io::Error::other("Rosetta mount is not read-only"));
    }
    Ok(CHECK_READ_ONLY_MOUNT)
}

fn verify_namespace() -> io::Result<u32> {
    let mut names = fs::read_dir(ROOT)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    if names != [std::ffi::OsString::from("rosetta")] {
        return Err(io::Error::other("Rosetta namespace inventory differs"));
    }
    Ok(CHECK_NAMESPACE)
}

fn rejected(result: io::Result<()>, check: u32) -> io::Result<u32> {
    match result {
        Err(error) if matches!(error.raw_os_error(), Some(libc::EROFS) | Some(libc::EACCES)) => {
            Ok(check)
        }
        Err(error) => Err(io::Error::other(format!(
            "mutation failed with unexpected errno: {error}"
        ))),
        Ok(()) => Err(io::Error::other(
            "read-only mutation unexpectedly succeeded",
        )),
    }
}

fn truncate_translator() -> io::Result<()> {
    let path = std::ffi::CString::new(TRANSLATOR)
        .map_err(|_| io::Error::other("invalid translator path"))?;
    if unsafe { libc::truncate(path.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

fn poweroff() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    loop {
        unsafe { libc::pause() };
    }
}
