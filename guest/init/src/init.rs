#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::applets::{self, install};
use crate::io;

const DEFAULT_ROOT: &[u8] = b"/dev/vda";
pub(crate) const DEFAULT_INIT: &[u8] = b"/sbin/init";
const MNT_ROOT: &[u8] = b"/mnt/root";
const AGENT_PAYLOAD_DIR: &[u8] = b"/agent";
const AGENT_SOURCE_BINARY: &[u8] = b"/agent/bento-agent";
const AGENT_RUN_DIR: &[u8] = b"/run/agent";
const AGENT_RUN_BINARY: &[u8] = b"/run/agent/bento-agent";
const SYSTEMD_UNIT_DIR: &[u8] = b"/run/systemd/system";
const SYSTEMD_WANTS_DIR: &[u8] = b"/run/systemd/system/multi-user.target.wants";
const AGENT_SERVICE_PATH: &[u8] = b"/run/systemd/system/bento-agent.service";
const AGENT_SERVICE_WANTS_PATH: &[u8] =
    b"/run/systemd/system/multi-user.target.wants/bento-agent.service";
const AGENT_SERVICE_WANTS_TARGET: &[u8] = b"../bento-agent.service";
const AGENT_SERVICE_UNIT: &[u8] = b"[Unit]\n\
Description=Bento Guest Agent\n\
After=basic.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=/run/agent/bento-agent\n\
Restart=on-failure\n\
RestartSec=1s\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";

struct BootConfig {
    root: Vec<u8>,
    init: Vec<u8>,
    rootfstype: Option<Vec<u8>>,
}

pub(crate) fn init(_argc: i32, _argv: *const *const u8) -> i32 {
    if let Err(message) = run_init() {
        io::write(io::STDERR, "init: ");
        io::write(io::STDERR, message);
        io::write(io::STDERR, "\n");
        rescue_shell();
    }
    0
}

fn run_init() -> Result<(), &'static str> {
    if io::getpid() != 1 {
        return Err("refusing to run init outside PID 1");
    }

    prepare_directories()?;
    mount_essential_filesystems()?;
    install(b"/bin");
    install(b"/sbin");

    let config = read_boot_config();
    if !config.root.starts_with(b"/") {
        return Err("root= must be an absolute device path");
    }
    if !is_block_device(&config.root) {
        return Err("root= does not point at a block device");
    }

    if mount_root(&config) != 0 {
        return Err("failed to mount root filesystem");
    }
    prepare_agent_handoff()?;

    let init_path = target_init_path(&config.init).ok_or("target init path is too long")?;
    if io::access(&init_path, libc::X_OK) != 0 {
        return Err("target init is not executable");
    }

    let init_argv = [config.init.as_slice()];
    if do_switch_root(MNT_ROOT, &config.init, &init_argv) != 0 {
        return Err("switch_root failed");
    }

    Ok(())
}

fn prepare_directories() -> Result<(), &'static str> {
    for path in [
        b"/bin".as_slice(),
        b"/sbin",
        b"/dev",
        b"/etc",
        b"/mnt",
        b"/mnt/root",
        b"/proc",
        b"/run",
        b"/sys",
        b"/tmp",
        b"/usr",
        b"/usr/bin",
        b"/usr/sbin",
    ] {
        if applets::files::mkdir_parents(path, 0o755) != 0 {
            return Err("failed to create initramfs directory");
        }
    }
    Ok(())
}

fn mount_essential_filesystems() -> Result<(), &'static str> {
    mount_ignore_busy(b"devtmpfs", b"/dev", b"devtmpfs")?;
    mount_ignore_busy(b"proc", b"/proc", b"proc")?;
    mount_ignore_busy(b"sysfs", b"/sys", b"sysfs")?;
    mount_ignore_busy(b"tmpfs", b"/tmp", b"tmpfs")?;
    mount_ignore_busy(b"tmpfs", b"/run", b"tmpfs")?;
    Ok(())
}

fn mount_ignore_busy(source: &[u8], target: &[u8], fstype: &[u8]) -> Result<(), &'static str> {
    if applets::system::mount_one(source, target, Some(fstype), 0, None) == 0 {
        return Ok(());
    }
    if io::errno() == libc::EBUSY {
        return Ok(());
    }
    Err("failed to mount initramfs filesystem")
}

fn read_boot_config() -> BootConfig {
    let fd = io::open(b"/proc/cmdline", libc::O_RDONLY, 0);
    let cmdline = if fd >= 0 {
        let bytes = io::read_all(fd);
        io::close(fd);
        bytes
    } else {
        Vec::new()
    };

    BootConfig {
        root: cmdline_value(&cmdline, b"root=")
            .unwrap_or(DEFAULT_ROOT)
            .to_vec(),
        init: cmdline_value(&cmdline, b"init=")
            .unwrap_or(DEFAULT_INIT)
            .to_vec(),
        rootfstype: cmdline_value(&cmdline, b"rootfstype=").map(|value| value.to_vec()),
    }
}

fn cmdline_value<'a>(cmdline: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut start = 0;
    for index in 0..=cmdline.len() {
        if index == cmdline.len() || cmdline[index].is_ascii_whitespace() {
            let token = &cmdline[start..index];
            if token.starts_with(key) {
                return Some(&token[key.len()..]);
            }
            start = index + 1;
        }
    }
    None
}

fn is_block_device(path: &[u8]) -> bool {
    let mut stat = io::stat_zeroed();
    if io::stat(path, &mut stat) != 0 {
        return false;
    }
    (stat.st_mode & libc::S_IFMT) == libc::S_IFBLK
}

fn mount_root(config: &BootConfig) -> i32 {
    if let Some(fstype) = config.rootfstype.as_deref() {
        applets::system::mount_one(&config.root, MNT_ROOT, Some(fstype), 0, None)
    } else {
        applets::system::mount_block_auto(&config.root, MNT_ROOT)
    }
}

fn prepare_agent_handoff() -> Result<(), &'static str> {
    if io::access(AGENT_PAYLOAD_DIR, libc::F_OK) != 0 {
        return Ok(());
    }

    if io::access(AGENT_SOURCE_BINARY, libc::R_OK) != 0 {
        return Err("agent payload is missing /agent/bento-agent");
    }

    if applets::files::mkdir_parents(AGENT_RUN_DIR, 0o755) != 0 {
        return Err("failed to create /run/agent");
    }
    if applets::files::mkdir_parents(SYSTEMD_UNIT_DIR, 0o755) != 0 {
        return Err("failed to create /run/systemd/system");
    }
    if applets::files::mkdir_parents(SYSTEMD_WANTS_DIR, 0o755) != 0 {
        return Err("failed to create bento-agent systemd wants directory");
    }

    copy_file(AGENT_SOURCE_BINARY, AGENT_RUN_BINARY, 0o755)?;
    write_static_file(AGENT_SERVICE_PATH, AGENT_SERVICE_UNIT, 0o644)?;

    if io::symlink(AGENT_SERVICE_WANTS_TARGET, AGENT_SERVICE_WANTS_PATH) != 0
        && io::errno() != libc::EEXIST
    {
        return Err("failed to enable bento-agent systemd unit");
    }

    Ok(())
}

fn copy_file(source: &[u8], target: &[u8], mode: u32) -> Result<(), &'static str> {
    let input = io::open(source, libc::O_RDONLY, 0);
    if input < 0 {
        return Err("failed to open agent payload source");
    }

    let output = io::open(target, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, mode);
    if output < 0 {
        io::close(input);
        return Err("failed to create agent payload target");
    }

    let mut result = Ok(());
    let mut buf = [0u8; 4096];
    loop {
        let len = io::read(input, &mut buf);
        if len < 0 {
            result = Err("failed to read agent payload source");
            break;
        }
        if len == 0 {
            break;
        }
        if io::write_buf(output, &buf[..len as usize]) != len {
            result = Err("failed to write agent payload target");
            break;
        }
    }

    if io::close(input) != 0 && result.is_ok() {
        result = Err("failed to close agent payload source");
    }
    if io::close(output) != 0 && result.is_ok() {
        result = Err("failed to close agent payload target");
    }
    if result.is_ok() && io::chmod(target, mode) != 0 {
        result = Err("failed to set agent payload permissions");
    }

    result
}

fn write_static_file(path: &[u8], contents: &[u8], mode: u32) -> Result<(), &'static str> {
    let fd = io::open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, mode);
    if fd < 0 {
        return Err("failed to create generated file");
    }

    let mut result = Ok(());
    if io::write_buf(fd, contents) != contents.len() as isize {
        result = Err("failed to write generated file");
    }
    if io::close(fd) != 0 && result.is_ok() {
        result = Err("failed to close generated file");
    }
    if result.is_ok() && io::chmod(path, mode) != 0 {
        result = Err("failed to set generated file permissions");
    }

    result
}

fn target_init_path(init: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(MNT_ROOT);
    if !init.starts_with(b"/") {
        out.push(b'/');
    }
    out.extend_from_slice(init);
    if out.len() >= io::PATH_MAX {
        None
    } else {
        Some(out)
    }
}

pub(crate) fn do_switch_root(new_root: &[u8], init: &[u8], init_argv: &[&[u8]]) -> i32 {
    move_mount_if_present(b"/dev", new_root);
    move_mount_if_present(b"/proc", new_root);
    move_mount_if_present(b"/sys", new_root);
    // Match util-linux switch_root behavior for /run. Bento relies on this as
    // a transient handoff: initramfs /run/... becomes rootfs /run/... here, and
    // systemd reuses the existing tmpfs instead of replacing it.
    move_mount_if_present(b"/run", new_root);

    if io::chdir(new_root) != 0 {
        return -1;
    }
    if applets::system::mount_one(b".", b"/", None, libc::MS_MOVE, None) != 0 {
        return -1;
    }
    if io::chroot(b".") != 0 {
        return -1;
    }
    if io::chdir(b"/") != 0 {
        return -1;
    }

    exec_init(init, init_argv)
}

fn move_mount_if_present(path: &[u8], new_root: &[u8]) {
    if io::access(path, libc::F_OK) != 0 {
        return;
    }
    let Some(target) = join_path(new_root, path) else {
        return;
    };
    applets::files::mkdir_parents(&target, 0o755);
    applets::system::mount_one(path, &target, None, libc::MS_MOVE, None);
}

fn join_path(prefix: &[u8], suffix: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(prefix);
    if !out.ends_with(b"/") {
        out.push(b'/');
    }
    if suffix.starts_with(b"/") {
        out.extend_from_slice(&suffix[1..]);
    } else {
        out.extend_from_slice(suffix);
    }
    if out.len() >= io::PATH_MAX {
        None
    } else {
        Some(out)
    }
}

fn exec_init(init: &[u8], init_argv: &[&[u8]]) -> i32 {
    let mut storage = Vec::new();
    if init_argv.is_empty() {
        storage.push(c_string(init));
    } else {
        for arg in init_argv {
            storage.push(c_string(arg));
        }
    }
    let mut argv = Vec::new();
    for arg in &storage {
        argv.push(arg.as_ptr().cast::<libc::c_char>());
    }
    argv.push(core::ptr::null());
    io::execv(init, &argv)
}

fn c_string(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(input);
    out.push(0);
    out
}

fn rescue_shell() -> ! {
    io::write(io::STDERR, "init: starting rescue shell\n");
    loop {
        exec_shell_once();
        let sh = *b"sh\0";
        let interactive = *b"-i\0";
        let argv = [
            sh.as_ptr().cast::<u8>(),
            interactive.as_ptr().cast::<u8>(),
            core::ptr::null(),
        ];
        applets::run_applet(b"sh", 2, argv.as_ptr());
        io::sleep(1);
    }
}

pub(crate) fn exec_shell_once() {
    let sh = *b"sh\0";
    let interactive = *b"-i\0";
    let argv = [
        sh.as_ptr().cast::<libc::c_char>(),
        interactive.as_ptr().cast::<libc::c_char>(),
        core::ptr::null(),
    ];

    io::execv(b"/bin/sh", &argv);
    io::execv(b"/sbin/sh", &argv);
    io::execv(b"/init", &argv);
}
