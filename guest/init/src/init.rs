#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::applets::{self, install};
use crate::io;

const DEFAULT_ROOT: &[u8] = b"/dev/vda";
pub(crate) const DEFAULT_INIT: &[u8] = b"/sbin/init";
const MNT_ROOT: &[u8] = b"/mnt/root";
const AGENT_PAYLOAD_DIR: &[u8] = b"/agent";
const AGENT_SOURCE_BINARY: &[u8] = b"/agent/silo-agent";
const AGENT_SOURCE_CONFIG: &[u8] = b"/agent/config.json";
const AGENT_RUN_DIR: &[u8] = b"/run/agent";
const AGENT_RUN_BINARY: &[u8] = b"/run/agent/silo-agent";
const AGENT_RUN_CONFIG: &[u8] = b"/run/agent/config.json";
const AGENT_CONFIG_ARG: &[u8] = b"--config=/run/agent/config.json";
const AGENT_INIT_ARG: &[u8] = b"--init";
const AGENT_HANDOFF_ARG_PREFIX: &[u8] = b"--handoff=";

struct BootConfig {
    root: Vec<u8>,
    init: Vec<u8>,
    init_explicit: bool,
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

    if prepare_agent_boot()? {
        let handoff_arg = agent_handoff_arg(&config);
        let init_argv = [
            AGENT_RUN_BINARY,
            AGENT_CONFIG_ARG,
            AGENT_INIT_ARG,
            handoff_arg.as_slice(),
        ];
        if do_switch_root(MNT_ROOT, AGENT_RUN_BINARY, &init_argv) != 0 {
            return Err("switch_root failed");
        }
    } else {
        let init_path = target_init_path(&config.init).ok_or("target init path is too long")?;
        if io::access(&init_path, libc::X_OK) != 0 {
            return Err("target init is not executable");
        }

        let init_argv = [config.init.as_slice()];
        if do_switch_root(MNT_ROOT, &config.init, &init_argv) != 0 {
            return Err("switch_root failed");
        }
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

    let init = cmdline_value(&cmdline, b"init=");

    BootConfig {
        root: cmdline_value(&cmdline, b"root=")
            .unwrap_or(DEFAULT_ROOT)
            .to_vec(),
        init: init.unwrap_or(DEFAULT_INIT).to_vec(),
        init_explicit: init.is_some(),
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

fn prepare_agent_boot() -> Result<bool, &'static str> {
    if io::access(AGENT_PAYLOAD_DIR, libc::F_OK) != 0 {
        return Ok(false);
    }

    validate_payload_file(
        AGENT_SOURCE_BINARY,
        "agent payload has invalid /agent/silo-agent",
    )?;
    validate_payload_file(
        AGENT_SOURCE_CONFIG,
        "agent payload has invalid /agent/config.json",
    )?;

    if applets::files::mkdir_parents(AGENT_RUN_DIR, 0o755) != 0 {
        return Err("failed to create /run/agent");
    }

    if let Err(message) = copy_file(AGENT_SOURCE_BINARY, AGENT_RUN_BINARY, 0o755)
        .and_then(|()| copy_file(AGENT_SOURCE_CONFIG, AGENT_RUN_CONFIG, 0o600))
    {
        io::unlink(AGENT_RUN_BINARY);
        io::unlink(AGENT_RUN_CONFIG);
        return Err(message);
    }

    Ok(true)
}

fn validate_payload_file(path: &[u8], message: &'static str) -> Result<(), &'static str> {
    let mut stat = io::stat_zeroed();
    if io::lstat(path, &mut stat) != 0
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || io::access(path, libc::R_OK) != 0
    {
        return Err(message);
    }
    Ok(())
}

fn agent_handoff_arg(config: &BootConfig) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(AGENT_HANDOFF_ARG_PREFIX);
    if config.init_explicit {
        if !config.init.is_empty() && !config.init.starts_with(b"/") {
            out.push(b'/');
        }
        out.extend_from_slice(&config.init);
    } else {
        out.extend_from_slice(b"auto");
    }
    out
}

fn copy_file(source: &[u8], target: &[u8], mode: u32) -> Result<(), &'static str> {
    let input = io::open(source, libc::O_RDONLY | libc::O_NOFOLLOW, 0);
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
    // Match util-linux switch_root behavior for /run. Silo relies on this to
    // carry the copied /run/agent/silo-agent into the real root.
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
