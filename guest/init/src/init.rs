#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::applets::{self, install};
use crate::io;

#[path = "freezer.rs"]
mod freezer;

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
    init: Vec<u8>,
    init_explicit: bool,
}

/// What a failure before image execution may expose on the console.
#[derive(Clone, Copy)]
enum Failure {
    /// The trusted root contract governs this boot: no workload, no shell.
    FailClosed(&'static str),
    /// A verified raw root and effective Rosetta are in place; only payload
    /// or handoff preparation failed. The initramfs shell may diagnose it.
    Rescue,
}

pub(crate) fn init(_argc: i32, _argv: *const *const u8) -> i32 {
    // Every boot is governed by the mandatory bootstrap until it is verified.
    let mut failure = Failure::FailClosed("root");
    if let Err(message) = run_init(&mut failure) {
        io::write(io::STDERR, "init: ");
        io::write(io::STDERR, message);
        io::write(io::STDERR, "\n");
        match failure {
            Failure::FailClosed(label) => {
                io::write(io::STDERR, "init: ");
                io::write(io::STDERR, label);
                io::write(io::STDERR, ": boot failed; workload prohibited\n");
                // PID 1 must not return (kernel panic) or expose a rescue shell.
                loop {
                    io::sleep(3600);
                }
            }
            Failure::Rescue => rescue_shell(),
        }
    }
    0
}

fn run_init(failure: &mut Failure) -> Result<(), &'static str> {
    if io::getpid() != 1 {
        return Err("refusing to run init outside PID 1");
    }

    prepare_directories()?;
    mount_essential_filesystems()?;
    if let Err(message) = freezer::prepare() {
        // Cold boot remains usable on kernels without the live profile. The
        // retained agent controller reports this as unsupported, never frozen.
        io::write(io::STDERR, "init: live workload containment unavailable: ");
        io::write(io::STDERR, message);
        io::write(io::STDERR, "\n");
    }
    install(b"/bin");
    install(b"/sbin");

    let cmdline = read_cmdline();
    let args = ::init::boot_args::parse(&cmdline)?;
    if args.marker.is_some() {
        *failure = Failure::FailClosed("overlay");
    }
    let bootstrap = crate::bootstrap::load()?;
    match bootstrap.root {
        rootfs_spec::Root::FlatOverlay(root) => {
            *failure = Failure::FailClosed("overlay");
            if args.marker != Some(::init::boot_args::RootMarker::FlatOverlay) {
                return Err("overlay: missing managed kernel marker");
            }
            crate::overlay::assemble(root)?;
        }
        rootfs_spec::Root::Raw(root) => {
            if args.marker.is_some() {
                return Err("raw: managed overlay marker on a raw root");
            }
            crate::raw::mount(&root)?;
        }
    }
    // Before either switch_root branch, with or without an injected agent.
    crate::rosetta::prepare(bootstrap.rosetta)?;
    if matches!(bootstrap.root, rootfs_spec::Root::Raw(_)) {
        *failure = Failure::Rescue;
    }
    let config = BootConfig {
        init: args.init.unwrap_or(DEFAULT_INIT).to_vec(),
        init_explicit: args.init.is_some(),
    };

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

        if let Err(message) = freezer::place_image_init() {
            io::write(
                io::STDERR,
                "init: image init cgroup placement unavailable: ",
            );
            io::write(io::STDERR, message);
            io::write(io::STDERR, "\n");
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

fn read_cmdline() -> Vec<u8> {
    let fd = io::open(b"/proc/cmdline", libc::O_RDONLY, 0);
    if fd < 0 {
        return Vec::new();
    }
    let bytes = io::read_all(fd);
    io::close(fd);
    bytes
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
    // Validate every destination before the first move. mount(MS_MOVE)
    // follows a destination symlink, which could otherwise strand /run.
    let root = io::open(
        new_root,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    );
    if root < 0 {
        return -1;
    }
    let prepared = ::init::handoff::prepare_mount_destinations(root);
    let closed = io::close(root);
    if prepared.is_err() || closed != 0 {
        return -1;
    }
    for path in [b"/dev".as_slice(), b"/proc", b"/sys", b"/run"] {
        // /run carries the agent and the managed root maintenance subtree.
        // Continuing after any required move would hide mounts from PID 1.
        if move_mount(path, new_root) != 0 {
            return -1;
        }
    }

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

fn move_mount(path: &[u8], new_root: &[u8]) -> i32 {
    let Some(target) = join_path(new_root, path) else {
        return -1;
    };
    applets::system::mount_one(path, &target, None, libc::MS_MOVE, None)
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
