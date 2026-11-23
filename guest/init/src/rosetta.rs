//! Init-owned Rosetta: mount the reserved share at its fixed trusted path,
//! admit the interpreter and register the fixed OCF binfmt_misc handler before
//! the first `switch_root`. The F flag opens the interpreter at registration;
//! the retained mount under `/run` also survives the root handoff for
//! visibility and shutdown inventory. No other component registers it.
use crate::owned::{directory, read_fd, read_file, Fd};
use crate::{applets, io};
use ::init::rosetta_checks::{self, FileFacts, MountFacts};
use rootfs_spec::rosetta::{
    self, BINFMT_MISC_PATH, BINFMT_REGISTER_PATH, BINFMT_STATUS_PATH, HANDLER_PATH,
    INTERPRETER_PATH, MOUNT_PATH, REGISTRATION, SHARE_TAG,
};
use rootfs_spec::RosettaMode;

/// Bound on the kernel's rendering of one binfmt_misc entry.
const MAX_ENTRY: usize = 4096;

pub(crate) fn prepare(mode: RosettaMode) -> Result<(), &'static str> {
    if !mode.enabled() {
        return Ok(());
    }
    directory(b"/run/silo", 0o700)?;
    directory(MOUNT_PATH.as_bytes(), 0o700)?;
    let parent_device = Fd::open(MOUNT_PATH.as_bytes(), libc::O_RDONLY | libc::O_DIRECTORY)?
        .stat()?
        .st_dev;
    if applets::system::mount_one(
        SHARE_TAG.as_bytes(),
        MOUNT_PATH.as_bytes(),
        Some(b"virtiofs"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    ) != 0
    {
        return Err("rosetta: share mount failed");
    }
    let share = Fd::open(MOUNT_PATH.as_bytes(), libc::O_RDONLY | libc::O_DIRECTORY)?;
    let share_device = share.stat()?.st_dev;
    let share_fs = share.statfs()?;
    // statfs fields are __fsword_t (signed) on glibc and unsigned long on musl;
    // magic and flag values are nonnegative bit patterns either way.
    rosetta_checks::check_share(
        MountFacts {
            filesystem_magic: share_fs.f_type as u64,
            flags: share_fs.f_flags as u64,
            device: share_device,
        },
        parent_device,
    )?;
    let interpreter = Fd::open(INTERPRETER_PATH.as_bytes(), libc::O_RDONLY)
        .map_err(|_| "rosetta: interpreter is missing or not a regular path")?;
    let interpreter_stat = interpreter.stat()?;
    rosetta_checks::check_interpreter(
        FileFacts {
            mode: interpreter_stat.st_mode,
            device: interpreter_stat.st_dev,
        },
        share_device,
    )?;
    if applets::system::mount_one(
        b"binfmt_misc",
        BINFMT_MISC_PATH.as_bytes(),
        Some(b"binfmt_misc"),
        0,
        None,
    ) != 0
    {
        return Err("rosetta: binfmt_misc mount failed");
    }
    let binfmt = Fd::open(
        BINFMT_MISC_PATH.as_bytes(),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    rosetta_checks::check_binfmt_mount(binfmt.statfs()?.f_type as u64)?;
    rosetta::check_global_status(&read_file(BINFMT_STATUS_PATH.as_bytes(), 64)?)
        .map_err(|_| "rosetta: global binfmt_misc is not enabled")?;
    register()?;
    io::write(
        io::STDERR,
        "init: rosetta: registered translation before root handoff\n",
    );
    Ok(())
}

/// Registers the fixed record with one complete write, or admits an identical
/// existing handler. A conflicting or disabled handler is never replaced.
fn register() -> Result<(), &'static str> {
    let existing = io::open(
        HANDLER_PATH.as_bytes(),
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    );
    if existing >= 0 {
        return check_handler(&read_fd(&Fd(existing), MAX_ENTRY)?);
    }
    if io::errno() != libc::ENOENT {
        return Err("rosetta: cannot inspect existing binfmt handler");
    }
    let register = Fd::open(BINFMT_REGISTER_PATH.as_bytes(), libc::O_WRONLY)?;
    // binfmt_misc parses exactly one record per write; never split it.
    let written = unsafe {
        libc::write(
            register.0,
            REGISTRATION.as_ptr().cast::<libc::c_void>(),
            REGISTRATION.len(),
        )
    };
    if usize::try_from(written).ok() != Some(REGISTRATION.len()) {
        return Err("rosetta: binfmt registration write failed");
    }
    check_handler(&read_file(HANDLER_PATH.as_bytes(), MAX_ENTRY)?)
}

fn check_handler(contents: &[u8]) -> Result<(), &'static str> {
    rosetta::check_handler(contents).map_err(|error| match error {
        rosetta::CheckError::HandlerDisabled => "rosetta: binfmt handler is disabled",
        _ => "rosetta: conflicting binfmt handler",
    })
}
