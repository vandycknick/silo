use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use agent_spec::UserConfig;
use eyre::{eyre, Context};

use crate::provision::{
    command_exists, format_error_chain, run_command, sanitize_unit_name, write_file,
    ProvisionContext, ProvisionOutcome, Provisioner, ProvisionerId,
};

mod database;

pub(crate) struct Users<'a> {
    users: &'a [UserConfig],
}

impl<'a> Provisioner<'a> for Users<'a> {
    type Config = [UserConfig];

    fn init(config: &'a Self::Config) -> Self {
        Self { users: config }
    }

    fn id(&self) -> ProvisionerId {
        ProvisionerId::USERS
    }

    fn apply(&self, context: &ProvisionContext) -> eyre::Result<ProvisionOutcome> {
        if self.users.is_empty() {
            return Ok(ProvisionOutcome::skipped("no users configured"));
        }

        let mut failures = Vec::new();

        for user in self.users {
            if let Err(err) = apply_user(context, user) {
                let error = format_error_chain(&err);
                tracing::error!(user = %user.name, error = %error, "failed to provision user; continuing");
                failures.push(format!("{}: {error}", user.name));
            }
        }

        if failures.is_empty() {
            Ok(ProvisionOutcome::succeeded(false))
        } else {
            Err(eyre!(
                "failed to provision {} user(s): {}",
                failures.len(),
                failures.join("; ")
            ))
        }
    }
}

fn apply_user(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    ensure_user(context, user)?;
    write_sudoers(context, user)?;
    Ok(())
}

fn ensure_user(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    match read_user_entry(context, &user.name)? {
        Some(entry) => reconcile_existing_user(context, user, &entry),
        None => match read_user_entry_by_uid(context, user.uid)? {
            Some(entry) => Err(eyre!(
                "uid {} is already owned by account {}; refusing to rename it to {}",
                entry.uid,
                entry.name,
                user.name
            )),
            None => create_user(context, user),
        },
    }
}

fn create_user(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    let account_started = Instant::now();
    let primary_gid = database::create(&context.guest_path("/etc"), user)?;
    let account_duration = account_started.elapsed();

    let home_started = Instant::now();
    initialize_home(context, user, primary_gid)?;

    tracing::info!(
        user = %user.name,
        uid = user.uid,
        account_duration_ms = account_duration.as_millis(),
        home_duration_ms = home_started.elapsed().as_millis(),
        "provisioned user"
    );
    Ok(())
}

fn initialize_home(
    context: &ProvisionContext,
    user: &UserConfig,
    primary_gid: u32,
) -> eyre::Result<()> {
    let (home, created) = ensure_home_directory(context, &user.home)?;
    set_owner(&home, user.uid, primary_gid)?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions on home directory {}", home.display()))?;

    if created {
        let skeleton = context.guest_path("/etc/skel");
        copy_skeleton(&skeleton, &home, user.uid, primary_gid)?;
    }
    Ok(())
}

fn ensure_home_directory(
    context: &ProvisionContext,
    configured: &str,
) -> eyre::Result<(PathBuf, bool)> {
    let root = context.guest_path("/");
    let relative = configured
        .strip_prefix('/')
        .ok_or_else(|| eyre!("home directory must be absolute: {configured}"))?;
    let components = Path::new(relative).components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(eyre!("home directory must not be the filesystem root"));
    }

    let mut current = root;
    let mut home_created = false;
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err(eyre!("home directory is not normalized: {configured}"));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(eyre!(
                    "home directory component {} must be a non-symlink directory",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!("create home directory component {}", current.display())
                })?;
                if index + 1 == components.len() {
                    home_created = true;
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect home directory component {}", current.display())
                });
            }
        }
    }
    Ok((current, home_created))
}

fn copy_skeleton(source: &Path, destination: &Path, uid: u32, gid: u32) -> eyre::Result<()> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(eyre!(
                "skeleton path {} must be a directory",
                source.display()
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", source.display())),
    }

    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", source.display()))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .with_context(|| format!("inspect {}", source_path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            fs::create_dir(&destination_path)
                .with_context(|| format!("create {}", destination_path.display()))?;
            copy_skeleton(&source_path, &destination_path, uid, gid)?;
            set_owner(&destination_path, uid, gid)?;
            fs::set_permissions(
                &destination_path,
                fs::Permissions::from_mode(metadata.permissions().mode() & 0o7777),
            )
            .with_context(|| format!("set permissions on {}", destination_path.display()))?;
        } else if file_type.is_file() {
            let mut source_file = File::open(&source_path)
                .with_context(|| format!("open {}", source_path.display()))?;
            let mut destination_file = File::options()
                .write(true)
                .create_new(true)
                .open(&destination_path)
                .with_context(|| format!("create {}", destination_path.display()))?;
            io::copy(&mut source_file, &mut destination_file).with_context(|| {
                format!(
                    "copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            set_owner(&destination_path, uid, gid)?;
            fs::set_permissions(
                &destination_path,
                fs::Permissions::from_mode(metadata.permissions().mode() & 0o7777),
            )
            .with_context(|| format!("set permissions on {}", destination_path.display()))?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&source_path)
                .with_context(|| format!("read link {}", source_path.display()))?;
            symlink(&target, &destination_path)
                .with_context(|| format!("create symlink {}", destination_path.display()))?;
            rustix::fs::chownat(
                rustix::fs::CWD,
                &destination_path,
                Some(rustix::process::Uid::from_raw(uid)),
                Some(rustix::process::Gid::from_raw(gid)),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|error| eyre!("set owner on {}: {error}", destination_path.display()))?;
        } else {
            return Err(eyre!(
                "unsupported skeleton entry type at {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn set_owner(path: &Path, uid: u32, gid: u32) -> eyre::Result<()> {
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .map_err(|error| eyre!("set owner on {}: {error}", path.display()))
}

fn reconcile_existing_user(
    context: &ProvisionContext,
    user: &UserConfig,
    entry: &UserEntry,
) -> eyre::Result<()> {
    if entry.uid != user.uid {
        return Err(eyre!(
            "existing user {} has uid {}, expected {}; refusing to change uid",
            user.name,
            entry.uid,
            user.uid
        ));
    }
    validate_primary_gid(user, entry)?;

    let mut args = Vec::new();
    if entry.gecos != user.gecos {
        args.push(OsString::from("--comment"));
        args.push(OsString::from(&user.gecos));
    }
    if entry.home != user.home {
        args.push(OsString::from("--home"));
        args.push(OsString::from(&user.home));
    }
    if entry.shell != user.shell {
        args.push(OsString::from("--shell"));
        args.push(OsString::from(&user.shell));
    }

    if !args.is_empty() {
        args.push(OsString::from(&user.name));
        run_command(context.process_supervisor(), "usermod", args)?;
    }

    reconcile_home(context, user, user.gid)?;
    reconcile_password_lock(context, user)?;

    tracing::info!(user = %user.name, uid = user.uid, "reconciled user");
    Ok(())
}

fn validate_primary_gid(user: &UserConfig, entry: &UserEntry) -> eyre::Result<()> {
    if entry.gid != user.gid {
        return Err(eyre!(
            "existing user {} has primary gid {}, expected {}; refusing to change gid",
            entry.name,
            entry.gid,
            user.gid
        ));
    }
    Ok(())
}

fn reconcile_home(
    context: &ProvisionContext,
    user: &UserConfig,
    primary_gid: u32,
) -> eyre::Result<()> {
    fs::create_dir_all(&user.home)
        .with_context(|| format!("create home directory {}", user.home))?;
    if command_exists("chown") {
        let owner = home_owner(user.uid, primary_gid);
        run_command(
            context.process_supervisor(),
            "chown",
            [owner.as_str(), user.home.as_str()],
        )?;
    }
    Ok(())
}

fn home_owner(uid: u32, primary_gid: u32) -> String {
    format!("{uid}:{primary_gid}")
}

fn reconcile_password_lock(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    if !command_exists("passwd") {
        return Ok(());
    }

    if user.lock_passwd {
        run_command(
            context.process_supervisor(),
            "passwd",
            ["--lock", user.name.as_str()],
        )
    } else {
        run_command(
            context.process_supervisor(),
            "passwd",
            ["--unlock", user.name.as_str()],
        )
    }
}

fn write_sudoers(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    let path = context.guest_path(&format!(
        "/etc/sudoers.d/silo-{}",
        sanitize_unit_name(&user.name)
    ));
    if user.sudo.trim().is_empty() {
        remove_file_if_exists(&path)?;
        return Ok(());
    }

    write_file(&path, format!("{} {}\n", user.name, user.sudo), 0o440)
}

fn remove_file_if_exists(path: &std::path::Path) -> eyre::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UserEntry {
    name: String,
    uid: u32,
    gid: u32,
    gecos: String,
    home: String,
    shell: String,
}

fn read_user_entry(context: &ProvisionContext, name: &str) -> eyre::Result<Option<UserEntry>> {
    let passwd_path = context.guest_path("/etc/passwd");
    let contents = match fs::read_to_string(&passwd_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", passwd_path.display())),
    };

    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(entry_name) = fields.next() else {
            continue;
        };
        if entry_name != name {
            continue;
        }

        let _password = fields.next();
        let uid = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing uid"))?
            .parse::<u32>()
            .with_context(|| format!("parse uid for user {name}"))?;
        let gid = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing gid"))?
            .parse::<u32>()
            .with_context(|| format!("parse gid for user {name}"))?;
        let gecos = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing gecos"))?
            .to_string();
        let home = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing home"))?
            .to_string();
        let shell = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing shell"))?
            .to_string();

        return Ok(Some(UserEntry {
            name: entry_name.to_string(),
            uid,
            gid,
            gecos,
            home,
            shell,
        }));
    }

    Ok(None)
}

fn read_user_entry_by_uid(
    context: &ProvisionContext,
    expected_uid: u32,
) -> eyre::Result<Option<UserEntry>> {
    let passwd_path = context.guest_path("/etc/passwd");
    let contents = match fs::read_to_string(&passwd_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", passwd_path.display())),
    };

    for line in contents.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 7 {
            continue;
        }
        let Ok(uid) = fields[2].parse::<u32>() else {
            continue;
        };
        if uid != expected_uid {
            continue;
        }

        let gid = fields[3]
            .parse::<u32>()
            .with_context(|| format!("parse gid for user {}", fields[0]))?;
        return Ok(Some(UserEntry {
            name: fields[0].to_string(),
            uid,
            gid,
            gecos: fields[4].to_string(),
            home: fields[5].to_string(),
            shell: fields[6].to_string(),
        }));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use agent_spec::UserConfig;

    use crate::provision::ProvisionContext;

    #[test]
    fn reads_user_entry_from_passwd() {
        let root = temp_root("user-entry");
        let etc = root.join("etc");
        fs::create_dir_all(&etc).expect("create etc");
        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\nsilo:x:1000:1000:Silo User:/home/silo:/bin/zsh\n",
        )
        .expect("write passwd");

        let context = ProvisionContext::for_test(&root);
        let entry = crate::provision::user::read_user_entry(&context, "silo")
            .expect("read user")
            .expect("entry exists");

        assert_eq!(entry.name, "silo");
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1000);
        assert_eq!(entry.gecos, "Silo User");
        assert_eq!(entry.home, "/home/silo");
        assert_eq!(entry.shell, "/bin/zsh");

        fs::remove_dir_all(root).expect("clean temp root");
    }

    #[test]
    fn finds_user_entry_by_uid_when_name_differs() {
        let root = temp_root("user-entry-by-uid");
        let etc = root.join("etc");
        fs::create_dir_all(&etc).expect("create etc");
        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
        )
        .expect("write passwd");

        let entry = crate::provision::user::read_user_entry_by_uid(
            &ProvisionContext::for_test(&root),
            1000,
        )
        .expect("read user")
        .expect("entry exists");

        assert_eq!(entry.name, "ubuntu");
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1000);
        assert_eq!(entry.home, "/home/ubuntu");

        fs::remove_dir_all(root).expect("clean temp root");
    }

    #[test]
    fn home_owner_uses_numeric_uid_and_primary_gid() {
        assert_eq!(crate::provision::user::home_owner(1000, 1001), "1000:1001");
    }

    #[test]
    fn initializes_new_home_from_skeleton_without_following_symlinks() {
        let root = temp_root("initialize-home");
        let skeleton = root.join("etc/skel");
        fs::create_dir_all(skeleton.join("config")).expect("create skeleton");
        fs::write(skeleton.join(".profile"), "profile\n").expect("write profile");
        fs::write(skeleton.join("config/settings"), "settings\n").expect("write settings");
        fs::set_permissions(
            skeleton.join("config/settings"),
            fs::Permissions::from_mode(0o640),
        )
        .expect("set settings mode");
        symlink(".profile", skeleton.join("profile-link")).expect("create skeleton symlink");

        let mut user = nickvd_config();
        user.uid = nix::unistd::Uid::current().as_raw();
        user.home = "/home/nickvd".to_string();
        let gid = nix::unistd::Gid::current().as_raw();
        let context = ProvisionContext::for_test(&root);

        crate::provision::user::initialize_home(&context, &user, gid).expect("initialize home");

        let home = root.join("home/nickvd");
        assert_eq!(
            fs::read_to_string(home.join(".profile")).expect("read profile"),
            "profile\n"
        );
        assert_eq!(
            fs::read_to_string(home.join("config/settings")).expect("read settings"),
            "settings\n"
        );
        assert_eq!(
            fs::symlink_metadata(home.join("config/settings"))
                .expect("stat settings")
                .mode()
                & 0o7777,
            0o640
        );
        assert_eq!(
            fs::read_link(home.join("profile-link")).expect("read copied link"),
            Path::new(".profile")
        );
        assert_eq!(
            fs::symlink_metadata(&home).expect("stat home").mode() & 0o7777,
            0o700
        );

        fs::remove_dir_all(root).expect("clean temp root");
    }

    #[test]
    fn rejects_symlinked_home_component() {
        let root = temp_root("symlink-home");
        let outside = temp_root("symlink-home-outside");
        fs::create_dir_all(&root).expect("create root");
        fs::create_dir_all(&outside).expect("create outside");
        symlink(&outside, root.join("home")).expect("create home symlink");

        let error = crate::provision::user::ensure_home_directory(
            &ProvisionContext::for_test(&root),
            "/home/silo",
        )
        .expect_err("symlinked home component must fail");

        assert!(error.to_string().contains("non-symlink directory"));
        assert!(!outside.join("silo").exists());

        fs::remove_dir_all(root).expect("clean temp root");
        fs::remove_dir_all(outside).expect("clean outside temp root");
    }

    #[test]
    fn rejects_uid_owned_by_another_account_without_mutation() {
        let root = temp_root("uid-conflict");
        fs::create_dir_all(root.join("etc")).unwrap();
        let passwd = "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n";
        fs::write(root.join("etc/passwd"), passwd).unwrap();
        let error = crate::provision::user::ensure_user(
            &ProvisionContext::for_test(&root),
            &nickvd_config(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusing to rename"));
        assert_eq!(fs::read_to_string(root.join("etc/passwd")).unwrap(), passwd);
        assert!(!root.join("home/nickvd").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_existing_account_with_different_primary_gid() {
        let mut user = nickvd_config();
        user.gid = 2000;

        let error = crate::provision::user::validate_primary_gid(&user, &ubuntu_entry())
            .expect_err("primary gid mismatch must fail");

        assert!(error.to_string().contains("expected 2000"));
    }

    fn ubuntu_entry() -> crate::provision::user::UserEntry {
        crate::provision::user::UserEntry {
            name: "ubuntu".to_string(),
            uid: 1000,
            gid: 1000,
            gecos: "Ubuntu".to_string(),
            home: "/home/ubuntu".to_string(),
            shell: "/bin/bash".to_string(),
        }
    }

    fn nickvd_config() -> UserConfig {
        UserConfig {
            name: "nickvd".to_string(),
            uid: 1000,
            gid: 1000,
            gecos: "Nick Van Driessche".to_string(),
            home: "/home/nickvd".to_string(),
            shell: "/bin/bash".to_string(),
            sudo: "ALL=(ALL) NOPASSWD:ALL".to_string(),
            lock_passwd: true,
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("silo-agent-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }
}
