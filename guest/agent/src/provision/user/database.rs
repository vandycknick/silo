use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eyre::{eyre, Context};
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::process::{Gid, Uid};

const DATABASES: [&str; 4] = ["passwd", "shadow", "group", "gshadow"];
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const LOCK_TIMEOUT: Duration = Duration::from_secs(15);

/// Adds the account's four local database records atomically enough for the
/// shadow-utils file protocol.
pub(super) fn create(etc: &Path, user: &agent_spec::UserConfig) -> eyre::Result<u32> {
    validate_user(user)?;
    let etc = open_etc(etc)?;
    let _lock = acquire_lock(&etc)?;

    let days = utc_days()?;
    let records = Records::new(user, days);
    let mut databases = DATABASES
        .into_iter()
        .map(|name| Database::read(&etc, name))
        .collect::<eyre::Result<Vec<_>>>()?;

    let mut changed = false;
    for database in &mut databases {
        changed |= database.reconcile(&records)?;
    }
    if !changed {
        return Ok(user.gid);
    }

    let mut temporary = databases
        .iter()
        .map(|database| Temporary::write(&etc, database))
        .collect::<eyre::Result<Vec<_>>>()?;

    // syncfs persists all staged files together before any name is replaced.
    fs::syncfs(&etc).map_err(|error| eyre!("sync filesystem for account databases: {error}"))?;

    for database in &databases {
        replace_backup(&etc, database.name)?;
    }
    for name in ["group", "gshadow", "shadow", "passwd"] {
        let temporary = temporary
            .iter_mut()
            .find(|temporary| temporary.database == name)
            .ok_or_else(|| eyre!("missing staged {name} database"))?;
        temporary.replace(&etc)?;
    }
    fs::fsync(&etc).map_err(|error| eyre!("sync account database directory: {error}"))?;

    Ok(user.gid)
}

fn validate_user(user: &agent_spec::UserConfig) -> eyre::Result<()> {
    for (field, value) in [
        ("name", user.name.as_str()),
        ("gecos", user.gecos.as_str()),
        ("home", user.home.as_str()),
        ("shell", user.shell.as_str()),
    ] {
        if value.contains([':', '\n', '\r']) {
            return Err(eyre!("user {field} may not contain a colon or newline"));
        }
    }
    if user.name.is_empty() {
        return Err(eyre!("user name may not be empty"));
    }
    Ok(())
}

fn open_etc(etc: &Path) -> eyre::Result<File> {
    fs::open(
        etc,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| eyre!("open {}: {error}", etc.display()))
}

fn acquire_lock(etc: &File) -> eyre::Result<File> {
    let lock = fs::openat(
        etc,
        ".pwd.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(|error| eyre!("open /etc/.pwd.lock: {error}"))?;
    require_regular(&lock, ".pwd.lock")?;

    let started = Instant::now();
    loop {
        match fs::fcntl_lock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(lock),
            Err(error)
                if (error == rustix::io::Errno::ACCESS || error == rustix::io::Errno::AGAIN)
                    && started.elapsed() < LOCK_TIMEOUT =>
            {
                thread::sleep(LOCK_RETRY_INTERVAL);
            }
            Err(error)
                if error == rustix::io::Errno::ACCESS || error == rustix::io::Errno::AGAIN =>
            {
                return Err(eyre!("timed out acquiring /etc/.pwd.lock"));
            }
            Err(error) => return Err(eyre!("lock /etc/.pwd.lock: {error}")),
        }
    }
}

fn utc_days() -> eyre::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 86_400)
        .map_err(|error| eyre!("system clock is before the Unix epoch: {error}"))
}

struct Records {
    passwd: Vec<u8>,
    shadow: Vec<u8>,
    group: Vec<u8>,
    gshadow: Vec<u8>,
}

impl Records {
    fn new(user: &agent_spec::UserConfig, days: u64) -> Self {
        let uid = user.uid;
        let gid = user.gid;
        Self {
            passwd: format!(
                "{}:x:{uid}:{gid}:{}:{}:{}",
                user.name, user.gecos, user.home, user.shell
            )
            .into_bytes(),
            shadow: format!("{}:!:{days}:0:99999:7:::", user.name).into_bytes(),
            group: format!("{}:x:{gid}:", user.name).into_bytes(),
            gshadow: format!("{}:!::", user.name).into_bytes(),
        }
    }

    fn for_database(&self, name: &str) -> Option<&[u8]> {
        match name {
            "passwd" => Some(&self.passwd),
            "shadow" => Some(&self.shadow),
            "group" => Some(&self.group),
            "gshadow" => Some(&self.gshadow),
            _ => None,
        }
    }
}

struct Database {
    name: &'static str,
    contents: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl Database {
    fn read(etc: &File, name: &'static str) -> eyre::Result<Self> {
        let mut file = fs::openat(
            etc,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| eyre!("open /etc/{name}: {error}"))?;
        let stat = require_regular(&file, name)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .with_context(|| format!("read /etc/{name}"))?;
        Ok(Self {
            name,
            contents,
            mode: stat.st_mode & 0o7777,
            uid: stat.st_uid,
            gid: stat.st_gid,
        })
    }

    fn reconcile(&mut self, records: &Records) -> eyre::Result<bool> {
        let expected = records
            .for_database(self.name)
            .ok_or_else(|| eyre!("unknown account database {}", self.name))?;
        let exists = match self.name {
            "passwd" => validate_passwd(&self.contents, expected)?,
            "shadow" => validate_shadow(&self.contents, expected)?,
            "gshadow" => validate_named(&self.contents, expected, self.name)?,
            "group" => validate_group(&self.contents, expected)?,
            _ => return Err(eyre!("unknown account database {}", self.name)),
        };
        if exists {
            return Ok(false);
        }
        append_record(&mut self.contents, expected);
        Ok(true)
    }
}

fn require_regular(file: &File, name: &str) -> eyre::Result<rustix::fs::Stat> {
    let stat = fs::fstat(file).map_err(|error| eyre!("stat /etc/{name}: {error}"))?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(eyre!("/etc/{name} must be a regular non-symlink file"));
    }
    Ok(stat)
}

fn validate_passwd(contents: &[u8], expected: &[u8]) -> eyre::Result<bool> {
    let expected_fields = fields(expected);
    let name = *expected_fields
        .first()
        .ok_or_else(|| eyre!("expected passwd record has no name"))?;
    let uid = parse_id(
        expected_fields
            .get(2)
            .ok_or_else(|| eyre!("expected passwd record has no uid"))?,
        "expected passwd uid",
    )?;
    let mut exists = false;

    for line in lines(contents) {
        let values = fields(line);
        let named = values.first().is_some_and(|value| *value == name);
        let matching_uid = values
            .get(2)
            .and_then(|value| parse_id(value, "passwd uid").ok())
            .is_some_and(|value| value == uid);
        if !named && !matching_uid {
            continue;
        }
        if values.len() != 7 {
            return Err(eyre!("malformed relevant passwd record"));
        }
        let record_uid = parse_id(
            values
                .get(2)
                .ok_or_else(|| eyre!("malformed relevant passwd record"))?,
            "passwd uid",
        )?;
        let record_gid = parse_id(
            values
                .get(3)
                .ok_or_else(|| eyre!("malformed relevant passwd record"))?,
            "passwd gid",
        )?;
        if line != expected || record_uid != uid || record_gid != uid {
            return Err(eyre!("conflicting username or uid in passwd"));
        }
        if exists {
            return Err(eyre!("duplicate username or uid in passwd"));
        }
        exists = true;
    }
    Ok(exists)
}

fn validate_group(contents: &[u8], expected: &[u8]) -> eyre::Result<bool> {
    let expected_fields = fields(expected);
    let name = *expected_fields
        .first()
        .ok_or_else(|| eyre!("expected group record has no name"))?;
    let gid = parse_id(
        expected_fields
            .get(2)
            .ok_or_else(|| eyre!("expected group record has no gid"))?,
        "expected group gid",
    )?;
    let mut exists = false;

    for line in lines(contents) {
        let values = fields(line);
        let named = values.first().is_some_and(|value| *value == name);
        let matching_gid = values
            .get(2)
            .and_then(|value| parse_id(value, "group gid").ok())
            .is_some_and(|value| value == gid);
        if !named && !matching_gid {
            continue;
        }
        if values.len() != 4 {
            return Err(eyre!("malformed relevant group record"));
        }
        let record_gid = parse_id(
            values
                .get(2)
                .ok_or_else(|| eyre!("malformed relevant group record"))?,
            "group gid",
        )?;
        if line != expected || record_gid != gid {
            return Err(eyre!("conflicting group or gid in group"));
        }
        if exists {
            return Err(eyre!("duplicate group or gid in group"));
        }
        exists = true;
    }
    Ok(exists)
}

fn validate_named(contents: &[u8], expected: &[u8], database: &str) -> eyre::Result<bool> {
    let expected_fields = fields(expected);
    let name = *expected_fields
        .first()
        .ok_or_else(|| eyre!("expected {database} record has no name"))?;
    let mut exists = false;
    for line in lines(contents) {
        let values = fields(line);
        if values.first().is_none_or(|value| *value != name) {
            continue;
        }
        if line != expected {
            return Err(eyre!("malformed or conflicting relevant {database} record"));
        }
        if exists {
            return Err(eyre!("duplicate relevant {database} record"));
        }
        exists = true;
    }
    Ok(exists)
}

fn validate_shadow(contents: &[u8], expected: &[u8]) -> eyre::Result<bool> {
    let expected_fields = fields(expected);
    let name = *expected_fields
        .first()
        .ok_or_else(|| eyre!("expected shadow record has no name"))?;
    let mut exists = false;
    for line in lines(contents) {
        let values = fields(line);
        if values.first().is_none_or(|value| *value != name) {
            continue;
        }
        let valid = values.len() == 9
            && values.get(1).is_some_and(|value| *value == b"!")
            && values
                .get(2)
                .is_some_and(|value| parse_shadow_days(value).is_ok())
            && values.get(3).is_some_and(|value| *value == b"0")
            && values.get(4).is_some_and(|value| *value == b"99999")
            && values.get(5).is_some_and(|value| *value == b"7")
            && values.get(6).is_some_and(|value| value.is_empty())
            && values.get(7).is_some_and(|value| value.is_empty())
            && values.get(8).is_some_and(|value| value.is_empty());
        if !valid {
            return Err(eyre!("malformed or conflicting relevant shadow record"));
        }
        if exists {
            return Err(eyre!("duplicate relevant shadow record"));
        }
        exists = true;
    }
    Ok(exists)
}

fn fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|byte| *byte == b':').collect()
}

fn lines(contents: &[u8]) -> impl Iterator<Item = &[u8]> {
    contents
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
}

fn parse_id(value: &[u8], field: &str) -> eyre::Result<u32> {
    std::str::from_utf8(value)
        .with_context(|| format!("decode {field}"))?
        .parse()
        .with_context(|| format!("parse {field}"))
}

fn parse_shadow_days(value: &[u8]) -> eyre::Result<u64> {
    std::str::from_utf8(value)
        .context("decode shadow last-change day")?
        .parse()
        .context("parse shadow last-change day")
}

fn append_record(contents: &mut Vec<u8>, record: &[u8]) {
    if !contents.is_empty() && !contents.ends_with(b"\n") {
        contents.push(b'\n');
    }
    contents.extend_from_slice(record);
    contents.push(b'\n');
}

struct Temporary {
    database: &'static str,
    name: String,
    file: Option<File>,
    directory: File,
    replaced: bool,
}

impl Temporary {
    fn write(etc: &File, database: &Database) -> eyre::Result<Self> {
        let name = format!(".silo-user-{}-{}", database.name, uuid::Uuid::new_v4());
        let directory = etc
            .try_clone()
            .with_context(|| format!("duplicate /etc descriptor for {name}"))?;
        let mut file = fs::openat(
            etc,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|error| eyre!("create /etc/{name}: {error}"))?;
        let result = fs::fchown(
            &file,
            Some(Uid::from_raw(database.uid)),
            Some(Gid::from_raw(database.gid)),
        )
        .map_err(|error| eyre!("preserve owner for /etc/{name}: {error}"))
        .and_then(|()| {
            file.set_permissions(std::fs::Permissions::from_mode(database.mode))
                .with_context(|| format!("preserve mode for /etc/{name}"))
        })
        .and_then(|()| {
            file.write_all(&database.contents)
                .with_context(|| format!("write /etc/{name}"))
        });
        if let Err(error) = result {
            drop(file);
            let _ = fs::unlinkat(etc, &name, AtFlags::empty());
            return Err(error);
        }

        Ok(Self {
            database: database.name,
            name,
            file: Some(file),
            directory,
            replaced: false,
        })
    }

    fn replace(&mut self, etc: &File) -> eyre::Result<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| eyre!("staged {} database file is unavailable", self.database))?;
        drop(file);
        fs::renameat(etc, &self.name, etc, self.database)
            .map_err(|error| eyre!("replace /etc/{}: {error}", self.database))?;
        self.replaced = true;
        Ok(())
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.replaced {
            drop(self.file.take());
            let _ = fs::unlinkat(&self.directory, &self.name, AtFlags::empty());
        }
    }
}

fn replace_backup(etc: &File, name: &str) -> eyre::Result<()> {
    let backup = format!("{name}-");
    let temporary = format!(".silo-user-{name}-backup-{}", uuid::Uuid::new_v4());
    match fs::statat(etc, &backup, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_file() => {}
        Ok(_) => return Err(eyre!("/etc/{backup} must be a regular non-symlink file")),
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(eyre!("stat /etc/{backup}: {error}")),
    }
    fs::linkat(etc, name, etc, &temporary, AtFlags::empty())
        .map_err(|error| eyre!("stage backup for /etc/{name}: {error}"))?;
    let result = fs::renameat(etc, &temporary, etc, &backup)
        .map_err(|error| eyre!("back up /etc/{name} to /etc/{backup}: {error}"));
    if result.is_err() {
        let _ = fs::unlinkat(etc, &temporary, AtFlags::empty());
    }
    result
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::Path;

    use agent_spec::UserConfig;
    use tempfile::TempDir;

    use crate::provision::user::database::{create, utc_days};

    #[test]
    fn creates_complete_account_database_records_and_preserves_metadata() {
        let fixture = Fixture::new();
        for (name, mode) in [
            ("passwd", 0o640),
            ("shadow", 0o600),
            ("group", 0o644),
            ("gshadow", 0o640),
        ] {
            fixture.set_mode(name, mode);
        }
        let before =
            ["passwd", "shadow", "group", "gshadow"].map(|name| (name, fixture.metadata(name)));

        assert_eq!(
            create(fixture.etc(), &fixture.user()).expect("create user"),
            2000
        );

        assert_eq!(
            fixture.read("passwd"),
            "root:x:0:0:root:/root:/bin/sh\nsilo:x:2000:2000:Silo User:/home/silo:/bin/bash\n"
        );
        assert_eq!(fixture.read("group"), "root:x:0:\nsilo:x:2000:\n");
        assert_eq!(fixture.read("gshadow"), "root:!::\nsilo:!::\n");
        assert_eq!(
            fixture.read("shadow"),
            format!(
                "root:*:1:0:99999:7:::\nsilo:!:{}:0:99999:7:::\n",
                utc_days().expect("days")
            )
        );
        for (name, before) in before {
            let after = fixture.metadata(name);
            assert_eq!(after.mode() & 0o7777, before.mode() & 0o7777);
            assert_eq!(after.uid(), before.uid());
            assert_eq!(after.gid(), before.gid());
        }
    }

    #[test]
    fn creates_a_private_group_with_an_explicit_gid() {
        let fixture = Fixture::new();
        let mut user = fixture.user();
        user.gid = 3000;

        assert_eq!(create(fixture.etc(), &user).expect("create user"), 3000);
        assert!(fixture
            .read("passwd")
            .contains("silo:x:2000:3000:Silo User:/home/silo:/bin/bash"));
        assert!(fixture.read("group").contains("silo:x:3000:"));
    }

    #[test]
    fn rolls_forward_exact_partial_records_without_reordering_existing_bytes() {
        let fixture = Fixture::new();
        let user = fixture.user();
        fs::write(
            fixture.etc().join("passwd"),
            "root:x:0:0:root:/root:/bin/sh\nsilo:x:2000:2000:Silo User:/home/silo:/bin/bash\n",
        )
        .expect("write passwd");
        fs::write(fixture.etc().join("group"), "root:x:0:\nsilo:x:2000:\n").expect("write group");
        fs::write(
            fixture.etc().join("shadow"),
            "root:*:1:0:99999:7:::\nsilo:!:1:0:99999:7:::\n",
        )
        .expect("write shadow");

        create(fixture.etc(), &user).expect("roll forward account");

        assert_eq!(
            fixture.read("passwd"),
            "root:x:0:0:root:/root:/bin/sh\nsilo:x:2000:2000:Silo User:/home/silo:/bin/bash\n"
        );
        assert_eq!(fixture.read("group"), "root:x:0:\nsilo:x:2000:\n");
        assert_eq!(
            fixture.read("shadow"),
            "root:*:1:0:99999:7:::\nsilo:!:1:0:99999:7:::\n"
        );
        assert_eq!(fixture.read("gshadow"), "root:!::\nsilo:!::\n");
    }

    #[test]
    fn rejects_conflicting_username_uid_group_and_gid() {
        for (database, contents) in [
            (
                "passwd",
                "root:x:0:0:root:/root:/bin/sh\nother:x:2000:2000:Other:/home/other:/bin/sh\n",
            ),
            ("group", "root:x:0:\nother:x:2000:\n"),
            ("shadow", "root:*:1:0:99999:7:::\nsilo:*:1:0:99999:7:::\n"),
            ("gshadow", "root:!::\nsilo:other::\n"),
        ] {
            let fixture = Fixture::new();
            fs::write(fixture.etc().join(database), contents).expect("write conflict");
            let error = create(fixture.etc(), &fixture.user()).expect_err("conflict must fail");
            assert!(
                error.to_string().contains("conflicting")
                    || error.to_string().contains("malformed")
            );
        }
    }

    #[test]
    fn rejects_malformed_relevant_records() {
        for (database, contents) in [
            ("passwd", "root:x:0:0:root:/root:/bin/sh\nsilo:x:2000\n"),
            ("shadow", "root:*:1:0:99999:7:::\nsilo:!\n"),
            ("group", "root:x:0:\nsilo:x\n"),
            ("gshadow", "root:!::\nsilo:!\n"),
        ] {
            let fixture = Fixture::new();
            fs::write(fixture.etc().join(database), contents).expect("write malformed record");
            let error =
                create(fixture.etc(), &fixture.user()).expect_err("malformed record must fail");
            assert!(error.to_string().contains("malformed"));
        }
    }

    #[test]
    fn rejects_duplicate_exact_records() {
        for (database, record) in [
            (
                "passwd",
                "silo:x:2000:2000:Silo User:/home/silo:/bin/bash\n",
            ),
            ("shadow", "silo:!:1:0:99999:7:::\n"),
            ("group", "silo:x:2000:\n"),
            ("gshadow", "silo:!::\n"),
        ] {
            let fixture = Fixture::new();
            let mut contents = fixture.read(database);
            contents.push_str(record);
            contents.push_str(record);
            fs::write(fixture.etc().join(database), contents).expect("write duplicate records");

            let error = create(fixture.etc(), &fixture.user()).expect_err("duplicates must fail");

            assert!(error.to_string().contains("duplicate"));
        }
    }

    #[test]
    fn rejects_symlinked_database_files() {
        let fixture = Fixture::new();
        let group = fixture.etc().join("group");
        fs::remove_file(&group).expect("remove group");
        symlink(fixture.etc().join("passwd"), group).expect("symlink group");

        let error = create(fixture.etc(), &fixture.user()).expect_err("symlink must fail");

        assert!(error.to_string().contains("group"));
    }

    #[test]
    fn is_idempotent_after_a_complete_transaction() {
        let fixture = Fixture::new();
        let user = fixture.user();
        create(fixture.etc(), &user).expect("create user");
        let before = ["passwd", "shadow", "group", "gshadow"]
            .map(|name| (fixture.read(name), fixture.metadata(name).ino()));

        create(fixture.etc(), &user).expect("repeat create user");

        for ((contents, inode), name) in before
            .into_iter()
            .zip(["passwd", "shadow", "group", "gshadow"])
        {
            assert_eq!(fixture.read(name), contents);
            assert_eq!(fixture.metadata(name).ino(), inode);
        }
    }

    #[test]
    fn creates_hard_link_backups_of_live_databases() {
        let fixture = Fixture::new();
        let originals = ["passwd", "shadow", "group", "gshadow"].map(|name| {
            (
                name,
                fixture.read(name),
                File::open(fixture.etc().join(name)).expect("open live database"),
            )
        });

        create(fixture.etc(), &fixture.user()).expect("create user");

        for (name, contents, original) in originals {
            assert_eq!(fixture.read(&format!("{name}-")), contents);
            assert_eq!(
                original.metadata().expect("stat original database").ino(),
                fixture.metadata(&format!("{name}-")).ino()
            );
        }
    }

    struct Fixture {
        root: TempDir,
        etc: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("create fixture");
            let etc = root.path().join("etc");
            fs::create_dir(&etc).expect("create etc");
            for (name, contents) in [
                ("passwd", "root:x:0:0:root:/root:/bin/sh\n"),
                ("shadow", "root:*:1:0:99999:7:::\n"),
                ("group", "root:x:0:\n"),
                ("gshadow", "root:!::\n"),
            ] {
                fs::write(etc.join(name), contents).expect("write database");
            }
            Self { root, etc }
        }

        fn etc(&self) -> &Path {
            debug_assert!(self.etc.starts_with(self.root.path()));
            &self.etc
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.etc.join(name)).expect("read database")
        }

        fn metadata(&self, name: &str) -> fs::Metadata {
            fs::metadata(self.etc.join(name)).expect("stat database")
        }

        fn set_mode(&self, name: &str, mode: u32) {
            fs::set_permissions(self.etc.join(name), fs::Permissions::from_mode(mode))
                .expect("set database mode");
        }

        fn user(&self) -> UserConfig {
            UserConfig {
                name: "silo".to_string(),
                uid: 2000,
                gid: 2000,
                gecos: "Silo User".to_string(),
                home: "/home/silo".to_string(),
                shell: "/bin/bash".to_string(),
                sudo: String::new(),
                lock_passwd: true,
            }
        }
    }
}
