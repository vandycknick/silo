//! Generated lower descriptors, never imported VMDK text.
//!
//! Planning borrows retained metadata and performs no filesystem access or
//! descriptor allocation. The runtime owns closure retention from metadata
//! resolution through verification, publication, startup and failure cleanup.
//! Only a successful process-limit preflight exposes encoding and verification.

use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use crate::storage::identity::StreamId;
use crate::storage::limits::{
    preflight_fd_budget, BoundViolation, FileDescriptorLimits, Resource, LOGICAL_SECTOR_SIZE,
};
use crate::storage::pool::StoragePool;
use crate::storage::StorageError;

const FLAT_SECTORS: u64 = 2 * 1024 * 1024 * 1024 / LOGICAL_SECTOR_SIZE;
const HEADER: &str = "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\n\n";

/// One retained whole-stream occurrence. Only the owned pool resolves these;
/// repeats remain separate occurrences, not a set of attachment paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowerOccurrence {
    stream: StreamId,
    path: PathBuf,
    length: u64,
}

impl LowerOccurrence {
    pub(crate) fn resolved(stream: StreamId, path: PathBuf, length: u64) -> Self {
        Self {
            stream,
            path,
            length,
        }
    }

    pub fn stream(&self) -> &StreamId {
        &self.stream
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn length(&self) -> u64 {
        self.length
    }
}

#[derive(Debug)]
pub struct FlatLowerPlan<'a> {
    occurrences: &'a [LowerOccurrence],
    logical_length: u64,
    record_count: u64,
    descriptor_bytes: u64,
}

#[derive(Debug)]
pub struct PreparedLowerPlan<'a> {
    plan: FlatLowerPlan<'a>,
    limits: FileDescriptorLimits,
}

impl<'a> FlatLowerPlan<'a> {
    /// Count every split and repeated occurrence before constructing any text.
    pub fn new(occurrences: &'a [LowerOccurrence]) -> Result<Self, StorageError> {
        let mut logical_length = 0;
        let mut record_count = 0;
        for occurrence in occurrences {
            validate_path(&occurrence.path)?;
            if !occurrence.length.is_multiple_of(LOGICAL_SECTOR_SIZE) {
                return Err(BoundViolation::DiskGeometry {
                    length: occurrence.length,
                }
                .into());
            }
            logical_length =
                Resource::LogicalLowerBytes.sum([logical_length, occurrence.length])?;
            let sectors = occurrence.length / LOGICAL_SECTOR_SIZE;
            record_count =
                Resource::VmdkFlatRecords.sum([record_count, sectors.div_ceil(FLAT_SECTORS)])?;
        }
        if logical_length == 0 {
            return Err(BoundViolation::DiskGeometry { length: 0 }.into());
        }
        let mut count = ByteCount(0);
        encode(occurrences, &mut count)?;
        Resource::VmdkDescriptorBytes.check(count.0)?;
        Ok(Self {
            occurrences,
            logical_length,
            record_count,
            descriptor_bytes: count.0,
        })
    }

    pub fn logical_length(&self) -> u64 {
        self.logical_length
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn descriptor_bytes(&self) -> u64 {
        self.descriptor_bytes
    }

    /// The two roots and at most fourteen data disks fit the existing bounded
    /// included-disk envelope. Their handles, one closure lease and transient
    /// descriptor/verification opens are covered by the fixed 256-FD reserve.
    pub fn preflight(self, data_disk_count: u64) -> Result<PreparedLowerPlan<'a>, StorageError> {
        Resource::IncludedDisks.sum([2, data_disk_count])?;
        let limits = preflight_fd_budget(self.record_count)?;
        Ok(PreparedLowerPlan { plan: self, limits })
    }
}

impl PreparedLowerPlan<'_> {
    pub fn logical_length(&self) -> u64 {
        self.plan.logical_length
    }

    pub fn record_count(&self) -> u64 {
        self.plan.record_count
    }

    pub fn descriptor_bytes(&self) -> u64 {
        self.plan.descriptor_bytes
    }

    pub fn limits(&self) -> FileDescriptorLimits {
        self.limits
    }

    pub fn occurrences(&self) -> &[LowerOccurrence] {
        self.plan.occurrences
    }

    /// No path copies or per-record hashes. Empty streams have no backing open.
    pub fn unique_occurrences(&self) -> impl Iterator<Item = &LowerOccurrence> {
        self.plan
            .occurrences
            .iter()
            .enumerate()
            .filter_map(|(index, occurrence)| {
                (occurrence.length != 0
                    && !self.plan.occurrences[..index].iter().any(|previous| {
                        previous.length != 0 && previous.stream == occurrence.stream
                    }))
                .then_some(occurrence)
            })
    }

    /// Authenticate each unique immutable stream once, after resource admission.
    /// The caller must retain its closure guard throughout this operation and
    /// until worker startup/failure cleanup has completed.
    pub fn verify(&self, pool: &StoragePool) -> Result<(), StorageError> {
        for occurrence in self.occurrences() {
            if pool.stream_path(&occurrence.stream) != occurrence.path {
                return Err(StorageError::InvalidPath(format!(
                    "lower occurrence {} is outside the current pool",
                    occurrence.stream
                )));
            }
            let current = pool.lower_occurrence(&occurrence.stream)?;
            if current.length != occurrence.length {
                return Err(StorageError::LowerLength {
                    stream: occurrence.stream,
                    expected: occurrence.length,
                    actual: current.length,
                });
            }
        }
        for occurrence in self.unique_occurrences() {
            let map = pool.verify_stream(&occurrence.stream)?;
            if map.length() != occurrence.length {
                return Err(StorageError::LowerLength {
                    stream: occurrence.stream,
                    expected: occurrence.length,
                    actual: map.length(),
                });
            }
        }
        Ok(())
    }

    /// Allocate only the exact admitted text size, not a buffer per extent.
    pub fn descriptor(&self) -> Result<String, StorageError> {
        let capacity =
            usize::try_from(self.plan.descriptor_bytes).map_err(|_| BoundViolation::Overflow {
                resource: Resource::VmdkDescriptorBytes,
            })?;
        let mut output = BoundedText {
            bytes: Vec::new(),
            maximum: capacity,
        };
        output
            .bytes
            .try_reserve_exact(capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        encode(self.plan.occurrences, &mut output)?;
        if output.bytes.len() != capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "lower descriptor size changed",
            )
            .into());
        }
        String::from_utf8(output.bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error).into())
    }
}

fn validate_path(path: &Path) -> Result<&str, StorageError> {
    let text = path.to_str().ok_or_else(|| {
        StorageError::InvalidPath("lower descriptor paths must be valid UTF-8".into())
    })?;
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || text
            .split('/')
            .any(|component| component == "." || component == "..")
        || text
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\'))
        || text.trim() != text
    {
        return Err(StorageError::InvalidPath(
            "lower descriptor path is not representable".into(),
        ));
    }
    Ok(text)
}

fn encode(occurrences: &[LowerOccurrence], output: &mut impl Write) -> Result<(), StorageError> {
    output.write_all(HEADER.as_bytes())?;
    for occurrence in occurrences {
        let path = validate_path(&occurrence.path)?;
        let sectors = occurrence.length / LOGICAL_SECTOR_SIZE;
        let mut offset = 0;
        while offset < sectors {
            let count = FLAT_SECTORS.min(sectors - offset);
            writeln!(output, "RW {count} FLAT \"{path}\" {offset}")?;
            offset = offset.checked_add(count).ok_or(BoundViolation::Overflow {
                resource: Resource::LogicalLowerBytes,
            })?;
        }
    }
    Ok(())
}

struct ByteCount(u64);
impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "descriptor size overflow")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoundedText {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for BoundedText {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor exceeds admitted size",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    use crate::storage::identity::StreamId;
    use crate::storage::limits::{
        BoundViolation, FileDescriptorBudgetError, FileDescriptorLimits, Resource,
    };
    use crate::storage::vmdk::{FlatLowerPlan, LowerOccurrence, PreparedLowerPlan, HEADER};
    use crate::storage::StorageError;

    fn occurrence(id: u8, path: impl Into<PathBuf>, length: u64) -> LowerOccurrence {
        LowerOccurrence::resolved(StreamId::from_sha256([id; 32]), path.into(), length)
    }

    // Pure encoder tests do not mutate the process-wide limits. Actual admission
    // is exercised separately, in fresh subprocesses below.
    fn admitted(plan: FlatLowerPlan<'_>) -> PreparedLowerPlan<'_> {
        PreparedLowerPlan {
            plan,
            limits: FileDescriptorLimits {
                soft: 4096,
                hard: 4096,
                required: 256,
            },
        }
    }

    #[test]
    fn vmdk_split_boundaries_are_half_open_sector_offsets() {
        let gib = 1024_u64.pow(3);
        for (length, expected) in [
            (512, vec![(1, 0)]),
            (2 * gib - 512, vec![(4_194_303, 0)]),
            (2 * gib, vec![(4_194_304, 0)]),
            (2 * gib + 512, vec![(4_194_304, 0), (1, 4_194_304)]),
            (4 * gib, vec![(4_194_304, 0), (4_194_304, 4_194_304)]),
            (
                9 * gib / 2,
                vec![
                    (4_194_304, 0),
                    (4_194_304, 4_194_304),
                    (1_048_576, 8_388_608),
                ],
            ),
        ] {
            let occurrences = [occurrence(1, "/pool/a", length)];
            let plan = FlatLowerPlan::new(&occurrences).unwrap();
            assert_eq!(plan.logical_length(), length);
            assert_eq!(plan.record_count(), expected.len() as u64);
            let text = admitted(plan).descriptor().unwrap();
            let expected_text =
                expected
                    .into_iter()
                    .fold(HEADER.to_owned(), |mut text, (count, offset)| {
                        text.push_str(&format!("RW {count} FLAT \"/pool/a\" {offset}\n"));
                        text
                    });
            assert_eq!(text, expected_text);
        }
    }

    #[test]
    fn vmdk_ordered_repeats_and_empty_occurrences_preserve_mapping() {
        let occurrences = [
            occurrence(1, "/pool/a.bin", 4_831_838_208),
            occurrence(2, "/pool/empty", 0),
            occurrence(3, "/pool/b.bin", 1_048_576),
            occurrence(3, "/pool/b.bin", 1_048_576),
        ];
        let plan = FlatLowerPlan::new(&occurrences).unwrap();
        assert_eq!(plan.logical_length(), 4_833_935_360);
        assert_eq!(plan.record_count(), 5);
        let prepared = admitted(plan);
        assert_eq!(prepared.unique_occurrences().count(), 2);
        assert_eq!(prepared.occurrences(), occurrences);
        assert_eq!(prepared.descriptor().unwrap(), format!(
            "{HEADER}RW 4194304 FLAT \"/pool/a.bin\" 0\nRW 4194304 FLAT \"/pool/a.bin\" 4194304\nRW 1048576 FLAT \"/pool/a.bin\" 8388608\nRW 2048 FLAT \"/pool/b.bin\" 0\nRW 2048 FLAT \"/pool/b.bin\" 0\n"
        ));
        assert!(FlatLowerPlan::new(&[]).is_err());
        assert!(FlatLowerPlan::new(&[occurrence(2, "/pool/empty", 0)]).is_err());
    }

    #[test]
    fn vmdk_logical_and_record_bounds_are_inclusive_and_independent() {
        let tib = 1024_u64.pow(4);
        let occurrences = [occurrence(1, "/pool/a", tib)];
        assert_eq!(
            FlatLowerPlan::new(&occurrences).unwrap().record_count(),
            512
        );
        for length in [511, tib + 512, u64::MAX] {
            assert!(FlatLowerPlan::new(&[occurrence(1, "/pool/a", length)]).is_err());
        }
        let many = vec![occurrence(1, "/pool/a", 512); 1536];
        assert_eq!(FlatLowerPlan::new(&many).unwrap().record_count(), 1536);
        let too_many = vec![occurrence(1, "/pool/a", 512); 1537];
        assert!(matches!(
            FlatLowerPlan::new(&too_many),
            Err(StorageError::Bound(BoundViolation::Exceeded {
                resource: Resource::VmdkFlatRecords,
                actual: 1537,
                maximum: 1536
            }))
        ));
        assert!(matches!(
            Resource::LogicalLowerBytes.sum([1, u64::MAX]),
            Err(BoundViolation::Overflow { .. })
        ));
    }

    #[test]
    fn vmdk_exact_text_limit_counts_header_paths_digits_and_repeats() {
        let short = [occurrence(1, "/x", 512)];
        let base = FlatLowerPlan::new(&short).unwrap().descriptor_bytes();
        let maximum = Resource::VmdkDescriptorBytes.maximum();
        let path = format!("/{}", "x".repeat((maximum - base + 1) as usize));
        let exact = [occurrence(1, &path, 512)];
        let plan = FlatLowerPlan::new(&exact).unwrap();
        assert_eq!(plan.descriptor_bytes(), maximum);
        assert_eq!(admitted(plan).descriptor().unwrap().len() as u64, maximum);
        let over = [occurrence(1, format!("{path}x"), 512)];
        assert!(
            matches!(FlatLowerPlan::new(&over), Err(StorageError::Bound(BoundViolation::Exceeded {
            resource: Resource::VmdkDescriptorBytes, actual, maximum: limit
        })) if actual == maximum + 1 && limit == maximum)
        );
        let repeat_path = format!("/{}", "x".repeat(1024));
        let repeated = vec![occurrence(1, repeat_path, 512); 1536];
        let plan = FlatLowerPlan::new(&repeated).unwrap();
        assert_eq!(
            admitted(plan).descriptor().unwrap().len() as u64,
            HEADER.len() as u64 + 1536 * ("RW 1 FLAT \"\" 0\n".len() as u64 + 1025)
        );
    }

    #[test]
    fn vmdk_paths_allow_interior_spaces_and_utf8_but_reject_ambiguous_spellings() {
        let good = [occurrence(1, "/home/a b/日本語/sha256/a", 512)];
        assert!(admitted(FlatLowerPlan::new(&good).unwrap())
            .descriptor()
            .unwrap()
            .contains("\"/home/a b/日本語/sha256/a\""));
        for path in [
            "relative/a",
            "/a/../b",
            "/a/./b",
            "/a/quote\"",
            "/a/back\\slash",
            "/a/\0",
            "/a/\n",
            "/a/\r",
            "/a/\t",
            "/a/\u{7f}",
            "/a/\u{85}",
            "/a/trailing ",
        ] {
            assert!(
                FlatLowerPlan::new(&[occurrence(1, path, 512)]).is_err(),
                "{path:?}"
            );
        }
        let invalid = PathBuf::from(std::ffi::OsString::from_vec(b"/a/\xff".to_vec()));
        assert!(FlatLowerPlan::new(&[occurrence(1, invalid, 512)]).is_err());
    }

    #[test]
    fn vmdk_other_attachments_are_bounded_inside_reserved_overhead() {
        let occurrences = [occurrence(1, "/pool/missing", 512)];
        assert!(matches!(
            FlatLowerPlan::new(&occurrences).unwrap().preflight(15),
            Err(StorageError::Bound(BoundViolation::Exceeded {
                resource: Resource::IncludedDisks,
                ..
            }))
        ));
        assert!(matches!(
            FlatLowerPlan::new(&occurrences)
                .unwrap()
                .preflight(u64::MAX),
            Err(StorageError::Bound(BoundViolation::Overflow {
                resource: Resource::IncludedDisks
            }))
        ));
    }

    #[test]
    fn vmdk_rlimit_admission_runs_in_isolated_processes() {
        for mode in ["raise", "insufficient", "exact"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "storage::vmdk::tests::vmdk_rlimit_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("SILO_VMDK_RLIMIT_CHILD", mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn vmdk_rlimit_child() {
        let Ok(mode) = std::env::var("SILO_VMDK_RLIMIT_CHILD") else {
            return;
        };
        use nix::sys::resource::{getrlimit, setrlimit, Resource as HostResource};
        let (_, original_hard) = getrlimit(HostResource::RLIMIT_NOFILE).unwrap();
        assert!(
            original_hard >= 512,
            "test requires an initial hard limit >= 512"
        );
        let occurrences = [occurrence(1, "/pool/does-not-exist", 512)];
        let (soft, hard) = match mode.as_str() {
            "raise" => (32, 512),
            "insufficient" => (256, 256),
            "exact" => (257, 257),
            _ => panic!("unexpected child mode"),
        };
        setrlimit(HostResource::RLIMIT_NOFILE, soft, hard).unwrap();
        let result = FlatLowerPlan::new(&occurrences).unwrap().preflight(0);
        if mode == "insufficient" {
            assert!(matches!(
                result,
                Err(StorageError::FileDescriptorBudget(
                    FileDescriptorBudgetError::Insufficient {
                        required: 257,
                        soft: 256,
                        hard: 256
                    }
                ))
            ));
        } else {
            let limits = result.unwrap().limits();
            assert_eq!(
                (limits.soft, limits.hard, limits.required),
                (hard, hard, 257)
            );
        }
        assert_eq!(
            getrlimit(HostResource::RLIMIT_NOFILE).unwrap(),
            (hard, hard)
        );
    }

    #[test]
    fn vmdk_pool_metadata_rejects_symlinks_special_files_modes_and_links() {
        use crate::storage::pool::StoragePool;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&directory.path().join("images")).unwrap();
        let id = StreamId::from_sha256([42; 32]);
        let path = pool.stream_path(&id);
        let source = directory.path().join("source");
        std::fs::write(&source, [7; 512]).unwrap();
        symlink(&source, &path).unwrap();
        assert!(pool.lower_occurrence(&id).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(pool.lower_occurrence(&id).is_err());
        std::fs::remove_dir(&path).unwrap();
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(pool.lower_occurrence(&id).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, [7; 512]).unwrap();
        assert!(pool.lower_occurrence(&id).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(pool.lower_occurrence(&id).unwrap().length(), 512);
        let link = directory.path().join("link");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(pool.lower_occurrence(&id).is_err());
        std::fs::remove_file(&link).unwrap();
        let escaped = directory.path().join("escaped");
        std::fs::rename(directory.path().join("images/streams/sha256"), &escaped).unwrap();
        symlink(&escaped, directory.path().join("images/streams/sha256")).unwrap();
        assert!(StoragePool::open_existing(&directory.path().join("images")).is_err());
    }

    #[test]
    fn vmdk_verification_checks_current_pool_identity_and_exact_retained_length() {
        use crate::storage::pool::StoragePool;
        let directory = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&directory.path().join("images")).unwrap();
        let source = directory.path().join("source");
        std::fs::write(&source, [7; 512]).unwrap();
        let published = pool.publish_stream(&source).unwrap();
        let occurrences = [pool.lower_occurrence(&published.id).unwrap()];
        assert!(admitted(FlatLowerPlan::new(&occurrences).unwrap())
            .verify(&pool)
            .is_ok());
        let wrong_length = [LowerOccurrence::resolved(
            published.id,
            published.path.clone(),
            1024,
        )];
        assert!(matches!(
            admitted(FlatLowerPlan::new(&wrong_length).unwrap()).verify(&pool),
            Err(StorageError::LowerLength {
                expected: 1024,
                actual: 512,
                ..
            })
        ));
        let outside = [LowerOccurrence::resolved(published.id, source, 512)];
        assert!(matches!(
            admitted(FlatLowerPlan::new(&outside).unwrap()).verify(&pool),
            Err(StorageError::InvalidPath(_))
        ));
        let other = StoragePool::open(&directory.path().join("other")).unwrap();
        assert!(matches!(
            admitted(FlatLowerPlan::new(&occurrences).unwrap()).verify(&other),
            Err(StorageError::InvalidPath(_))
        ));
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&published.path, [8; 512]).unwrap();
        std::fs::set_permissions(&published.path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            admitted(FlatLowerPlan::new(&occurrences).unwrap()).verify(&pool),
            Err(StorageError::ContentMismatch(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vmdk_repeated_objects_are_opened_for_authentication_once() {
        use crate::storage::pool::StoragePool;
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        let directory = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&directory.path().join("images")).unwrap();
        let source = directory.path().join("source");
        std::fs::write(&source, [7; 512]).unwrap();
        let published = pool.publish_stream(&source).unwrap();
        let watcher = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK).unwrap();
        watcher
            .add_watch(
                &published.path,
                AddWatchFlags::IN_OPEN | AddWatchFlags::IN_CLOSE_NOWRITE,
            )
            .unwrap();
        let discovered: Vec<_> = pool
            .scan_streams()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(discovered, vec![(published.id, 512)]);
        assert_eq!(
            watcher.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN,
            "recovery discovery must not open lower backing files"
        );
        let occurrences = vec![pool.lower_occurrence(&published.id).unwrap(); 16];
        assert_eq!(
            watcher.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN
        );
        admitted(FlatLowerPlan::new(&occurrences).unwrap())
            .verify(&pool)
            .unwrap();
        let events = watcher.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.mask.contains(AddWatchFlags::IN_OPEN))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.mask.contains(AddWatchFlags::IN_CLOSE_NOWRITE))
                .count(),
            1
        );
        assert!(!events
            .iter()
            .any(|event| event.mask.contains(AddWatchFlags::IN_Q_OVERFLOW)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vmdk_refusal_observes_no_backing_opens_in_isolated_processes() {
        use crate::storage::pool::StoragePool;
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        use nix::sys::resource::{getrlimit, setrlimit, Resource as HostResource};
        let Ok(mode) = std::env::var("SILO_VMDK_NO_OPEN_CHILD") else {
            for mode in ["fd", "text"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "storage::vmdk::tests::vmdk_refusal_observes_no_backing_opens_in_isolated_processes", "--nocapture", "--test-threads=1"])
                    .env("SILO_VMDK_NO_OPEN_CHILD", mode).output().unwrap();
                assert!(
                    output.status.success(),
                    "{mode}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let mut home = directory.path().to_owned();
        if mode == "text" {
            for _ in 0..7 {
                home.push("x".repeat(220));
            }
            std::fs::create_dir_all(&home).unwrap();
        }
        let pool = StoragePool::open(&home.join("images")).unwrap();
        let source = directory.path().join("source");
        std::fs::write(&source, [7; 512]).unwrap();
        let published = pool.publish_stream(&source).unwrap();
        let watcher = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK).unwrap();
        watcher
            .add_watch(
                &published.path,
                AddWatchFlags::IN_OPEN | AddWatchFlags::IN_CLOSE_NOWRITE,
            )
            .unwrap();
        // Positive control: successful open-and-close is observable, unlike an
        // FD snapshot that would miss an already closed verification handle.
        drop(std::fs::File::open(&published.path).unwrap());
        assert!(watcher
            .read_events()
            .unwrap()
            .iter()
            .any(|event| event.mask.contains(AddWatchFlags::IN_OPEN)));
        let occurrences = vec![pool.lower_occurrence(&published.id).unwrap(); 1536];
        assert_eq!(
            watcher.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN
        );
        let (_, hard) = getrlimit(HostResource::RLIMIT_NOFILE).unwrap();
        assert!(hard >= 512);
        setrlimit(HostResource::RLIMIT_NOFILE, 512, 512).unwrap();
        let result = FlatLowerPlan::new(&occurrences)
            .and_then(|plan| plan.preflight(0))
            .and_then(|prepared| prepared.verify(&pool));
        if mode == "fd" {
            assert!(matches!(
                result,
                Err(StorageError::FileDescriptorBudget(
                    FileDescriptorBudgetError::Insufficient {
                        required: 1792,
                        soft: 512,
                        hard: 512
                    }
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(StorageError::Bound(BoundViolation::Exceeded {
                    resource: Resource::VmdkDescriptorBytes,
                    ..
                }))
            ));
        }
        assert_eq!(
            watcher.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN,
            "no successful backing open, including open-and-close, is permitted on refusal"
        );
    }
}
