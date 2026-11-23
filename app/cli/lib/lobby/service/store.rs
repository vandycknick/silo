use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use futures::future::BoxFuture;
use nix::errno::Errno;
use nix::fcntl::{open, openat, renameat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, mkdirat, Mode};
use nix::unistd::{geteuid, linkat, unlinkat, UnlinkatFlags};

use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::identity::Principal;
use crate::lobby::service::documents::{
    valid_document_name, Document, DocumentKind, DocumentTier, DOCUMENT_LIMIT,
};

/// Validation is deliberately outside the filesystem implementation. Policy
/// validation can call the daemon without weakening checks on stored documents.
pub(crate) trait DocumentValidator: Send + Sync {
    fn validate(&self, kind: DocumentKind, raw: String) -> BoxFuture<'_, Outcome<Document>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteMode {
    Create,
    Edit,
}

pub(crate) struct DocumentStore {
    home: PathBuf,
    config_dir: PathBuf,
    mutation: tokio::sync::Mutex<()>,
}

impl DocumentStore {
    pub(crate) fn new(home: PathBuf, config_dir: PathBuf) -> Outcome<Self> {
        Ok(Self {
            home: absolute_path(&home).map_err(store_failure)?,
            config_dir: absolute_path(&config_dir).map_err(store_failure)?,
            mutation: tokio::sync::Mutex::new(()),
        })
    }

    fn principal_path(&self, kind: DocumentKind, owner: &Principal) -> PathBuf {
        self.home
            .join("lobby/principals")
            .join(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(owner.as_str()))
            .join(kind.directory())
    }

    fn own_dir(
        &self,
        kind: DocumentKind,
        owner: &Principal,
        create: bool,
    ) -> io::Result<Option<File>> {
        Principal::parse(owner.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid principal"))?;
        optional_dir(
            &self.principal_path(kind, owner),
            Some(&self.home.join("lobby")),
            create,
        )
    }

    fn operator_dir(&self, kind: DocumentKind) -> io::Result<Option<File>> {
        optional_dir(&self.config_dir.join(kind.directory()), None, false)
    }

    pub(crate) async fn list(
        &self,
        kind: DocumentKind,
        owner: &Principal,
        validator: &(impl DocumentValidator + ?Sized),
    ) -> Outcome<Vec<Document>> {
        let _guard = self.mutation.lock().await;
        let own = self.own_dir(kind, owner, false).map_err(store_failure)?;
        let operator = self.operator_dir(kind).map_err(store_failure)?;
        let mut out = Vec::new();
        for (dir, tier) in [
            (own.as_ref(), DocumentTier::Yours),
            (operator.as_ref(), DocumentTier::Operator),
        ] {
            if let Some(dir) = dir {
                for name in document_names(dir, kind).map_err(store_failure)? {
                    let mut document = load(dir, kind, &name, tier, owner, validator).await?;
                    document.content.clear();
                    out.push(document);
                }
            }
        }
        out.sort_by(|left, right| {
            left.name.cmp(&right.name).then_with(|| {
                (left.tier == Some(DocumentTier::Operator))
                    .cmp(&(right.tier == Some(DocumentTier::Operator)))
            })
        });
        Ok(out)
    }

    pub(crate) async fn read(
        &self,
        kind: DocumentKind,
        owner: &Principal,
        name: &str,
        validator: &(impl DocumentValidator + ?Sized),
    ) -> Outcome<Document> {
        check_name(name)?;
        let _guard = self.mutation.lock().await;
        let own = self.own_dir(kind, owner, false).map_err(store_failure)?;
        let operator = self.operator_dir(kind).map_err(store_failure)?;
        if let Some(dir) = own.as_ref() {
            match load(dir, kind, name, DocumentTier::Yours, owner, validator).await {
                Err(error) if error.code == Code::NotFound => {}
                result => return result,
            }
        }
        let dir = operator.as_ref().ok_or_else(not_found)?;
        load(dir, kind, name, DocumentTier::Operator, owner, validator).await
    }

    pub(crate) async fn write(
        &self,
        kind: DocumentKind,
        owner: &Principal,
        name: &str,
        raw: String,
        mode: WriteMode,
        validator: &(impl DocumentValidator + ?Sized),
    ) -> Outcome<Document> {
        check_name(name)?;
        let _guard = self.mutation.lock().await;
        let own = self.own_dir(kind, owner, true).map_err(store_failure)?;
        let operator = self.operator_dir(kind).map_err(store_failure)?;
        let dir = own.as_ref().ok_or_else(not_found)?;
        let existing = load(dir, kind, name, DocumentTier::Yours, owner, validator).await;
        match existing {
            Ok(_) if mode == WriteMode::Create => {
                return Err(Failure::new(Code::Conflict, "document already exists"));
            }
            Err(error) if error.code != Code::NotFound => return Err(error),
            Err(error) if mode == WriteMode::Edit => {
                refuse_operator(operator.as_ref(), kind, name, owner, validator).await?;
                return Err(error);
            }
            _ => {}
        }
        let mut document = validator.validate(kind, raw).await?;
        if document.content.is_empty() || document.content.len() > DOCUMENT_LIMIT {
            return Err(Failure::new(
                Code::Usage,
                "canonical document exceeds 64KiB",
            ));
        }
        write_document(
            dir,
            &format!("{name}{}", kind.extension()),
            &document.content,
            mode,
        )
        .map_err(store_failure)?;
        document.kind = kind;
        document.name = name.to_owned();
        document.tier = Some(DocumentTier::Yours);
        document.owner = Some(owner.clone());
        Ok(document)
    }

    pub(crate) async fn remove(
        &self,
        kind: DocumentKind,
        owner: &Principal,
        name: &str,
        validator: &(impl DocumentValidator + ?Sized),
    ) -> Outcome<Document> {
        check_name(name)?;
        let _guard = self.mutation.lock().await;
        let own = self.own_dir(kind, owner, true).map_err(store_failure)?;
        let operator = self.operator_dir(kind).map_err(store_failure)?;
        let dir = own.as_ref().ok_or_else(not_found)?;
        if let Err(error) = load(dir, kind, name, DocumentTier::Yours, owner, validator).await {
            if error.code == Code::NotFound {
                refuse_operator(operator.as_ref(), kind, name, owner, validator).await?;
            }
            return Err(error);
        }
        unlinkat(
            dir,
            format!("{name}{}", kind.extension()).as_str(),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|error| store_failure(error.into()))?;
        dir.sync_all().map_err(store_failure)?;
        let mut document = Document::new(kind);
        document.name = name.to_owned();
        document.tier = Some(DocumentTier::Yours);
        document.owner = Some(owner.clone());
        Ok(document)
    }

    /// Operator files are uncached. This is also the startup/SIGHUP validation path.
    pub(crate) async fn list_operator(
        &self,
        kind: DocumentKind,
        validator: &(impl DocumentValidator + ?Sized),
    ) -> Outcome<Vec<Document>> {
        let _guard = self.mutation.lock().await;
        let Some(dir) = self.operator_dir(kind).map_err(store_failure)? else {
            return Ok(Vec::new());
        };
        let mut documents = Vec::new();
        for name in document_names(&dir, kind).map_err(store_failure)? {
            let raw = read_document(&dir, &format!("{name}{}", kind.extension()), false)
                .map_err(store_failure)?;
            let mut document = validator
                .validate(kind, raw)
                .await
                .map_err(|_| unsafe_store())?;
            document.kind = kind;
            document.name = name;
            document.tier = Some(DocumentTier::Operator);
            document.owner = None;
            document.content.clear();
            documents.push(document);
        }
        documents.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(documents)
    }

    pub(crate) async fn reload_operator(
        &self,
        validator: &(impl DocumentValidator + ?Sized),
    ) -> Outcome<()> {
        for kind in [DocumentKind::Template, DocumentKind::Policy] {
            self.list_operator(kind, validator).await?;
        }
        Ok(())
    }
}

async fn load(
    dir: &File,
    kind: DocumentKind,
    name: &str,
    tier: DocumentTier,
    owner: &Principal,
    validator: &(impl DocumentValidator + ?Sized),
) -> Outcome<Document> {
    let raw = read_document(
        dir,
        &format!("{name}{}", kind.extension()),
        tier == DocumentTier::Yours,
    )
    .map_err(store_failure)?;
    let mut document = validator
        .validate(kind, raw)
        .await
        .map_err(|_| unsafe_store())?;
    document.kind = kind;
    document.name = name.to_owned();
    document.tier = Some(tier);
    document.owner = (tier == DocumentTier::Yours).then(|| owner.clone());
    Ok(document)
}

async fn refuse_operator(
    dir: Option<&File>,
    kind: DocumentKind,
    name: &str,
    owner: &Principal,
    validator: &(impl DocumentValidator + ?Sized),
) -> Outcome<()> {
    if let Some(dir) = dir {
        match load(dir, kind, name, DocumentTier::Operator, owner, validator).await {
            Ok(_) => {
                return Err(Failure::new(
                    Code::Forbidden,
                    "operator documents are read-only",
                ))
            }
            Err(error) if error.code == Code::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::other("absolute document directory required"));
    }
    let mut clean = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::ParentDir => {
                clean.pop();
            }
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) => return Err(io::Error::other("invalid document directory")),
        }
    }
    Ok(clean)
}

fn optional_dir(
    path: &Path,
    private_from: Option<&Path>,
    create: bool,
) -> io::Result<Option<File>> {
    match document_dir(path, private_from, create) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn document_dir(path: &Path, private_from: Option<&Path>, create: bool) -> io::Result<File> {
    let path = absolute_path(path)?;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let mut current = File::from(open("/", flags, Mode::empty())?);
    let mut walked = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        walked.push(part);
        let private = private_from.is_some_and(|root| walked.starts_with(root));
        let next = match openat(&current, part, flags, Mode::empty()) {
            Err(Errno::ENOENT) if create && private => {
                match mkdirat(&current, part, Mode::S_IRWXU) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                openat(&current, part, flags, Mode::empty())?
            }
            result => result?,
        };
        current = File::from(next);
        if private {
            let metadata = current.metadata()?;
            if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
                return Err(io::Error::other(
                    "document directory must be owned and private",
                ));
            }
        }
    }
    Ok(current)
}

fn read_document(dir: &File, name: &str, private: bool) -> io::Result<String> {
    let file = File::from(openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > DOCUMENT_LIMIT as u64
        || (private && (metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o077 != 0))
    {
        return Err(io::Error::other("invalid document file"));
    }
    let mut raw = String::new();
    file.take(DOCUMENT_LIMIT as u64 + 1)
        .read_to_string(&mut raw)?;
    if raw.len() > DOCUMENT_LIMIT {
        return Err(io::Error::other("document exceeds 64KiB"));
    }
    Ok(raw)
}

fn document_names(dir: &File, kind: DocumentKind) -> io::Result<Vec<String>> {
    let mut stream = nix::dir::Dir::openat(
        dir,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let mut names = Vec::new();
    let mut count = 0;
    for entry in stream.iter() {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        count += 1;
        if count > 4096 {
            return Err(io::Error::other("document directory exceeds 4096 entries"));
        }
        if bytes.ends_with(kind.extension().as_bytes()) {
            let name = std::str::from_utf8(&bytes[..bytes.len() - kind.extension().len()])
                .map_err(|_| io::Error::other("invalid stored document name"))?;
            if !valid_document_name(name) {
                return Err(io::Error::other("invalid stored document name"));
            }
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

fn write_document(dir: &File, name: &str, raw: &str, mode: WriteMode) -> io::Result<()> {
    let temporary = format!(".lobby-{}", uuid::Uuid::new_v4().simple());
    let file = File::from(openat(
        dir,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )?);
    struct Temporary<'a> {
        dir: &'a File,
        name: &'a str,
    }
    impl Drop for Temporary<'_> {
        fn drop(&mut self) {
            let _ = unlinkat(self.dir, self.name, UnlinkatFlags::NoRemoveDir);
        }
    }
    let temporary_guard = Temporary {
        dir,
        name: &temporary,
    };
    let mut file = file;
    fchmod(&file, Mode::S_IRUSR | Mode::S_IWUSR)?;
    file.write_all(raw.as_bytes())?;
    file.sync_all()?;
    nix::unistd::close(file)?;
    match mode {
        WriteMode::Create => {
            linkat(dir, temporary.as_str(), dir, name, AtFlags::empty())?;
            unlinkat(dir, temporary.as_str(), UnlinkatFlags::NoRemoveDir)?;
        }
        WriteMode::Edit => renameat(dir, temporary.as_str(), dir, name)?,
    }
    drop(temporary_guard);
    dir.sync_all()
}

fn check_name(name: &str) -> Outcome<()> {
    if valid_document_name(name) {
        Ok(())
    } else {
        Err(Failure::new(Code::Usage, "invalid document name"))
    }
}

fn not_found() -> Failure {
    Failure::new(Code::NotFound, "document not found")
}
fn unsafe_store() -> Failure {
    Failure::new(Code::Unavailable, "document store unavailable or unsafe")
}
fn store_failure(error: io::Error) -> Failure {
    if error.kind() == io::ErrorKind::InvalidInput {
        return Failure::new(Code::Usage, "invalid remote document field type");
    }
    match error.raw_os_error() {
        Some(code) if code == Errno::ENOENT as i32 => not_found(),
        Some(code) if code == Errno::EEXIST as i32 => {
            Failure::new(Code::Conflict, "document already exists")
        }
        _ => unsafe_store(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::Path;

    use futures::future::BoxFuture;
    use silod_spec::daemon::v1 as w;

    use crate::lobby::failure::{Code, Failure, Outcome};
    use crate::lobby::identity::Principal;
    use crate::lobby::service::documents::{
        validate_document, Document, DocumentKind, DocumentTier, DOCUMENT_LIMIT,
    };
    use crate::lobby::service::store::{
        document_dir, document_names, read_document, DocumentStore, DocumentValidator, WriteMode,
    };

    struct Validator;
    impl DocumentValidator for Validator {
        fn validate(&self, kind: DocumentKind, raw: String) -> BoxFuture<'_, Outcome<Document>> {
            Box::pin(async move {
                validate_document(kind, &raw, &mut |request: w::NormalizePolicyRequest| {
                    std::future::ready(
                        silo_vm_control::policy::normalize_policy(request)
                            .map_err(|_| Failure::new(Code::Usage, "invalid policy")),
                    )
                })
                .await
            })
        }
    }

    fn fixture() -> (tempfile::TempDir, DocumentStore) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let home = root.join("home");
        let config = root.join("config");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&config).unwrap();
        let store = DocumentStore::new(home, config).unwrap();
        (temporary, store)
    }

    fn owner(number: u8) -> Principal {
        Principal::parse(&format!("user:{number}")).unwrap()
    }
    fn private_file(path: &Path, raw: &[u8]) {
        fs::write(path, raw).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[tokio::test]
    async fn principal_documents_real_files_tiers_and_reload() {
        let (_temporary, store) = fixture();
        let kind = DocumentKind::Template;
        let one = owner(1);
        let two = owner(2);
        assert!(store.list(kind, &one, &Validator).await.unwrap().is_empty());
        assert!(store
            .list_operator(kind, &Validator)
            .await
            .unwrap()
            .is_empty());
        assert!(!store.home.join("lobby").exists());
        let operator = store.config_dir.join("templates");
        fs::create_dir(&operator).unwrap();
        fs::write(
            operator.join("dev.yaml"),
            "version: '1'\ndescription: operator",
        )
        .unwrap();
        assert_eq!(
            store
                .read(kind, &one, "dev", &Validator)
                .await
                .unwrap()
                .tier,
            Some(DocumentTier::Operator)
        );
        assert_eq!(
            store
                .write(
                    kind,
                    &one,
                    "dev",
                    "version: '1'".into(),
                    WriteMode::Edit,
                    &Validator
                )
                .await
                .unwrap_err()
                .code,
            Code::Forbidden
        );
        assert_eq!(
            store
                .remove(kind, &one, "dev", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Forbidden
        );
        store
            .write(
                kind,
                &one,
                "dev",
                "version: '1'\ndescription: yours".into(),
                WriteMode::Create,
                &Validator,
            )
            .await
            .unwrap();
        let own = store.read(kind, &one, "dev", &Validator).await.unwrap();
        assert_eq!(own.template.unwrap().description.as_deref(), Some("yours"));
        let other = store.read(kind, &two, "dev", &Validator).await.unwrap();
        assert_eq!(
            other.template.unwrap().description.as_deref(),
            Some("operator")
        );
        store
            .write(
                kind,
                &one,
                "private",
                "version: '1'".into(),
                WriteMode::Create,
                &Validator,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .read(kind, &two, "private", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::NotFound
        );
        let listed = store.list(kind, &one, &Validator).await.unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].tier, Some(DocumentTier::Yours));
        assert_eq!(listed[1].tier, Some(DocumentTier::Operator));
        assert!(listed.iter().all(|document| document.content.is_empty()));
        fs::write(
            operator.join("dev.yaml"),
            "version: '1'\ndescription: refreshed",
        )
        .unwrap();
        store.reload_operator(&Validator).await.unwrap();
        assert_eq!(
            store
                .read(kind, &two, "dev", &Validator)
                .await
                .unwrap()
                .template
                .unwrap()
                .description
                .as_deref(),
            Some("refreshed")
        );
        fs::write(operator.join("dev.yaml"), "version: '1'\nmounts: []").unwrap();
        assert_eq!(
            store.reload_operator(&Validator).await.unwrap_err().code,
            Code::Unavailable
        );
        assert_eq!(
            store.list(kind, &one, &Validator).await.unwrap_err().code,
            Code::Unavailable
        );
        fs::write(operator.join("dev.yaml"), "version: '1'").unwrap();
        let own_path = store.principal_path(kind, &one);
        for ancestor in [
            store.home.join("lobby"),
            store.home.join("lobby/principals"),
            own_path.parent().unwrap().to_path_buf(),
            own_path.clone(),
        ] {
            assert_eq!(fs::metadata(ancestor).unwrap().mode() & 0o777, 0o700);
        }
        assert_eq!(
            fs::metadata(own_path.join("private.yaml")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(own_path
            .to_string_lossy()
            .ends_with("/lobby/principals/dXNlcjox/templates"));
        store
            .write(
                kind,
                &one,
                "private",
                "version: '1'\ndescription: edited".into(),
                WriteMode::Edit,
                &Validator,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .read(kind, &one, "private", &Validator)
                .await
                .unwrap()
                .template
                .unwrap()
                .description
                .as_deref(),
            Some("edited")
        );
        let removed = store
            .remove(kind, &one, "private", &Validator)
            .await
            .unwrap();
        assert_eq!(removed.owner.as_ref(), Some(&one));
        assert!(removed.content.is_empty());
        assert!(removed.template.is_none());
        assert_eq!(
            store
                .read(kind, &one, "private", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::NotFound
        );
        assert!(fs::read_dir(own_path).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".lobby-")));
    }

    #[tokio::test]
    async fn concurrent_create_has_one_atomic_winner() {
        let (_temporary, store) = fixture();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let store = DocumentStore::new(store.home.clone(), store.config_dir.clone()).unwrap();
            tasks.spawn(async move {
                store
                    .write(
                        DocumentKind::Template,
                        &owner(1),
                        "concurrent",
                        "version: '1'".into(),
                        WriteMode::Create,
                        &Validator,
                    )
                    .await
            });
        }
        let mut wins = 0;
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Ok(_) => wins += 1,
                Err(error) => assert_eq!(error.code, Code::Conflict),
            }
        }
        assert_eq!(wins, 1);
        let own = store.principal_path(DocumentKind::Template, &owner(1));
        assert_eq!(fs::read_dir(&own).unwrap().count(), 1);
        assert_eq!(
            fs::metadata(own.join("concurrent.yaml")).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn document_files_and_ancestors_refuse_symlinks_and_unsafe_modes() {
        let (temporary, store) = fixture();
        let kind = DocumentKind::Template;
        let owner = owner(1);
        store
            .write(
                kind,
                &owner,
                "private",
                "version: '1'".into(),
                WriteMode::Create,
                &Validator,
            )
            .await
            .unwrap();
        let path = store.principal_path(kind, &owner);
        let target = temporary.path().join("outside.yaml");
        private_file(&target, b"version: '1'");
        symlink(&target, path.join("link.yaml")).unwrap();
        assert_eq!(
            store
                .read(kind, &owner, "link", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Unavailable
        );
        assert_eq!(
            store
                .write(
                    kind,
                    &owner,
                    "link",
                    "version: '1'".into(),
                    WriteMode::Edit,
                    &Validator
                )
                .await
                .unwrap_err()
                .code,
            Code::Unavailable
        );
        fs::remove_file(path.join("link.yaml")).unwrap();
        private_file(&path.join("large.yaml"), &vec![b'x'; DOCUMENT_LIMIT + 1]);
        assert_eq!(
            store
                .read(kind, &owner, "large", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Unavailable
        );
        fs::remove_file(path.join("large.yaml")).unwrap();
        fs::set_permissions(path.join("private.yaml"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store
                .read(kind, &owner, "private", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Unavailable
        );
        fs::set_permissions(path.join("private.yaml"), fs::Permissions::from_mode(0o600)).unwrap();
        private_file(&path.join("malformed.yaml"), b"version: '1'\nmounts: []");
        assert_eq!(
            store.list(kind, &owner, &Validator).await.unwrap_err().code,
            Code::Unavailable
        );
        fs::remove_file(path.join("malformed.yaml")).unwrap();
        fs::rename(&path, path.with_extension("saved")).unwrap();
        symlink(path.with_extension("saved"), &path).unwrap();
        assert_eq!(
            store
                .read(kind, &owner, "private", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Unavailable
        );
        fs::remove_file(&path).unwrap();
        fs::rename(path.with_extension("saved"), &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            store.list(kind, &owner, &Validator).await.unwrap_err().code,
            Code::Unavailable
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let config = store.config_dir.join("templates");
        symlink(&path, &config).unwrap();
        assert_eq!(
            store
                .list_operator(kind, &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Unavailable
        );
    }

    #[test]
    fn descriptor_reads_reject_special_files_and_oversized_or_invalid_directories() {
        let (_temporary, store) = fixture();
        let path = store.principal_path(DocumentKind::Template, &owner(1));
        let dir = document_dir(&path, Some(&store.home.join("lobby")), true).unwrap();
        fs::create_dir(path.join("directory.yaml")).unwrap();
        assert!(read_document(&dir, "directory.yaml", true).is_err());
        nix::unistd::mkfifo(
            &path.join("fifo.yaml"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(read_document(&dir, "fifo.yaml", true).is_err());
        private_file(&path.join("invalid-utf8.yaml"), &[0xff]);
        assert!(read_document(&dir, "invalid-utf8.yaml", true).is_err());
        private_file(&path.join("INVALID.yaml"), b"version: '1'");
        assert!(document_names(&dir, DocumentKind::Template).is_err());
        fs::remove_file(path.join("INVALID.yaml")).unwrap();
        for number in 0..4097 {
            private_file(&path.join(format!("entry-{number}.ignored")), b"");
        }
        assert!(document_names(&dir, DocumentKind::Template).is_err());
        assert!(DocumentStore::new("relative".into(), store.config_dir.clone()).is_err());
    }

    #[tokio::test]
    async fn policy_namespaces_and_operator_precedence() {
        let (_temporary, store) = fixture();
        let kind = DocumentKind::Policy;
        fs::create_dir(store.config_dir.join("policies")).unwrap();
        fs::write(
            store.config_dir.join("policies/egress.hcl"),
            "settings { default_action = \"deny\" }",
        )
        .unwrap();
        store
            .write(
                kind,
                &owner(1),
                "egress",
                "settings { default_action = \"allow\" }".into(),
                WriteMode::Create,
                &Validator,
            )
            .await
            .unwrap();
        for (owner, tier, action) in [
            (owner(1), DocumentTier::Yours, "allow"),
            (owner(2), DocumentTier::Operator, "deny"),
        ] {
            let document = store
                .read(kind, &owner, "egress", &Validator)
                .await
                .unwrap();
            assert_eq!(document.tier, Some(tier));
            assert!(document
                .content
                .contains(&format!("default_action = \"{action}\"")));
        }
        assert_eq!(
            store
                .write(
                    kind,
                    &owner(2),
                    "egress",
                    "settings { default_action = \"allow\" }".into(),
                    WriteMode::Edit,
                    &Validator
                )
                .await
                .unwrap_err()
                .code,
            Code::Forbidden
        );
        assert_eq!(
            store
                .remove(kind, &owner(2), "egress", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Forbidden
        );
        store.reload_operator(&Validator).await.unwrap();
        for name in ["../x", "", "UPPER"] {
            assert_eq!(
                store
                    .read(kind, &owner(1), name, &Validator)
                    .await
                    .unwrap_err()
                    .code,
                Code::Usage
            );
        }
        assert_eq!(
            store
                .list(kind, &Principal::default(), &Validator)
                .await
                .unwrap_err()
                .code,
            Code::Usage
        );
        assert_eq!(
            store
                .write(
                    kind,
                    &owner(1),
                    "missing",
                    "settings { default_action = \"deny\" }".into(),
                    WriteMode::Edit,
                    &Validator
                )
                .await
                .unwrap_err()
                .code,
            Code::NotFound
        );
        assert_eq!(
            store
                .remove(kind, &owner(1), "missing", &Validator)
                .await
                .unwrap_err()
                .code,
            Code::NotFound
        );
    }
}
