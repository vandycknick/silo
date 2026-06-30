use std::fs;
use std::path::{Path, PathBuf};

use eyre::{eyre, Context};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

use crate::constants::{
    CERTIFICATE_AUTHORITY_CERTIFICATE_FILE_NAME, CERTIFICATE_AUTHORITY_COMMON_NAME,
    CERTIFICATE_AUTHORITY_PRIVATE_KEY_FILE_NAME,
};
use crate::paths::LocalPaths;

#[derive(Debug, Clone)]
pub struct CertificateAuthority {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub certificate_pem: String,
}

pub fn ensure_certificate_authority() -> eyre::Result<CertificateAuthority> {
    let paths = LocalPaths::from_env()?;
    ensure_certificate_authority_in(&paths)
}

pub(crate) fn ensure_certificate_authority_in(
    paths: &LocalPaths,
) -> eyre::Result<CertificateAuthority> {
    let keys_dir = paths.keys_dir();
    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("create bento keys directory {}", keys_dir.display()))?;
    set_keys_dir_permissions(&keys_dir)?;

    let certificate_path = keys_dir.join(CERTIFICATE_AUTHORITY_CERTIFICATE_FILE_NAME);
    let private_key_path = keys_dir.join(CERTIFICATE_AUTHORITY_PRIVATE_KEY_FILE_NAME);

    validate_existing_file_slot(&certificate_path, "certificate authority certificate")?;
    validate_existing_file_slot(&private_key_path, "certificate authority private key")?;

    match (certificate_path.exists(), private_key_path.exists()) {
        (true, true) => load_certificate_authority(&certificate_path, &private_key_path),
        (false, false) => generate_certificate_authority(&certificate_path, &private_key_path),
        (true, false) | (false, true) => Err(eyre!(
            "certificate authority files must exist together: {} and {}",
            certificate_path.display(),
            private_key_path.display()
        )),
    }
}

pub(crate) fn read_certificate_authority_certificate(path: &Path) -> eyre::Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("read certificate authority certificate {}", path.display()))
}

fn load_certificate_authority(
    certificate_path: &Path,
    private_key_path: &Path,
) -> eyre::Result<CertificateAuthority> {
    set_certificate_permissions(certificate_path)?;
    set_private_key_permissions(private_key_path)?;
    let certificate_pem = read_certificate_authority_certificate(certificate_path)?;

    Ok(CertificateAuthority {
        certificate_path: certificate_path.to_path_buf(),
        private_key_path: private_key_path.to_path_buf(),
        certificate_pem,
    })
}

fn generate_certificate_authority(
    certificate_path: &Path,
    private_key_path: &Path,
) -> eyre::Result<CertificateAuthority> {
    let signing_key = KeyPair::generate().context("generate certificate authority private key")?;
    let mut params = CertificateParams::new(vec![CERTIFICATE_AUTHORITY_COMMON_NAME.to_string()])
        .context("create certificate authority parameters")?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, CERTIFICATE_AUTHORITY_COMMON_NAME);
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let certificate = params
        .self_signed(&signing_key)
        .context("generate self-signed certificate authority certificate")?;
    let certificate_pem = certificate.pem();
    let private_key_pem = signing_key.serialize_pem();

    write_certificate_file(certificate_path, &certificate_pem)?;
    write_private_key_file(private_key_path, &private_key_pem)?;

    Ok(CertificateAuthority {
        certificate_path: certificate_path.to_path_buf(),
        private_key_path: private_key_path.to_path_buf(),
        certificate_pem,
    })
}

fn validate_existing_file_slot(path: &Path, description: &str) -> eyre::Result<()> {
    if path.exists() && !path.is_file() {
        return Err(eyre!(
            "{description} path is not a file: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_keys_dir_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn set_keys_dir_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_private_key_file(path: &Path, contents: &str) -> eyre::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!(
                "create certificate authority private key {}",
                path.display()
            )
        })?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write certificate authority private key {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush certificate authority private key {}", path.display()))?;
    set_private_key_permissions(path)
}

#[cfg(not(unix))]
fn write_private_key_file(path: &Path, contents: &str) -> eyre::Result<()> {
    fs::write(path, contents)
        .with_context(|| format!("write certificate authority private key {}", path.display()))
}

#[cfg(unix)]
fn write_certificate_file(path: &Path, contents: &str) -> eyre::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| {
            format!(
                "create certificate authority certificate {}",
                path.display()
            )
        })?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write certificate authority certificate {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush certificate authority certificate {}", path.display()))?;
    set_certificate_permissions(path)
}

#[cfg(not(unix))]
fn write_certificate_file(path: &Path, contents: &str) -> eyre::Result<()> {
    fs::write(path, contents)
        .with_context(|| format!("write certificate authority certificate {}", path.display()))
}

#[cfg(unix)]
fn set_private_key_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_key_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_certificate_permissions(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn set_certificate_permissions(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_certificate_authority_creates_files_in_keys_dir() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("bento"));

        let authority = ensure_certificate_authority_in(&paths).expect("ensure CA");

        assert_eq!(authority.certificate_path, paths.keys_dir().join("ca.pem"));
        assert_eq!(
            authority.private_key_path,
            paths.keys_dir().join("ca-key.pem")
        );
        assert!(authority.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(authority.certificate_path.is_file());
        assert!(authority.private_key_path.is_file());
    }

    #[test]
    fn ensure_certificate_authority_reuses_existing_files() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        let first = ensure_certificate_authority_in(&paths).expect("ensure CA");
        let second = ensure_certificate_authority_in(&paths).expect("reuse CA");

        assert_eq!(second.certificate_path, first.certificate_path);
        assert_eq!(second.private_key_path, first.private_key_path);
        assert_eq!(second.certificate_pem, first.certificate_pem);
    }

    #[test]
    fn ensure_certificate_authority_rejects_partial_files() {
        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("bento"));
        fs::create_dir_all(paths.keys_dir()).expect("create keys dir");
        fs::write(paths.keys_dir().join("ca.pem"), "certificate").expect("write cert");

        let err = ensure_certificate_authority_in(&paths).expect_err("reject partial CA");

        assert!(err.to_string().contains("must exist together"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_certificate_authority_sets_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("create tempdir");
        let paths = LocalPaths::new(temp.path().join("bento"));

        let authority = ensure_certificate_authority_in(&paths).expect("ensure CA");

        let mode = fs::metadata(authority.private_key_path)
            .expect("stat private key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
