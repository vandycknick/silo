use std::fs;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PublicKeyData,
};
use silo_secrets::{
    Secret, SecretBytes, SecretError, SecretName, SecretScope, SecretScopeTransaction, SecretStore,
};

use crate::constants::CERTIFICATE_AUTHORITY_COMMON_NAME;
use crate::paths::LocalPaths;
use crate::NetdRuntimeConfig;

pub(crate) const CERTIFICATE: &str = "silo.tls_ca.certificate";
pub(crate) const PRIVATE: &str = "silo.tls_ca.private_key";

#[derive(Debug)]
pub(crate) struct CaPair {
    pub(crate) certificate: String,
    pub(crate) private: SecretBytes,
}

fn invalid(message: impl Into<String>) -> SecretError {
    SecretError::InvalidRequest(message.into())
}

fn generate() -> Result<CaPair, SecretError> {
    let key = KeyPair::generate().map_err(|e| invalid(e.to_string()))?;
    let mut params = CertificateParams::new(vec![CERTIFICATE_AUTHORITY_COMMON_NAME.into()])
        .map_err(|e| invalid(e.to_string()))?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, CERTIFICATE_AUTHORITY_COMMON_NAME);
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let certificate = params
        .self_signed(&key)
        .map_err(|e| invalid(e.to_string()))?;
    Ok(CaPair {
        certificate: certificate.pem(),
        private: SecretBytes::new(key.serialize_pem().into_bytes()),
    })
}

fn validate(pair: CaPair) -> Result<CaPair, SecretError> {
    single_pem(pair.private.as_str()?, None)?;
    let key = KeyPair::from_pem(pair.private.as_str()?)
        .map_err(|e| invalid(format!("invalid TLS CA private key: {e}")))?;
    let der = single_pem(&pair.certificate, Some("CERTIFICATE"))?;
    let (rest, certificate) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| invalid(format!("invalid TLS CA certificate: {e}")))?;
    if !rest.is_empty() {
        return Err(invalid("trailing TLS CA certificate data"));
    }
    let constraints = certificate
        .basic_constraints()
        .map_err(|e| invalid(e.to_string()))?;
    let usage = certificate
        .key_usage()
        .map_err(|e| invalid(e.to_string()))?;
    // RFC 5280 permits an absent KeyUsage; if supplied, signing is required.
    if !constraints.is_some_and(|c| c.value.ca) || usage.is_some_and(|u| !u.value.key_cert_sign()) {
        return Err(invalid("TLS certificate is not a signing CA"));
    }
    if !certificate.validity().is_valid() {
        return Err(invalid("TLS CA certificate is expired or not yet valid"));
    }
    if certificate.public_key().raw != key.subject_public_key_info() {
        return Err(invalid("TLS CA certificate and private key do not match"));
    }
    Ok(pair)
}

fn single_pem(
    input: &str,
    label: Option<&str>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, SecretError> {
    let input = input.trim();
    if !input.starts_with("-----BEGIN ") {
        return Err(invalid(
            "TLS CA material must contain exactly one PEM block",
        ));
    }
    let (rest, pem) = x509_parser::pem::parse_x509_pem(input.as_bytes())
        .map_err(|e| invalid(format!("invalid TLS CA PEM: {e}")))?;
    let der = zeroize::Zeroizing::new(pem.contents);
    if !rest.iter().all(u8::is_ascii_whitespace)
        || label.is_some_and(|label| pem.label != label)
        || input.lines().next() != Some(format!("-----BEGIN {}-----", pem.label).as_str())
        || input.lines().last() != Some(format!("-----END {}-----", pem.label).as_str())
    {
        return Err(invalid(
            "TLS CA material must contain exactly one PEM block with the expected label",
        ));
    }
    Ok(der)
}

fn import(certificate: &Path, private: &Path) -> Result<CaPair, SecretError> {
    validate(CaPair {
        certificate: fs::read_to_string(certificate).map_err(|e| {
            invalid(format!(
                "read TLS CA certificate {}: {e}",
                certificate.display()
            ))
        })?,
        private: SecretBytes::new(fs::read(private).map_err(|e| {
            invalid(format!(
                "read TLS CA private key {}: {e}",
                private.display()
            ))
        })?),
    })
}

/// Resolve exactly once under the selected store's Home transaction. Legacy
/// files are import inputs only and are never modified or removed.
pub(crate) fn resolve(
    store: &dyn SecretStore,
    paths: &LocalPaths,
    config: &NetdRuntimeConfig,
) -> Result<CaPair, SecretError> {
    let certificate_name = SecretName::new(CERTIFICATE)?;
    let private_name = SecretName::new(PRIVATE)?;
    let mut resolved = None;
    let mut migrated = false;
    store.update_scope(
        &SecretScope::Home,
        &mut |tx: &mut dyn SecretScopeTransaction| {
            let stored = match (tx.get(&certificate_name)?, tx.get(&private_name)?) {
                (None, None) => None,
                (Some(Secret::Plain(certificate)), Some(Secret::Plain(private))) => {
                    Some(validate(CaPair {
                        certificate: certificate.as_str()?.into(),
                        private,
                    })?)
                }
                _ => {
                    return Err(invalid(
                        "stored TLS CA pair is partial or has invalid record types",
                    ))
                }
            };
            let operator = match (&config.tls_ca_cert, &config.tls_ca_key) {
                (None, None) => None,
                (Some(certificate), Some(private)) => Some(import(certificate, private)?),
                _ => {
                    return Err(invalid(
                        "TLS CA certificate and private key must be configured together",
                    ))
                }
            };
            let pair = if let Some(stored) = stored {
                if let Some(operator) = operator {
                    if stored.certificate != operator.certificate
                        || stored.private != operator.private
                    {
                        return Err(invalid("operator TLS CA conflicts with the stored Home CA"));
                    }
                }
                stored
            } else {
                let pair = if let Some(operator) = operator {
                    operator
                } else {
                    let certificate = paths.keys_dir().join("ca.pem");
                    let private = paths.keys_dir().join("ca-key.pem");
                    match (certificate.try_exists()?, private.try_exists()?) {
                        (false, false) => generate()?,
                        (true, true) => {
                            migrated = true;
                            import(&certificate, &private)?
                        }
                        _ => return Err(invalid("legacy TLS CA files must exist together")),
                    }
                };
                tx.put(
                    &certificate_name,
                    Secret::Plain(SecretBytes::new(pair.certificate.as_bytes().to_vec())),
                )?;
                tx.put(&private_name, Secret::Plain(pair.private.clone()))?;
                pair
            };
            resolved = Some(pair);
            Ok(())
        },
    )?;
    if migrated {
        tracing::info!(
            "imported legacy TLS CA into the selected Home secret store; legacy files retained"
        );
    }
    resolved.ok_or_else(|| {
        SecretError::Internal("secret store did not execute atomic scope operation".into())
    })
}

#[cfg(test)]
mod tests {
    use crate::host::certificates::{generate, resolve, validate, CERTIFICATE, PRIVATE};
    use crate::paths::LocalPaths;
    use crate::NetdRuntimeConfig;
    use silo_secrets::{FileStore, Secret, SecretBytes, SecretName, SecretScope, SecretStore};
    use std::fs;

    fn fixture() -> (tempfile::TempDir, LocalPaths, FileStore) {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("runtime"));
        let store = FileStore::new(temp.path().join("external"));
        (temp, paths, store)
    }

    #[test]
    fn fresh_home_reuses_atomic_pair_without_key_files() {
        let (_temp, paths, store) = fixture();
        let pair = resolve(&store, &paths, &NetdRuntimeConfig::default()).unwrap();
        validate(pair).unwrap();
        let before = fs::read(store.path()).unwrap();
        let pair = resolve(&store, &paths, &NetdRuntimeConfig::default()).unwrap();
        assert!(pair.certificate.contains("BEGIN CERTIFICATE"));
        assert_eq!(before, fs::read(store.path()).unwrap());
        assert!(!paths.keys_dir().exists());
        assert!(!paths.home().join("secrets.json").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn legacy_import_is_non_destructive_and_only_when_store_empty() {
        let (_temp, paths, store) = fixture();
        let old = generate().unwrap();
        fs::create_dir_all(paths.keys_dir()).unwrap();
        let cert = paths.keys_dir().join("ca.pem");
        let key = paths.keys_dir().join("ca-key.pem");
        fs::write(&cert, &old.certificate).unwrap();
        fs::write(&key, old.private.as_bytes()).unwrap();
        let pair = resolve(&store, &paths, &NetdRuntimeConfig::default()).unwrap();
        assert_eq!(pair.certificate, old.certificate);
        assert_eq!(pair.private, old.private);
        assert_eq!(fs::read_to_string(&cert).unwrap(), old.certificate);
        assert_eq!(fs::read(&key).unwrap(), old.private.as_bytes());
        fs::write(&key, "bad legacy material, ignored after import").unwrap();
        assert_eq!(
            resolve(&store, &paths, &NetdRuntimeConfig::default())
                .unwrap()
                .certificate,
            old.certificate
        );
    }

    #[test]
    fn partial_malformed_and_mismatched_stores_fail_without_mutation() {
        for variant in 0..4 {
            let (_temp, paths, store) = fixture();
            let pair = generate().unwrap();
            let certificate = if variant == 2 {
                "malformed".into()
            } else {
                pair.certificate
            };
            store
                .put(
                    &SecretScope::Home,
                    &SecretName::new(CERTIFICATE).unwrap(),
                    Secret::Plain(SecretBytes::new(certificate.into_bytes())),
                )
                .unwrap();
            if variant != 0 {
                let key = if variant == 3 {
                    generate().unwrap().private
                } else {
                    pair.private
                };
                store
                    .put(
                        &SecretScope::Home,
                        &SecretName::new(PRIVATE).unwrap(),
                        Secret::Plain(key),
                    )
                    .unwrap();
            }
            if variant == 1 {
                store
                    .delete(&SecretScope::Home, &SecretName::new(CERTIFICATE).unwrap())
                    .unwrap();
            }
            let before = fs::read(store.path()).unwrap();
            assert!(resolve(&store, &paths, &NetdRuntimeConfig::default()).is_err());
            assert_eq!(fs::read(store.path()).unwrap(), before);
        }
    }

    #[test]
    fn operator_import_is_idempotent_and_rejects_conflicts() {
        let (temp, paths, store) = fixture();
        let pair = generate().unwrap();
        let cert = temp.path().join("operator.pem");
        let key = temp.path().join("operator-key.pem");
        fs::write(&cert, &pair.certificate).unwrap();
        fs::write(&key, pair.private.as_bytes()).unwrap();
        let config = NetdRuntimeConfig::default().with_tls_ca(&cert, &key);
        assert_eq!(
            resolve(&store, &paths, &config).unwrap().certificate,
            pair.certificate
        );
        let before = fs::read(store.path()).unwrap();
        resolve(&store, &paths, &config).unwrap();
        let other = generate().unwrap();
        fs::write(&cert, &other.certificate).unwrap();
        fs::write(&key, other.private.as_bytes()).unwrap();
        assert!(resolve(&store, &paths, &config)
            .unwrap_err()
            .to_string()
            .contains("conflicts"));
        fs::write(&key, "malformed").unwrap();
        assert!(resolve(&store, &paths, &config).is_err());
        assert_eq!(before, fs::read(store.path()).unwrap());
    }

    #[test]
    fn strict_pem_constraints_and_validity_on_actual_import_files() {
        let (temp, paths, store) = fixture();
        let cert = temp.path().join("import.pem");
        let key = temp.path().join("import-key.pem");
        let config = NetdRuntimeConfig::default().with_tls_ca(&cert, &key);
        let pair = generate().unwrap();
        for (certificate, private) in [
            (
                format!("{}garbage", pair.certificate),
                pair.private.as_str().unwrap().to_owned(),
            ),
            (
                format!("{}{}", pair.certificate, pair.certificate),
                pair.private.as_str().unwrap().to_owned(),
            ),
            (
                format!("garbage{}", pair.certificate),
                pair.private.as_str().unwrap().to_owned(),
            ),
            (
                pair.certificate
                    .replace("END CERTIFICATE", "END PRIVATE KEY"),
                pair.private.as_str().unwrap().to_owned(),
            ),
            (
                pair.certificate.clone(),
                format!("{}garbage", pair.private.as_str().unwrap()),
            ),
            (
                pair.certificate.clone(),
                format!(
                    "{}{}",
                    pair.private.as_str().unwrap(),
                    pair.private.as_str().unwrap()
                ),
            ),
        ] {
            fs::write(&cert, certificate).unwrap();
            fs::write(&key, private).unwrap();
            assert!(resolve(&store, &paths, &config).is_err());
            assert!(!store.path().exists());
        }
        for variant in ["leaf", "usage", "expired", "future", "absent-usage"] {
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["test.invalid".into()]).unwrap();
            if variant != "leaf" {
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            }
            params.key_usages = if variant == "usage" {
                vec![rcgen::KeyUsagePurpose::DigitalSignature]
            } else if variant == "absent-usage" {
                vec![]
            } else {
                vec![rcgen::KeyUsagePurpose::KeyCertSign]
            };
            if variant == "expired" {
                params.not_before = rcgen::date_time_ymd(2000, 1, 1);
                params.not_after = rcgen::date_time_ymd(2001, 1, 1);
            }
            if variant == "future" {
                params.not_before = rcgen::date_time_ymd(2090, 1, 1);
            }
            fs::write(&cert, params.self_signed(&key_pair).unwrap().pem()).unwrap();
            fs::write(&key, key_pair.serialize_pem()).unwrap();
            if variant == "absent-usage" {
                resolve(&store, &paths, &config).unwrap();
            } else {
                assert!(resolve(&store, &paths, &config).is_err(), "{variant}");
                assert!(!store.path().exists());
            }
        }
    }

    #[test]
    fn partial_or_invalid_legacy_and_partial_operator_do_not_create_store() {
        let (_temp, paths, store) = fixture();
        fs::create_dir_all(paths.keys_dir()).unwrap();
        fs::write(paths.keys_dir().join("ca.pem"), "malformed").unwrap();
        assert!(resolve(&store, &paths, &NetdRuntimeConfig::default()).is_err());
        fs::write(paths.keys_dir().join("ca-key.pem"), "malformed").unwrap();
        assert!(resolve(&store, &paths, &NetdRuntimeConfig::default()).is_err());
        let config = NetdRuntimeConfig {
            tls_ca_cert: Some(paths.keys_dir().join("ca.pem")),
            ..NetdRuntimeConfig::default()
        };
        assert!(resolve(&store, &paths, &config).is_err());
        assert!(!store.path().exists());
    }

    #[test]
    fn concurrent_processes_share_one_pair() {
        let (_temp, paths, store) = fixture();
        let executable = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..6)
            .map(|_| {
                std::process::Command::new(&executable)
                    .args([
                        "--exact",
                        "host::certificates::tests::ca_process",
                        "--nocapture",
                    ])
                    .env("SILO_TEST_TLS_CA_HOME", store.path().parent().unwrap())
                    .env("SILO_TEST_TLS_RUNTIME_HOME", paths.home())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let final_pair = resolve(&store, &paths, &NetdRuntimeConfig::default()).unwrap();
        let mut observations = 0;
        for entry in fs::read_dir(store.path().parent().unwrap()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().starts_with("winner-") {
                observations += 1;
                assert_eq!(
                    fs::read_to_string(entry.path()).unwrap(),
                    final_pair.certificate
                );
            }
        }
        assert_eq!(observations, 6);
        validate(final_pair).unwrap();
    }

    #[test]
    fn concurrent_operator_imports_recheck_under_same_lock() {
        let (temp, paths, store) = fixture();
        let pair = generate().unwrap();
        let cert = temp.path().join("operator.pem");
        let key = temp.path().join("operator-key.pem");
        fs::write(&cert, &pair.certificate).unwrap();
        fs::write(&key, pair.private.as_bytes()).unwrap();
        let executable = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..6)
            .map(|_| {
                std::process::Command::new(&executable)
                    .args([
                        "--exact",
                        "host::certificates::tests::ca_process",
                        "--nocapture",
                    ])
                    .env("SILO_TEST_TLS_CA_HOME", store.path().parent().unwrap())
                    .env("SILO_TEST_TLS_RUNTIME_HOME", paths.home())
                    .env("SILO_TEST_TLS_IMPORT_CERT", &cert)
                    .env("SILO_TEST_TLS_IMPORT_KEY", &key)
                    .spawn()
                    .unwrap()
            })
            .collect();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let resolved = resolve(&store, &paths, &NetdRuntimeConfig::default()).unwrap();
        assert_eq!(resolved.certificate, pair.certificate);
        assert_eq!(resolved.private, pair.private);
    }

    #[test]
    fn ca_process() {
        let Some(home) = std::env::var_os("SILO_TEST_TLS_CA_HOME") else {
            return;
        };
        let paths = LocalPaths::new(std::env::var_os("SILO_TEST_TLS_RUNTIME_HOME").unwrap());
        let store = FileStore::new(&home);
        let mut config = NetdRuntimeConfig::default();
        if let (Some(cert), Some(key)) = (
            std::env::var_os("SILO_TEST_TLS_IMPORT_CERT"),
            std::env::var_os("SILO_TEST_TLS_IMPORT_KEY"),
        ) {
            config = config.with_tls_ca(cert, key);
        }
        let pair = resolve(&store, &paths, &config).unwrap();
        fs::write(
            std::path::Path::new(&home).join(format!("winner-{}", std::process::id())),
            pair.certificate,
        )
        .unwrap();
    }
}
