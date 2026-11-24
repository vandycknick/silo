//! Per-registry TLS trust, kept apart from the prefix access policy.
//!
//! ```text
//! image reference --policy.check--> admitted --registry()--> RegistryHost
//!                                                               |
//!                     configured? RegistryCa client pair  <-----+
//!                     otherwise   shared system client pair
//! ```
//!
//! The pair selected for a reference serves every request of that operation,
//! so token realms and blob redirects on other hosts verify against the same
//! roots. Hostname verification always stays on.
use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use oci_client::Reference;

use crate::digest::Sha256Digest;
use crate::error::RegistryClientError;
use crate::registry::RegistryClient;
use crate::{OciError, OciResult, RegistryPolicy};

const DOCKER_HUB: &str = "docker.io";
const DOCKER_HUB_LEGACY: &str = "index.docker.io";
const HTTPS_PORT: u16 = 443;

/// A canonical registry authority: lowercase host, plus the port unless it is
/// the HTTPS default. `index.docker.io` folds to `docker.io`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistryHost(String);

impl RegistryHost {
    /// Parses `host[:port]`. Anything that is not a bare authority (scheme,
    /// path, userinfo, wildcard, whitespace, IPv6 literal) is rejected.
    pub fn parse(value: &str) -> OciResult<Self> {
        let invalid = |message: &str| OciError::InvalidRegistryHost {
            value: value.to_string(),
            message: message.to_string(),
        };
        let (host, port) = match value.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        };
        if host.is_empty() {
            return Err(invalid("the host is empty"));
        }
        let label_ok = |label: &str| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        };
        if !host.split('.').all(label_ok) {
            return Err(invalid(
                "expected host[:port] with a DNS name, localhost or an IPv4 address",
            ));
        }
        let port = match port {
            None => None,
            Some(port) => {
                if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid("the port must be a number from 1 to 65535"));
                }
                match port.parse::<u16>() {
                    Ok(0) | Err(_) => {
                        return Err(invalid("the port must be a number from 1 to 65535"))
                    }
                    Ok(HTTPS_PORT) => None,
                    Ok(port) => Some(port),
                }
            }
        };
        let host = host.to_ascii_lowercase();
        Ok(Self(match port {
            Some(port) => format!("{host}:{port}"),
            None if host == DOCKER_HUB_LEGACY => DOCKER_HUB.to_string(),
            None => host,
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for RegistryHost {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated extra CA bundle for one registry. It owns the client pair that
/// was built to validate it, so the bundle is parsed once per configuration
/// load and never read again.
#[derive(Clone)]
pub struct RegistryCa {
    path: PathBuf,
    sha256: Sha256Digest,
    client: RegistryClient,
}

impl RegistryCa {
    /// Reads and validates the PEM bundle at `path` for `registry`. The path
    /// must already be resolved; a relative path would depend on the working
    /// directory.
    pub fn load(registry: &RegistryHost, path: &Path) -> OciResult<Self> {
        let read_error = |error: std::io::Error| OciError::RegistryCaRead {
            registry: registry.to_string(),
            path: path.to_path_buf(),
            error,
        };
        // A FIFO or device would block or never end; only regular files (and
        // symlinks to them) are certificate bundles.
        if !std::fs::metadata(path).map_err(read_error)?.is_file() {
            return Err(read_error(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file",
            )));
        }
        let pem = std::fs::read(path).map_err(read_error)?;
        Self::from_pem(registry, path, &pem)
    }

    /// Validates PEM bytes already read from `path`.
    pub fn from_pem(registry: &RegistryHost, path: &Path, pem: &[u8]) -> OciResult<Self> {
        let invalid = |source: RegistryClientError| OciError::RegistryCaInvalid {
            registry: registry.to_string(),
            path: path.to_path_buf(),
            source: Box::new(source),
        };
        let roots =
            reqwest::Certificate::from_pem_bundle(pem).map_err(|error| invalid(error.into()))?;
        if roots.is_empty() {
            return Err(OciError::RegistryCaEmpty {
                registry: registry.to_string(),
                path: path.to_path_buf(),
            });
        }
        Ok(Self {
            path: path.to_path_buf(),
            sha256: Sha256Digest::from_bytes(pem),
            client: RegistryClient::with_extra_roots(pem, roots).map_err(invalid)?,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `sha256:<hex>` of the bundle file as loaded.
    pub fn sha256(&self) -> String {
        self.sha256.to_string()
    }
}

/// Identity is the resolved path and the bundle content digest. Certificate
/// bytes are deliberately absent from both `Debug` and equality.
impl Debug for RegistryCa {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryCa")
            .field("path", &self.path)
            .field("sha256", &self.sha256.to_string())
            .finish()
    }
}

impl PartialEq for RegistryCa {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.sha256 == other.sha256
    }
}

impl Eq for RegistryCa {}

/// Extra TLS roots keyed by the registry named in an image reference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryTrust(BTreeMap<RegistryHost, RegistryCa>);

impl RegistryTrust {
    /// Two entries that normalise to the same registry are an error, never a
    /// silent overwrite.
    pub fn new(entries: impl IntoIterator<Item = (RegistryHost, RegistryCa)>) -> OciResult<Self> {
        let mut trust = BTreeMap::new();
        for (registry, ca) in entries {
            if trust.contains_key(&registry) {
                return Err(OciError::DuplicateRegistry {
                    registry: registry.to_string(),
                });
            }
            trust.insert(registry, ca);
        }
        Ok(Self(trust))
    }

    pub fn get(&self, registry: &RegistryHost) -> Option<&RegistryCa> {
        self.0.get(registry)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RegistryHost, &RegistryCa)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Everything that governs registry traffic: the prefix access policy, the
/// per-registry trust, and the HTTP clients that enforce that trust.
///
/// Clones share the clients, so one loaded configuration keeps one connection
/// pool and token cache per registry trust for as long as it lives.
#[derive(Clone, Default)]
pub struct ImageRegistryConfig {
    policy: RegistryPolicy,
    trust: RegistryTrust,
    /// Built on the first request to a registry without its own CA. Runtime
    /// state only: it takes no part in `Debug` or equality.
    system_client: Arc<Mutex<Option<RegistryClient>>>,
}

impl ImageRegistryConfig {
    pub fn new(policy: RegistryPolicy, trust: RegistryTrust) -> Self {
        Self {
            policy,
            trust,
            system_client: Arc::default(),
        }
    }

    pub fn policy(&self) -> &RegistryPolicy {
        &self.policy
    }

    pub fn trust(&self) -> &RegistryTrust {
        &self.trust
    }

    /// The only way to obtain a client for `reference`: the access policy is
    /// checked first, then the client pair is chosen by the registry the
    /// reference names. A CA entry never grants access by itself.
    pub(crate) fn admit(&self, reference: &Reference) -> OciResult<RegistryClient> {
        self.policy.check(reference)?;
        if let Some(ca) = self.ca_for(reference) {
            return Ok(ca.client.clone());
        }
        let mut system = self
            .system_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(client) = system.as_ref() {
            return Ok(client.clone());
        }
        let client = RegistryClient::system().map_err(|source| OciError::RegistryClientBuild {
            source: Box::new(source),
        })?;
        *system = Some(client.clone());
        Ok(client)
    }

    /// The CA entry of the registry named by `reference`, if one is configured.
    /// Matching is by the logical registry, never by a redirect target.
    pub(crate) fn ca_for(&self, reference: &Reference) -> Option<&RegistryCa> {
        let registry = RegistryHost::parse(reference.registry()).ok()?;
        self.trust.get(&registry)
    }
}

impl From<RegistryPolicy> for ImageRegistryConfig {
    fn from(policy: RegistryPolicy) -> Self {
        Self::new(policy, RegistryTrust::default())
    }
}

impl Debug for ImageRegistryConfig {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImageRegistryConfig")
            .field("policy", &self.policy)
            .field("trust", &self.trust)
            .finish()
    }
}

impl PartialEq for ImageRegistryConfig {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy && self.trust == other.trust
    }
}

impl Eq for ImageRegistryConfig {}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::str::FromStr;

    use oci_client::Reference;

    use crate::registry_config::{ImageRegistryConfig, RegistryCa, RegistryHost, RegistryTrust};
    use crate::{OciError, RegistryAction, RegistryPolicy, RegistryRule};

    // Two unrelated self-signed P-256 CA certificates (CN silo-unit-test-ca-a
    // and -b, valid until 2126), made with `openssl ecparam -name prime256v1
    // -genkey` and `openssl req -x509 -new -days 36500`. The private keys were
    // discarded; nothing trusts these outside the tests below.
    const CA_A: &str = "-----BEGIN CERTIFICATE-----
MIIBWDCB/qADAgECAgkA51E7pzVjJPwwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwT
c2lsby11bml0LXRlc3QtY2EtYTAgFw0yNjExMjQxMjMzNTNaGA8yMTI2MTAzMTEy
MzM1M1owHjEcMBoGA1UEAwwTc2lsby11bml0LXRlc3QtY2EtYTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABPC6Om5ZX3HCVcoTwFG8O77DJZujH3Xk67WXEYqk6o6R
28xL8W4aS05dEn5wROmgu0rOlxoX46MQMhiqdJsvHyujIzAhMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQCRlPs//ffA
esRds0WmZ2yHq2izrpASQ1kKF2bePi2DnQIhAOcuoJWZ0+LdF2AWSoxgLkSoMkQB
ajyKdcq+ueHF6794
-----END CERTIFICATE-----
";
    const CA_B: &str = "-----BEGIN CERTIFICATE-----
MIIBVzCB/qADAgECAgkAng1IO/2Hj5EwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwT
c2lsby11bml0LXRlc3QtY2EtYjAgFw0yNjExMjQxMjMzNTNaGA8yMTI2MTAzMTEy
MzM1M1owHjEcMBoGA1UEAwwTc2lsby11bml0LXRlc3QtY2EtYjBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABP0ehW61AU0x+IBpFr+BoaZWCzmIBm/MRINEvd2sRVr2
92F7FqYpe6ZPbj45pLZ6ZhbVUwnpnV/eWUixFTVQBxOjIzAhMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIF/oPDHr6afX
CSrZcUjLrxgu0J6lURVzbdRp5a8tsFNIAiEAjE7XeApDr0I/x8zYnuQ2/YOxV3AN
5hSg/yL4plUrJ6Q=
-----END CERTIFICATE-----
";

    fn host(value: &str) -> RegistryHost {
        RegistryHost::parse(value).expect("registry host")
    }

    fn reference(value: &str) -> Reference {
        Reference::from_str(value).expect("reference")
    }

    /// Every fixture entry gets its own path so equal bundles stay distinguishable.
    fn ca(registry: &str, pem: &str) -> RegistryCa {
        RegistryCa::from_pem(
            &host(registry),
            Path::new(&format!("/fixture/{registry}.pem")),
            pem.as_bytes(),
        )
        .expect("valid CA bundle")
    }

    fn pem_error(pem: &[u8]) -> OciError {
        RegistryCa::from_pem(&host("localhost:5443"), Path::new("/fixture/ca.pem"), pem)
            .expect_err("bundle must be rejected")
    }

    #[test]
    fn registry_hosts_normalise_case_default_port_and_docker_hub() {
        for (input, expected) in [
            ("registry.example", "registry.example"),
            ("REGISTRY.Example", "registry.example"),
            ("registry.example:443", "registry.example"),
            ("registry.example:0443", "registry.example"),
            ("Registry.Example:5443", "registry.example:5443"),
            ("registry.example:05443", "registry.example:5443"),
            ("localhost", "localhost"),
            ("localhost:5000", "localhost:5000"),
            ("127.0.0.1:5000", "127.0.0.1:5000"),
            ("docker.io", "docker.io"),
            ("index.docker.io", "docker.io"),
            ("INDEX.docker.io:443", "docker.io"),
            ("index.docker.io:5000", "index.docker.io:5000"),
            ("registry-1.docker.io", "registry-1.docker.io"),
            ("my-registry.internal:65535", "my-registry.internal:65535"),
        ] {
            let parsed = host(input);
            assert_eq!(parsed.as_str(), expected, "{input}");
            assert_eq!(parsed.to_string(), expected, "{input}");
        }
    }

    #[test]
    fn registry_hosts_reject_everything_that_is_not_a_bare_authority() {
        for input in [
            "",
            ":5000",
            "registry.example:",
            "registry.example:0",
            "registry.example:00",
            "registry.example:65536",
            "registry.example:port",
            "registry.example:+80",
            "registry.example:5000:5000",
            "https://registry.example",
            "registry.example/team",
            "registry.example/",
            "user@registry.example",
            "user:secret@registry.example",
            "registry.example?x=1",
            "registry.example#x",
            " registry.example",
            "registry.example ",
            "registry .example",
            "registry.example\n",
            "*.registry.example",
            "*",
            "registry.example.",
            ".registry.example",
            "registry..example",
            "-registry.example",
            "registry-.example",
            "registry_one.example",
            "r\u{e9}gistry.example",
            "[::1]:5000",
            "::1",
        ] {
            assert!(
                matches!(
                    RegistryHost::parse(input),
                    Err(OciError::InvalidRegistryHost { .. })
                ),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn duplicate_registries_after_normalisation_are_rejected() {
        for (first, second) in [
            ("localhost:5443", "localhost:5443"),
            ("registry.example", "registry.example:443"),
            ("registry.example", "REGISTRY.example"),
            ("docker.io", "index.docker.io"),
        ] {
            let error = RegistryTrust::new([
                (host(first), ca(first, CA_A)),
                (host(second), ca(second, CA_B)),
            ])
            .expect_err("duplicate registry");
            assert!(
                matches!(&error, OciError::DuplicateRegistry { registry } if registry == host(first).as_str()),
                "{first} {second}: {error}"
            );
        }
        let distinct = RegistryTrust::new([
            (host("localhost:5443"), ca("localhost:5443", CA_A)),
            (host("localhost:5444"), ca("localhost:5444", CA_A)),
            (host("localhost"), ca("localhost", CA_B)),
        ])
        .unwrap();
        assert_eq!(distinct.iter().count(), 3);
    }

    fn trusting(entries: &[(&str, &str)], policy: RegistryPolicy) -> ImageRegistryConfig {
        ImageRegistryConfig::new(
            policy,
            RegistryTrust::new(
                entries
                    .iter()
                    .map(|(registry, pem)| (host(registry), ca(registry, pem))),
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_reference_selects_only_the_ca_of_the_registry_it_names() {
        let config = trusting(
            &[
                ("localhost:5443", CA_A),
                ("registry.example", CA_B),
                ("docker.io", CA_A),
            ],
            RegistryPolicy::default(),
        );
        let a = config.trust().get(&host("localhost:5443")).unwrap();
        let b = config.trust().get(&host("registry.example")).unwrap();
        let hub = config.trust().get(&host("docker.io")).unwrap();
        for (image, expected) in [
            ("localhost:5443/team/app:v1", Some(a)),
            ("LOCALHOST:5443/team/app:v1", Some(a)),
            ("localhost:05443/team/app", Some(a)),
            ("registry.example/team/app", Some(b)),
            ("registry.example:443/team/app", Some(b)),
            (
                "registry.example/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                Some(b),
            ),
            ("docker.io/library/alpine:3.21", Some(hub)),
            ("index.docker.io/library/alpine:3.21", Some(hub)),
            ("alpine", Some(hub)),
            ("localhost:5444/team/app", None),
            ("localhost/team/app", None),
            ("registry.example:5443/team/app", None),
            ("sub.registry.example/team/app", None),
            ("registry.example.org/team/app", None),
            ("xregistry.example/team/app", None),
            ("registry-1.docker.io/library/alpine", None),
            ("ghcr.io/org/app", None),
        ] {
            let selected = config.ca_for(&reference(image));
            assert_eq!(selected, expected, "{image}");
        }
        let short_names = RegistryPolicy::new(
            RegistryAction::Allow,
            vec!["localhost:5443".into(), "ghcr.io".into()],
            Vec::new(),
        )
        .unwrap();
        let candidates = short_names.candidates("team/app").unwrap();
        assert_eq!(config.ca_for(&candidates[0]), Some(a));
        assert_eq!(config.ca_for(&candidates[1]), None);
    }

    #[test]
    fn a_ca_entry_never_changes_prefix_rule_decisions() {
        let policy = || {
            RegistryPolicy::new(
                RegistryAction::Deny,
                vec!["docker.io".into()],
                vec![
                    RegistryRule::new("localhost:5443/team", RegistryAction::Allow),
                    RegistryRule::new("registry.example", RegistryAction::Allow),
                    RegistryRule::new("registry.example/private", RegistryAction::Deny),
                ],
            )
            .unwrap()
        };
        let plain = ImageRegistryConfig::from(policy());
        let with_ca = trusting(
            &[("localhost:5443", CA_A), ("registry.example", CA_B)],
            policy(),
        );
        for (image, allowed) in [
            ("localhost:5443/team/app", true),
            ("localhost:5443/other/app", false),
            ("localhost:5443/teammate/app", false),
            ("registry.example/public/app", true),
            ("registry.example/private/app", false),
            // Trust keys normalise the default port; prefix rules still match
            // the reference text, so the `/private` deny does not see `:443`.
            ("registry.example:443/public/app", true),
            ("registry.example:443/private/app", true),
            ("ghcr.io/org/app", false),
        ] {
            let image = reference(image);
            for config in [&plain, &with_ca] {
                let decision = config.policy().check(&image);
                assert_eq!(decision.is_ok(), allowed, "{image}");
                if !allowed {
                    assert!(matches!(
                        config.admit(&image),
                        Err(OciError::RegistryPolicyDenied { .. })
                    ));
                }
            }
            if allowed {
                assert!(with_ca.admit(&image).is_ok(), "{image}");
            }
        }
    }

    #[test]
    fn pem_bundles_load_one_or_many_certificates_through_the_real_client_builders() {
        let one = ca("localhost:5443", CA_A);
        let two = ca("localhost:5443", &format!("{CA_A}{CA_B}"));
        let commented = ca(
            "localhost:5443",
            &format!("# rotated 2026\n\n{CA_B}\ntrailing notes\n{CA_A}\n"),
        );
        assert_ne!(one, two);
        assert_ne!(two, commented);
        assert_eq!(one, ca("localhost:5443", CA_A));
        assert_eq!(one.path(), Path::new("/fixture/localhost:5443.pem"));
        assert!(one.sha256().starts_with("sha256:"));
        assert_eq!(one.sha256().len(), "sha256:".len() + 64);
    }

    #[test]
    fn bundles_without_a_usable_certificate_fail_closed() {
        for empty in [
            &b""[..],
            b"\n\n",
            b"this file holds no certificate at all\n",
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            // DER is not accepted: the setting is a PEM bundle.
            &[0x30, 0x82, 0x01, 0x58, 0x30, 0x81, 0xfe, 0xa0][..],
        ] {
            let error = pem_error(empty);
            assert!(
                matches!(
                    &error,
                    OciError::RegistryCaEmpty { registry, path }
                        if registry == "localhost:5443" && path == Path::new("/fixture/ca.pem")
                ),
                "{error}"
            );
            assert_eq!(
                error.to_string(),
                "images.registries[\"localhost:5443\"].ca: /fixture/ca.pem contains no PEM certificates"
            );
        }

        let truncated = &CA_A[..CA_A.len() / 2];
        let bad_base64 = CA_A.replace("MIIBWDCB", "!!!!!!!!");
        let not_a_certificate = concat!(
            "-----BEGIN CERTIFICATE-----\n",
            "bm90IGEgY2VydGlmaWNhdGU=\n",
            "-----END CERTIFICATE-----\n"
        );
        let good_then_bad = format!("{CA_A}{not_a_certificate}");
        for invalid in [
            truncated,
            bad_base64.as_str(),
            not_a_certificate,
            good_then_bad.as_str(),
        ] {
            let error = pem_error(invalid.as_bytes());
            assert!(
                matches!(
                    &error,
                    OciError::RegistryCaInvalid { registry, path, .. }
                        if registry == "localhost:5443" && path == Path::new("/fixture/ca.pem")
                ),
                "{invalid:?}: {error}"
            );
            assert_eq!(
                error.to_string(),
                "images.registries[\"localhost:5443\"].ca: invalid PEM certificate bundle /fixture/ca.pem"
            );
            assert!(std::error::Error::source(&error).is_some());
        }
    }

    #[test]
    fn ca_files_load_from_real_paths_and_report_unreadable_ones() {
        let temp = tempfile::tempdir().unwrap();
        let registry = host("localhost:5443");
        let file = temp.path().join("ca.pem");
        std::fs::write(&file, CA_A).unwrap();
        let loaded = RegistryCa::load(&registry, &file).unwrap();
        assert_eq!(loaded.path(), file);
        assert_eq!(
            loaded.sha256(),
            RegistryCa::from_pem(&registry, &file, CA_A.as_bytes())
                .unwrap()
                .sha256()
        );

        let link = temp.path().join("link.pem");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(
            RegistryCa::load(&registry, &link).unwrap().sha256(),
            loaded.sha256()
        );

        let missing = temp.path().join("missing.pem");
        for unreadable in [missing.as_path(), temp.path()] {
            let error = RegistryCa::load(&registry, unreadable).expect_err("unreadable CA");
            assert!(
                matches!(
                    &error,
                    OciError::RegistryCaRead { registry, path, .. }
                        if registry == "localhost:5443" && path == unreadable
                ),
                "{error}"
            );
            assert!(
                error.to_string().starts_with(&format!(
                    "images.registries[\"localhost:5443\"].ca: cannot read {}: ",
                    unreadable.display()
                )),
                "{error}"
            );
        }

        let empty = temp.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        assert!(matches!(
            RegistryCa::load(&registry, &empty),
            Err(OciError::RegistryCaEmpty { .. })
        ));
    }

    #[test]
    fn identity_follows_bundle_bytes_and_debug_never_prints_them() {
        let temp = tempfile::tempdir().unwrap();
        let registry = host("localhost:5443");
        let file = temp.path().join("ca.pem");
        let load = || {
            ImageRegistryConfig::new(
                RegistryPolicy::default(),
                RegistryTrust::new([(
                    registry.clone(),
                    RegistryCa::load(&registry, &file).unwrap(),
                )])
                .unwrap(),
            )
        };
        std::fs::write(&file, CA_A).unwrap();
        let first = load();
        assert_eq!(first, load());
        std::fs::write(&file, CA_B).unwrap();
        let rotated = load();
        assert_ne!(first, rotated);
        assert_ne!(format!("{first:?}"), format!("{rotated:?}"));
        assert_ne!(first, ImageRegistryConfig::default());

        // The first generation keeps the bundle it loaded.
        let image = reference("localhost:5443/team/app");
        assert_ne!(
            first.ca_for(&image).unwrap().sha256(),
            rotated.ca_for(&image).unwrap().sha256()
        );

        let debug = format!("{rotated:?}");
        assert!(debug.contains("localhost:5443"), "{debug}");
        assert!(debug.contains(&file.display().to_string()), "{debug}");
        assert!(
            debug.contains(&rotated.ca_for(&image).unwrap().sha256()),
            "{debug}"
        );
        for secretive in ["BEGIN CERTIFICATE", "MIIBVzCB", "MIIBWDCB"] {
            assert!(!debug.contains(secretive), "{debug}");
        }
    }

    #[test]
    fn clones_share_one_client_set_and_unconfigured_registries_use_system_trust() {
        let config = trusting(&[("localhost:5443", CA_A)], RegistryPolicy::default());
        let clone = config.clone();
        assert!(std::sync::Arc::ptr_eq(
            &config.system_client,
            &clone.system_client
        ));
        assert!(config.system_client.lock().unwrap().is_none());
        config
            .admit(&reference("localhost:5443/team/app"))
            .expect("configured registry client");
        assert!(
            config.system_client.lock().unwrap().is_none(),
            "a configured registry must not build or use the system pair"
        );
        assert!(ImageRegistryConfig::default().trust().is_empty());
    }
}
