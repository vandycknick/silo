use std::fs;
use std::process::Command;

use serde_json::{json, Value};
use silo_secrets::{
    FileStore, MachineScopeId, OAuthSecret, Secret, SecretBytes, SecretError, SecretField,
    SecretName, SecretScope, SecretStore, SecretStoreDescriptor,
};

fn name(value: &str) -> SecretName {
    SecretName::new(value).unwrap()
}
fn plain(value: &str) -> Secret {
    Secret::Plain(SecretBytes::new(value.as_bytes().to_vec()))
}
fn value(store: &FileStore, scope: &SecretScope, key: &str) -> String {
    store
        .get(scope, &SecretName::legacy(key))
        .unwrap()
        .unwrap()
        .project(SecretField::Value)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn names_scopes_and_deserialization_validate_new_addresses() {
    for key in [
        "",
        ".hidden",
        "a..b",
        "a.",
        "../bad",
        "white space",
        "ümlaut",
    ] {
        assert!(SecretName::new(key).is_err(), "{key}");
        assert!(serde_json::from_value::<SecretName>(json!(key)).is_err());
    }
    for key in ["A", "a-b.c_d.123", "silo.ssh_ca.private_key"] {
        assert!(SecretName::new(key).is_ok());
    }
    for id in [
        "",
        "../",
        "0123456789abcdef0123456789abcdeF",
        "0123456789abcdef0123456789abcdef0",
    ] {
        assert!(MachineScopeId::new(id).is_err());
    }
    let id = MachineScopeId::new("0123456789abcdef0123456789abcdef").unwrap();
    assert_eq!(
        serde_json::from_value::<MachineScopeId>(json!(id.as_str())).unwrap(),
        id
    );
}

#[test]
fn home_machine_round_trips_and_missing_machine_rules() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().join("home"));
    let home = SecretScope::Home;
    let id = MachineScopeId::new("0123456789abcdef0123456789abcdef").unwrap();
    let machine = SecretScope::Machine { id };
    assert!(matches!(
        store.get(&machine, &name("key")),
        Err(SecretError::NotFound)
    ));
    assert!(matches!(
        store.put(&machine, &name("key"), plain("bad")),
        Err(SecretError::NotFound)
    ));
    assert!(matches!(store.list(&machine), Err(SecretError::NotFound)));
    assert!(matches!(
        store.delete(&machine, &name("key")),
        Err(SecretError::NotFound)
    ));
    assert!(matches!(
        store.delete_scope(&machine),
        Err(SecretError::NotFound)
    ));
    assert!(!store.scope_path(&machine).parent().unwrap().exists());
    fs::create_dir_all(store.scope_path(&machine).parent().unwrap()).unwrap();
    store.put(&home, &name("key"), plain("home\n☃")).unwrap();
    store.put(&machine, &name("key"), plain("machine")).unwrap();
    let oauth = Secret::OAuth(OAuthSecret {
        provider: Some("provider".into()),
        access_token: SecretBytes::new(b"access".to_vec()),
        refresh_token: SecretBytes::new(b"refresh".to_vec()),
        expires_at: "2026-09-30T01:02:03Z".parse().unwrap(),
        account_id: None,
        created_at: None,
        updated_at: None,
    });
    store.put(&machine, &name("oauth"), oauth.clone()).unwrap();
    assert_eq!(store.get(&machine, &name("oauth")).unwrap(), Some(oauth));
    let machine_json: Value =
        serde_json::from_slice(&fs::read(store.scope_path(&machine)).unwrap()).unwrap();
    assert!(machine_json["oauth"].get("created_at").is_none());
    assert_eq!(machine_json["oauth"]["provider"], "provider");
    assert_eq!(value(&store, &home, "key"), "home\n☃");
    assert_eq!(value(&store, &machine, "key"), "machine");
    assert_eq!(store.list_scopes().unwrap().len(), 2);
    assert_eq!(store.list(&machine).unwrap()[0].name, name("key"));
    assert!(store.delete(&machine, &name("key")).unwrap());
    assert!(!store.delete(&machine, &name("key")).unwrap());
    store.delete_scope(&machine).unwrap();
    store.delete_scope(&machine).unwrap();
    assert_eq!(store.list_scopes().unwrap(), vec![home.clone()]);
    assert!(store.scope_path(&machine).parent().unwrap().exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for scope in [&home, &machine] {
            assert_eq!(
                fs::metadata(store.scope_path(scope).parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(store.path().with_file_name("secrets.json.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    store.delete_scope(&home).unwrap();
    assert!(store.list_scopes().unwrap().is_empty());
    assert!(store.get(&home, &name("key")).unwrap().is_none());
}

#[test]
fn file_store_descriptor_is_object_safe_and_preserves_explicit_filename() {
    let dir = tempfile::tempdir().unwrap();
    for store in [
        FileStore::new(dir.path()),
        FileStore::with_store_file(dir.path().join("custom-credentials.json")).unwrap(),
    ] {
        let erased: &dyn SecretStore = &store;
        assert_eq!(
            erased.descriptor(),
            Some(SecretStoreDescriptor::File {
                store_file: store.path().to_path_buf()
            })
        );
    }
}

#[test]
fn stable_error_wire_codes() {
    for (error, code) in [
        (SecretError::NotFound, "not_found"),
        (SecretError::ReadOnly, "read_only"),
        (SecretError::Unauthorized("denied".into()), "unauthorized"),
        (
            SecretError::InvalidRequest("invalid".into()),
            "invalid_request",
        ),
        (
            SecretError::ProviderUnavailable("unavailable".into()),
            "provider_unavailable",
        ),
        (
            SecretError::ProviderRejected("rejected".into()),
            "provider_rejected",
        ),
        (SecretError::RateLimited, "rate_limited"),
        (SecretError::Unsupported, "unsupported"),
        (SecretError::Internal("failed".into()), "internal_error"),
    ] {
        assert_eq!(error.wire_code(), code);
    }
}

#[test]
fn legacy_json_values_and_absence_survive_unrelated_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("arbitrary-file.json");
    let original = json!({
        ".old..key": {"type":"plain", "value":"old"},
        "oauth.old.oauth": {"type":"oauth", "access_token":"access", "refresh_token":"refresh", "expires_at":"2026-09-30T01:02:03+00:00"},
        "future": {"opaque": [1,2,3]},
        "oauth.full.oauth": {"type":"oauth", "provider":"other", "access_token":"a", "refresh_token":"r", "expires_at":"2026-09-30T01:02:03Z", "created_at":null, "updated_at":null, "account_id":null}
    });
    fs::write(&file, serde_json::to_vec(&original).unwrap()).unwrap();
    let store = FileStore::with_store_file(&file).unwrap();
    assert_eq!(value(&store, &SecretScope::Home, ".old..key"), "old");
    let Secret::OAuth(o) = store
        .get(&SecretScope::Home, &name("oauth.old.oauth"))
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    assert!(o.provider.is_none() && o.created_at.is_none() && o.updated_at.is_none());
    store
        .put(
            &SecretScope::Home,
            &name("oauth.old.oauth"),
            Secret::OAuth(o),
        )
        .unwrap();
    let full = store
        .get(&SecretScope::Home, &name("oauth.full.oauth"))
        .unwrap()
        .unwrap();
    store
        .put(&SecretScope::Home, &name("oauth.full.oauth"), full)
        .unwrap();
    store
        .put(&SecretScope::Home, &name("new"), plain("new"))
        .unwrap();
    let after: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    for (key, entry) in original.as_object().unwrap() {
        assert_eq!(&after[key], entry);
    }
    // Unknown records are preserved, but listing cannot claim to understand them.
    assert!(store.list(&SecretScope::Home).is_err());
    assert!(store
        .delete(&SecretScope::Home, &SecretName::legacy("future"))
        .unwrap());
    assert!(store
        .list(&SecretScope::Home)
        .unwrap()
        .iter()
        .any(|entry| entry.name.as_str() == ".old..key"));
    assert!(store
        .put(
            &SecretScope::Home,
            &SecretName::legacy(".old..key"),
            plain("new")
        )
        .is_err());
    assert!(store
        .delete(&SecretScope::Home, &SecretName::legacy(".old..key"))
        .unwrap());
}

#[test]
fn projections_redaction_and_non_utf8_rejection() {
    let now = "2026-09-30T01:02:03Z".parse().unwrap();
    let o = Secret::OAuth(OAuthSecret {
        provider: None,
        access_token: SecretBytes::new(b"private-access".to_vec()),
        refresh_token: SecretBytes::new(b"private-refresh".to_vec()),
        expires_at: now,
        account_id: Some("acct".into()),
        created_at: None,
        updated_at: None,
    });
    assert_eq!(o.expires_at(), Some(now));
    assert!(o.project(SecretField::Value).is_none());
    assert_eq!(
        o.project(SecretField::OAuthAccessToken)
            .unwrap()
            .as_str()
            .unwrap(),
        "private-access"
    );
    assert_eq!(
        o.project(SecretField::OAuthExpiresAt)
            .unwrap()
            .as_str()
            .unwrap(),
        "2026-09-30T01:02:03Z"
    );
    assert_eq!(
        o.project(SecretField::OAuthAccountId)
            .unwrap()
            .as_str()
            .unwrap(),
        "acct"
    );
    assert!(!format!("{o:?}").contains("private-"));
    assert_eq!(format!("{:?}", SecretBytes::new(vec![255])), "<redacted>");
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path());
    store.put(&SecretScope::Home, &name("oauth"), o).unwrap();
    let before = fs::read(store.path()).unwrap();
    assert!(store
        .put(
            &SecretScope::Home,
            &name("binary"),
            Secret::Plain(SecretBytes::new(vec![255]))
        )
        .is_err());
    assert_eq!(fs::read(store.path()).unwrap(), before);
    let stored: Value = serde_json::from_slice(&before).unwrap();
    assert!(stored["oauth"].get("provider").is_none());
    assert!(stored["oauth"].get("created_at").is_none());
    assert!(stored["oauth"].get("updated_at").is_none());
    let mut fractional = store
        .get(&SecretScope::Home, &name("oauth"))
        .unwrap()
        .unwrap();
    if let Secret::OAuth(o) = &mut fractional {
        o.expires_at = "2026-09-30T01:02:03.123Z".parse().unwrap();
    }
    assert_eq!(
        fractional
            .project(SecretField::OAuthExpiresAt)
            .unwrap()
            .as_str()
            .unwrap(),
        "2026-09-30T01:02:03.123Z"
    );
}

#[test]
fn pair_transactions_rollback_and_reject_partials() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path());
    let private = name("silo.ssh_ca.private_key");
    let public = name("silo.ssh_ca.public_key");
    let result: Result<(), SecretError> = store.transaction(&SecretScope::Home, |tx| {
        tx.put(&private, plain("private"))?;
        Err(SecretError::InvalidRequest("interrupted".into()))
    });
    assert!(result.is_err());
    assert!(store.get(&SecretScope::Home, &private).unwrap().is_none());
    store
        .put(&SecretScope::Home, &private, plain("partial"))
        .unwrap();
    let before = fs::read(store.path()).unwrap();
    assert!(store
        .transaction(&SecretScope::Home, |tx| {
            let pair = (tx.get(&private)?, tx.get(&public)?);
            match pair {
                (None, None) => {
                    tx.put(&private, plain("p"))?;
                    tx.put(&public, plain("q"))
                }
                (Some(_), Some(_)) => Ok(()),
                _ => Err(SecretError::InvalidRequest("partial CA pair".into())),
            }
        })
        .is_err());
    assert_eq!(fs::read(store.path()).unwrap(), before);
    store
        .transaction(&SecretScope::Home, |tx| {
            tx.put(&private, plain("private"))?;
            tx.put(&public, plain("public"))
        })
        .unwrap();
    assert_eq!(store.list(&SecretScope::Home).unwrap().len(), 2);
}

#[test]
fn interrupted_temp_is_not_truncated_and_malformed_store_is_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path());
    let stale = dir
        .path()
        .join(format!(".secrets.json.tmp.{}.0", std::process::id()));
    fs::write(&stale, "interrupted payload").unwrap();
    store
        .put(&SecretScope::Home, &name("key"), plain("value"))
        .unwrap();
    assert_eq!(fs::read_to_string(&stale).unwrap(), "interrupted payload");
    fs::write(store.path(), "{truncated").unwrap();
    assert!(store
        .put(&SecretScope::Home, &name("new"), plain("new"))
        .is_err());
    assert_eq!(fs::read_to_string(store.path()).unwrap(), "{truncated");
}

#[test]
fn subprocess_writer() {
    let Ok(home) = std::env::var("SILO_SECRETS_WRITER_HOME") else {
        return;
    };
    let writer = std::env::var("SILO_SECRETS_WRITER_ID").unwrap();
    let store = FileStore::new(home);
    for i in 0..20 {
        store
            .put(
                &SecretScope::Home,
                &name(&format!("writer{writer}.{i}")),
                plain(&writer),
            )
            .unwrap();
    }
}

#[test]
fn subprocess_interrupted_transaction() {
    let Ok(home) = std::env::var("SILO_SECRETS_INTERRUPTED_HOME") else {
        return;
    };
    let store = FileStore::new(home);
    let mut tx = store.begin_transaction(&SecretScope::Home).unwrap();
    tx.put(&name("silo.ssh_ca.private_key"), plain("uncommitted"))
        .unwrap();
    // A process exit bypasses guard destruction, just like an interrupted writer.
    std::process::exit(0);
}

#[test]
fn interrupted_child_never_exposes_half_a_pair_and_releases_lock() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path());
    store
        .put(&SecretScope::Home, &name("unrelated"), plain("keep"))
        .unwrap();
    let before = fs::read(store.path()).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "subprocess_interrupted_transaction"])
        .env("SILO_SECRETS_INTERRUPTED_HOME", dir.path())
        .status()
        .unwrap();
    assert!(child.success());
    assert_eq!(fs::read(store.path()).unwrap(), before);
    store
        .transaction(&SecretScope::Home, |tx| {
            assert!(tx.get(&name("silo.ssh_ca.private_key"))?.is_none());
            tx.put(&name("silo.ssh_ca.private_key"), plain("private"))?;
            tx.put(&name("silo.ssh_ca.public_key"), plain("public"))
        })
        .unwrap();
    assert_eq!(store.list(&SecretScope::Home).unwrap().len(), 3);
}

#[test]
fn concurrent_subprocess_writers_do_not_lose_entries() {
    let dir = tempfile::tempdir().unwrap();
    let mut children = (0..8)
        .map(|id| {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "subprocess_writer", "--nocapture"])
                .env("SILO_SECRETS_WRITER_HOME", dir.path())
                .env("SILO_SECRETS_WRITER_ID", id.to_string())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let store = FileStore::new(dir.path());
    assert_eq!(store.list(&SecretScope::Home).unwrap().len(), 160);
    for id in 0..8 {
        for i in 0..20 {
            assert_eq!(
                value(&store, &SecretScope::Home, &format!("writer{id}.{i}")),
                id.to_string()
            );
        }
    }
}
