use std::io::Write;
use std::process::{Command, Output, Stdio};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use serde_json::Value;

fn run(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_silo"))
        .env("SILO_HOME", home)
        .args(args)
        .output()
        .unwrap()
}
fn success(home: &std::path::Path, args: &[&str]) -> Output {
    let out = run(home, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn provider_get(store: &std::path::Path, request: &Value) -> (Value, Vec<u8>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_silo"))
        .env_clear()
        .args(["secret", "provide", "--store-file"])
        .arg(store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    silo_secrets::grant::write_json_frame(child.stdin.take().unwrap(), request).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = silo_secrets::grant::read_json_frame(output.stdout.as_slice()).unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-refresh"));
    (response, output.stdout)
}

#[test]
fn actual_provider_get_projects_and_denies_entire_request_before_io() {
    let dir = tempfile::tempdir().unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    let key = "openai_codex_oauth.personal.oauth";
    let file = dir.path().join("custom.json");
    let before=serde_json::to_vec(&serde_json::json!({key:{"type":"oauth","access_token":"selected-access","refresh_token":"private-refresh","expires_at":"2099-01-01T00:00:00Z"}})).unwrap();
    std::fs::write(&file, &before).unwrap();
    let grant = serde_json::json!({"version":2,"store":format!("file:{}",file.display()),"machine":id,"run":"run","issued_at":"2026-09-30T00:00:00Z","allowed":[{"slot":"personal.oauth.access_token","key":key,"field":"OAuthAccessToken","backing_scope":"Home"},{"slot":"personal.oauth.expires_at","key":key,"field":"OAuthExpiresAt","backing_scope":"Home"}]});
    let request = serde_json::json!({"version":2,"operation":"get","grant":STANDARD.encode(serde_json::to_vec(&grant).unwrap()),"scope":{"machine":id,"run":"run"},"names":["personal.oauth.access_token","personal.oauth.expires_at"],"reason":"expired"});
    let (response, wire) = provider_get(&file, &request);
    assert_eq!(response["status"], "ok");
    assert_eq!(response["secrets"].as_array().unwrap().len(), 2);
    assert_eq!(
        STANDARD
            .decode(response["secrets"][0]["value"].as_str().unwrap())
            .unwrap(),
        b"selected-access"
    );
    assert!(!String::from_utf8(wire)
        .unwrap()
        .contains(&STANDARD.encode(b"private-refresh")));
    for variant in [
        "name",
        "run",
        "machine",
        "reserved",
        "duplicate",
        "store",
        "backing",
    ] {
        let mut denied = request.clone();
        let mut changed_grant = grant.clone();
        match variant {
            "name" => {
                denied["names"] =
                    serde_json::json!(["personal.oauth.access_token", "outside.token"])
            }
            "run" => denied["scope"]["run"] = serde_json::json!("other"),
            "machine" => {
                denied["scope"]["machine"] = serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            }
            "reserved" => denied["names"] = serde_json::json!(["silo.ssh_ca.private_key"]),
            "duplicate" => {
                denied["names"] = serde_json::json!([
                    "personal.oauth.access_token",
                    "personal.oauth.access_token"
                ])
            }
            "store" => changed_grant["store"] = serde_json::json!("file:/wrong/store.json"),
            "backing" => {
                changed_grant["allowed"][0]["backing_scope"] =
                    serde_json::json!({"Machine":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})
            }
            _ => unreachable!(),
        }
        denied["grant"] =
            serde_json::json!(STANDARD.encode(serde_json::to_vec(&changed_grant).unwrap()));
        let (response, _) = provider_get(&file, &denied);
        assert_eq!(response["error"]["code"], "unauthorized", "{variant}");
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }
    let absent = dir.path().join("never-create/store.json");
    let (response, _) = provider_get(&absent, &request);
    assert_eq!(response["error"]["code"], "unauthorized");
    assert!(!absent.parent().unwrap().exists());
}

#[test]
fn actual_binary_set_list_show_remove_preserves_legacy_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/secrets/basic.json")).unwrap();
    let mut original = fixture.clone();
    original[".old..name"] = serde_json::json!({"type":"plain","value":"private-legacy"});
    original["old.oauth"] = serde_json::json!({"type":"oauth","access_token":"private-access","refresh_token":"private-refresh","expires_at":"2026-09-30T00:00:00Z"});
    let path = dir.path().join("secrets.json");
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    success(
        dir.path(),
        &[
            "secret",
            "set",
            "bearer_token.github.token",
            "--value",
            "private-token",
        ],
    );
    let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (key, record) in original.as_object().unwrap() {
        assert_eq!(&stored[key], record);
    }
    assert_eq!(
        stored["bearer_token.github.token"],
        serde_json::json!({"type":"plain", "value":"private-token"})
    );
    let list = success(dir.path(), &["secret", "ls", "--format", "json"]);
    let records: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(
        records.as_array().unwrap().len(),
        original.as_object().unwrap().len() + 1
    );
    for key in original.as_object().unwrap().keys() {
        assert!(records
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == *key));
    }
    for key in ["bearer_token.github.token", ".old..name", "old.oauth"] {
        let shown = success(dir.path(), &["secret", "show", key, "--format", "json"]);
        let stdout = String::from_utf8(shown.stdout).unwrap();
        assert!(!stdout.contains("private-"));
        assert_eq!(serde_json::from_str::<Value>(&stdout).unwrap()["name"], key);
    }
    assert!(!run(
        dir.path(),
        &[
            "secret",
            "set",
            "bearer_token.github.token",
            "--value",
            "replacement"
        ]
    )
    .status
    .success());
    assert!(!run(
        dir.path(),
        &[
            "secret",
            "set",
            "silo.ssh_ca.private_key",
            "--value",
            "reserved"
        ]
    )
    .status
    .success());
    assert!(!run(
        dir.path(),
        &["secret", "set", "bad..name", "--value", "bad"]
    )
    .status
    .success());
    assert!(!run(dir.path(), &["secret", "rm", ".old..name"])
        .status
        .success());
    success(dir.path(), &["secret", "rm", ".old..name", "--force"]);
    success(
        dir.path(),
        &["secret", "rm", "bearer_token.github.token", "--force"],
    );
    assert!(!run(dir.path(), &["secret", "show", "missing"])
        .status
        .success());
    let after: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(after.get(".old..name").is_none());
    assert!(after.get("bearer_token.github.token").is_none());
    for (key, record) in fixture.as_object().unwrap() {
        assert_eq!(&after[key], record);
    }
}

#[test]
fn actual_binary_concurrent_create_does_not_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let mut children = (0..8)
        .map(|i| {
            Command::new(env!("CARGO_BIN_EXE_silo"))
                .env("SILO_HOME", dir.path())
                .args(["secret", "set", "same", "--value", &format!("writer{i}")])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let winners = children
        .iter_mut()
        .map(|child| child.wait().unwrap().success())
        .filter(|success| *success)
        .count();
    assert_eq!(winners, 1);
    let stored: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("secrets.json")).unwrap()).unwrap();
    assert_eq!(stored.as_object().unwrap().len(), 1);
}

#[test]
fn provider_grants_and_arbitrary_store_file_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("launch-specific-store.json");
    std::fs::write(
        &path,
        br#"{"openai_codex_oauth.personal.oauth":{"type":"plain","value":"private-token"}}"#,
    )
    .unwrap();
    let before = std::fs::read(&path).unwrap();
    for (grant_path, allowed, encoding, code) in [
        (path.clone(), true, "valid", "invalid_request"),
        (dir.path().join("other.json"), true, "valid", "unauthorized"),
        (path.clone(), false, "valid", "unauthorized"),
        (path.clone(), true, "missing", "unauthorized"),
        (path.clone(), true, "malformed", "unauthorized"),
        (path.clone(), true, "double", "unauthorized"),
        (path.clone(), true, "version", "unauthorized"),
    ] {
        let grant = serde_json::json!({"version":if encoding == "version" {1} else {2},"store":format!("file:{}",grant_path.display()),"machine":"0123456789abcdef0123456789abcdef","run":"run","issued_at":"2026-09-30T00:00:00Z","allowed":if allowed { vec![serde_json::json!({"slot":"personal.oauth.access_token","key":"openai_codex_oauth.personal.oauth","field":"OAuthAccessToken","backing_scope":"Home"})] } else { vec![] }});
        let encoded = STANDARD.encode(serde_json::to_vec(&grant).unwrap());
        let mut request = serde_json::json!({"version":2,"operation":"get","grant":"","scope":{"machine":"0123456789abcdef0123456789abcdef","run":"run"},"names":["personal.oauth.access_token"],"reason":"expired"});
        if encoding != "missing" {
            request["grant"] = Value::String(match encoding {
                "malformed" => "%%%".to_string(),
                "double" => STANDARD.encode(encoded.as_bytes()),
                _ => encoded,
            });
        }
        let request = serde_json::to_vec(&request).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_silo"))
            .env("SILO_HOME", dir.path().join("wrong-home"))
            .env(
                "SILO_NET_OAUTH_REFRESH_AUTH",
                "ambient-auth-must-be-ignored",
            )
            .args(["secret", "provide", "--store-file"])
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        write!(input, "Content-Length: {}\r\n\r\n", request.len()).unwrap();
        input.write_all(&request).unwrap();
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let frame = String::from_utf8(output.stdout).unwrap();
        let (header, body) = frame.split_once("\r\n\r\n").unwrap();
        assert_eq!(header, format!("Content-Length: {}", body.len()));
        let response: Value = serde_json::from_str(body).unwrap();
        assert_eq!(response["version"], 2);
        assert_eq!(response["status"], "error");
        assert_eq!(response["error"]["code"], code);
        assert!(!frame.contains("private-token"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!dir.path().join("wrong-home/secrets.json").exists());
    }
}

#[test]
fn actual_provider_reads_exact_granted_scope_without_home_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    let machine_dir = dir.path().join("machines").join(id);
    std::fs::create_dir_all(&machine_dir).unwrap();
    let home_file = dir.path().join("secrets.json");
    let machine_file = machine_dir.join("secrets.json");
    let key = "openai_codex_oauth.personal.oauth";
    let home = serde_json::json!({key:{"type":"plain","value":"home-must-not-be-read"}});
    std::fs::write(&home_file, serde_json::to_vec(&home).unwrap()).unwrap();
    for (record, machine, run_id, code, text) in [
        (
            Some(
                serde_json::json!({"type":"oauth","access_token":"machine-access","refresh_token":"","expires_at":"2026-09-30T00:00:00Z"}),
            ),
            Some(id),
            Some("run"),
            "invalid_request",
            "does not contain a refresh token",
        ),
        (
            None,
            Some(id),
            Some("run"),
            "not_found",
            "OAuth secret was not found",
        ),
        (
            Some(serde_json::json!({"type":"plain","value":"machine"})),
            Some(id),
            Some("run"),
            "invalid_request",
            "is not an OAuth secret",
        ),
        (None, None, Some("run"), "unauthorized", "machine scope"),
        (
            None,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some("run"),
            "unauthorized",
            "machine scope",
        ),
        (None, Some(id), None, "unauthorized", "machine scope"),
    ] {
        let mut records = serde_json::json!({});
        if let Some(record) = record {
            records[key] = record;
        }
        std::fs::write(&machine_file, serde_json::to_vec(&records).unwrap()).unwrap();
        let before_home = std::fs::read(&home_file).unwrap();
        let before_machine = std::fs::read(&machine_file).unwrap();
        let grant = serde_json::json!({"version":2,"store":format!("file:{}",home_file.display()),"machine":machine,"run":run_id,"issued_at":"2026-09-30T00:00:00Z","allowed":[{"slot":"personal.oauth.access_token","key":key,"field":"OAuthAccessToken","backing_scope":{"Machine":{"id":id}}}]});
        let request = serde_json::json!({"version":2,"operation":"get","grant":STANDARD.encode(serde_json::to_vec(&grant).unwrap()),"scope":{"machine":id,"run":"run"},"names":["personal.oauth.access_token"],"reason":"expired"});
        let request = serde_json::to_vec(&request).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_silo"))
            .env_clear()
            .args(["secret", "provide", "--store-file"])
            .arg(&home_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        write!(input, "Content-Length: {}\r\n\r\n", request.len()).unwrap();
        input.write_all(&request).unwrap();
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let frame = String::from_utf8(output.stdout).unwrap();
        let response: Value =
            serde_json::from_str(frame.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(response["error"]["code"], code);
        if code != "unauthorized" {
            assert!(response["error"]["message"]
                .as_str()
                .unwrap()
                .contains(text));
        }
        assert!(!frame.contains("machine-access"));
        assert!(!frame.contains("home-must-not-be-read"));
        assert_eq!(std::fs::read(&home_file).unwrap(), before_home);
        assert_eq!(std::fs::read(&machine_file).unwrap(), before_machine);
    }
}

#[test]
fn scoped_provider_waits_for_selected_scope_transaction_and_rereads() {
    use silo_secrets::{FileStore, MachineScopeId, Secret, SecretBytes, SecretName, SecretScope};
    let dir = tempfile::tempdir().unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    let scope = SecretScope::Machine {
        id: MachineScopeId::new(id).unwrap(),
    };
    let store = FileStore::new(dir.path());
    let machine_file = store.scope_path(&scope);
    std::fs::create_dir_all(machine_file.parent().unwrap()).unwrap();
    std::fs::write(&machine_file, br#"{"openai_codex_oauth.personal.oauth":{"type":"oauth","access_token":"access","refresh_token":"","expires_at":"2026-09-30T00:00:00Z"}}"#).unwrap();
    let mut transaction = store.begin_transaction(&scope).unwrap();
    let grant = serde_json::json!({"version":2,"store":format!("file:{}",store.path().display()),"machine":id,"run":"run","issued_at":"2026-09-30T00:00:00Z","allowed":[{"slot":"personal.oauth.access_token","key":"openai_codex_oauth.personal.oauth","field":"OAuthAccessToken","backing_scope":scope}]});
    let request = serde_json::to_vec(&serde_json::json!({"version":2,"operation":"get","grant":STANDARD.encode(serde_json::to_vec(&grant).unwrap()),"scope":{"machine":id,"run":"run"},"names":["personal.oauth.access_token"],"reason":"expired"})).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_silo"))
        .env_clear()
        .args(["secret", "provide", "--store-file"])
        .arg(store.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    write!(input, "Content-Length: {}\r\n\r\n", request.len()).unwrap();
    input.write_all(&request).unwrap();
    drop(input);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(
        child.try_wait().unwrap().is_none(),
        "provider did not retain the selected scope lock"
    );
    transaction
        .put(
            &SecretName::new("openai_codex_oauth.personal.oauth").unwrap(),
            Secret::Plain(SecretBytes::new(b"replacement".to_vec())),
        )
        .unwrap();
    transaction.commit().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let frame = String::from_utf8(output.stdout).unwrap();
    let response: Value = serde_json::from_str(frame.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(response["error"]["code"], "invalid_request");
    assert!(response["error"]["message"]
        .as_str()
        .unwrap()
        .contains("is not an OAuth secret"));
    assert!(!frame.contains("replacement"));
    assert!(!store.path().exists());
}
