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
fn v1_refresh_grants_and_arbitrary_store_file_are_preserved() {
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
        let grant = serde_json::json!({"version":if encoding == "version" {2} else {1},"store_file":grant_path,"credentials":if allowed { vec![serde_json::json!({"name":"personal","kind":"openai_codex_oauth","endpoint":"api","secret_key":"openai_codex_oauth.personal.oauth"})] } else { vec![] }});
        let encoded = STANDARD.encode(serde_json::to_vec(&grant).unwrap());
        let mut request = serde_json::json!({"version":1,"operation":"oauth_refresh","credential":{"name":"personal","kind":"openai_codex_oauth","endpoint":"api"},"reason":"expired","expires_at":"2026-09-30T00:00:00Z"});
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
            .args(["secret", "refresh-oauth", "--store-file"])
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
        assert_eq!(response["version"], 1);
        assert_eq!(response["status"], "error");
        assert_eq!(response["error"]["code"], code);
        assert!(!frame.contains("private-token"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!dir.path().join("wrong-home/secrets.json").exists());
    }
}
