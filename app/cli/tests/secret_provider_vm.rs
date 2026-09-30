//! SEC-02 guest qualification. Local OAuth HTTP refresh is covered separately.
use std::time::Duration;

use libvm::{HostCommand, MachineReadinessOutcome, NetworkPolicy, Runtime, RuntimeConfig};
use silo_secrets::{
    FileStore, OAuthSecret, Secret, SecretBytes, SecretName, SecretScope, SecretStore,
};

#[tokio::test]
async fn sec02_real_guest_reloads_expired_payload_through_actual_cli_provider() {
    if std::env::var("SILO_E2E_KVM").as_deref() != Ok("1") {
        eprintln!(
            "SKIPPED SEC-02: SILO_E2E_KVM=1 is required for real guest provider qualification"
        );
        return;
    }
    assert!(
        std::path::Path::new("/dev/kvm").exists(),
        "SILO_E2E_KVM=1 requires /dev/kvm"
    );
    let (Some(root), Ok(image)) = (
        std::env::var_os("SILO_TEST_RUNTIME_ROOT"),
        std::env::var("SILO_TEST_IMAGE"),
    ) else {
        eprintln!(
            "SKIPPED SEC-02: SILO_TEST_RUNTIME_ROOT and SILO_TEST_IMAGE (with curl) are required"
        );
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let store = FileStore::new(home.path());
    let key = SecretName::new("openai_codex_oauth.personal.oauth").unwrap();
    let record = |token: &str, expiry: &str| {
        Secret::OAuth(OAuthSecret {
            provider: None,
            access_token: SecretBytes::new(token.as_bytes().to_vec()),
            // No live OAuth material. An unexpected provider HTTP refresh fails closed.
            refresh_token: SecretBytes::new(Vec::new()),
            expires_at: expiry.parse().unwrap(),
            account_id: None,
            created_at: None,
            updated_at: None,
        })
    };
    store
        .put(
            &SecretScope::Home,
            &key,
            record("expired-initial-payload", "2020-01-01T00:00:00Z"),
        )
        .unwrap();
    let provider = HostCommand::new(env!("CARGO_BIN_EXE_silo"))
        .args(["secret", "provide", "--store-file"])
        .arg(store.path());
    let runtime = Runtime::new(RuntimeConfig::local(home.path()).with_runtime_root(root))
        .await
        .unwrap()
        .with_secret_provider(provider);
    // This public HTTPS fixture echoes only a synthetic bearer token. It uses
    // real DNS/TLS and therefore belongs to the explicit qualification gate.
    let policy = NetworkPolicy::from_json_str(r#"{"version":1,"endpoints":[{"name":"echo","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["httpbingo.org"]}],"credentials":[{"name":"personal","kind":"openai_codex_oauth","endpoint":"echo"}],"rules":[{"endpoints":["echo"],"credential":"personal","verdict":"allow"}]}"#).unwrap();
    let machine = runtime
        .machine()
        .name("sec02-provider")
        .image(image)
        .vsock(true)
        .network(|network| network.private().policy(policy))
        .create()
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(210), async {
        machine.start().await?;
        let ready = machine.wait_ready(Duration::from_secs(90)).await?;
        eyre::ensure!(
            ready.outcome == MachineReadinessOutcome::Ready,
            "guest not ready"
        );
        // A concurrent host refresh won before the first guest request. netd
        // still holds the expired launch payload; the actual CLI must lock and
        // re-read this record and return its new projections without refreshing.
        store.put(
            &SecretScope::Home,
            &key,
            record("synthetic-sec02-refreshed-access", "2099-01-01T00:00:00Z"),
        )?;
        let before = std::fs::read(store.path())?;
        for _ in 0..2 {
            let output = machine
                .exec(
                    "curl",
                    [
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--max-time",
                        "20",
                        "https://httpbingo.org/bearer",
                    ],
                )
                .await?;
            let echoed: serde_json::Value = serde_json::from_slice(output.stdout_bytes())?;
            eyre::ensure!(
                echoed["authenticated"] == true
                    && echoed["token"] == "synthetic-sec02-refreshed-access",
                "guest did not use refreshed token"
            );
            eyre::ensure!(
                !output.stdout()?.contains("expired-initial-payload"),
                "guest used old token"
            );
        }
        eyre::ensure!(
            std::fs::read(store.path())? == before,
            "fresh get mutated store"
        );
        Ok::<(), eyre::Report>(())
    })
    .await;
    let stopped = machine.stop().await;
    let removed = machine.remove().await;
    result.unwrap().unwrap();
    stopped.unwrap();
    removed.unwrap();
}
