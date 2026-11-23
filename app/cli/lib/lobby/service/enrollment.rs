use crate::config::tailscale::EnrollmentMode;
use crate::daemon::control::lobby::categorize;
use crate::lobby::{
    caller::Caller,
    failure::{Code, Failure, Outcome},
    identity::{canonical_dns, Action, Principal},
    jobs::{Completion, Progress},
    service::{documents, vm, Service},
    views::{ForwardView, VmView},
};
use futures::future::BoxFuture;
use silo_secrets as secrets;
use silod_spec::daemon::v1 as w;

#[derive(Clone, Debug)]
pub(crate) struct NodePin {
    pub(crate) tailnet: String,
    pub(crate) suffix: String,
    pub(crate) control_url: String,
}
pub(crate) trait ConsentProvider: Send + Sync {
    fn acquire<'a>(
        &'a self,
        attempt: &'a str,
        owner: &'a Principal,
        progress: Progress,
    ) -> BoxFuture<'a, Outcome<Option<Vec<u8>>>>;
}

impl Service {
    pub(crate) fn enrollment_mode(&self, owner: &Principal) -> &'static str {
        if self.config.settings.enrollment_mode() == EnrollmentMode::None {
            "none"
        } else if owner.is_tag() {
            "tag"
        } else if self.config.settings.enrollment_mode() != EnrollmentMode::Interactive
            && self.config.consent.is_some()
        {
            "user"
        } else {
            "interactive"
        }
    }
    fn node_dns(&self, machine: &w::MachineSnapshot) -> String {
        match (&self.config.node_pin, &machine.tailscale) {
            (Some(pin), Some(node)) => canonical_dns(&format!("{}.{}", node.hostname, pin.suffix)),
            _ => String::new(),
        }
    }
    pub(crate) async fn bind_node_identity(
        &self,
        policy: &w::PolicyDocument,
        owner: &Principal,
        tags: &[String],
        mode: &str,
    ) -> Outcome<w::PolicyDocument> {
        let pin = self
            .config
            .node_pin
            .as_ref()
            .filter(|pin| !pin.tailnet.is_empty() && !pin.suffix.is_empty())
            .ok_or_else(|| {
                Failure::new(Code::Unavailable, "verified tailnet identity unavailable")
            })?;
        let mut root: serde_json::Value = serde_json::from_str(&policy.canonical_json)
            .map_err(|_| Failure::new(Code::Unavailable, "invalid normalized policy"))?;
        let bootstrap = match mode {
            "user" => "auth_key",
            "tag" => "client_secret",
            _ => "interactive",
        };
        let expected = serde_json::to_string(&serde_json::json!({ "owner": owner, "tags": tags, "tailnet": pin.tailnet, "suffix": pin.suffix, "bootstrap": bootstrap, "disable_key_expiry": self.config.settings.disable_key_expiry() }))
            .map_err(|_| Failure::new(Code::Unavailable, "node identity unavailable"))?;
        if expected.len() > 4096 {
            return Err(Failure::new(
                Code::Usage,
                "node identity metadata exceeds size limit",
            ));
        }
        let object = root
            .as_object_mut()
            .ok_or_else(|| Failure::new(Code::Unavailable, "invalid normalized policy"))?;
        let metadata = object
            .entry("metadata")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| Failure::new(Code::Unavailable, "invalid normalized policy metadata"))?;
        metadata.insert(
            "io.silo.lobby.node".into(),
            serde_json::Value::String(expected),
        );
        self.management()
            .normalize_policy(w::NormalizePolicyRequest {
                input: Some(w::normalize_policy_request::Input::CanonicalJson(
                    root.to_string(),
                )),
            })
            .await
            .map_err(|status| categorize(&status))
    }
    pub(crate) async fn inject_node(
        &self,
        policy: Option<&w::PolicyDocument>,
        name: &str,
        owner: &Principal,
        tags: &[String],
        mode: &str,
    ) -> Outcome<w::PolicyDocument> {
        let url = self
            .config
            .node_pin
            .as_ref()
            .map_or(self.config.settings.control_url(), |pin| {
                pin.control_url.as_str()
            });
        let policy =
            documents::inject_tailnet(policy, name, owner, url, tags, &mut |request| async {
                self.management()
                    .normalize_policy(request)
                    .await
                    .map_err(|status| categorize(&status))
            })
            .await?;
        self.bind_node_identity(&policy, owner, tags, mode).await
    }
    fn home_credential(&self, name: &str) -> Outcome<Option<secrets::SecretBytes>> {
        use secrets::SecretStore;
        let name = secrets::SecretName::new(name)
            .map_err(|_| Failure::new(Code::Unavailable, "invalid credential name"))?;
        match secrets::FileStore::new(&self.config.home)
            .get(&secrets::SecretScope::Home, &name)
            .map_err(|_| Failure::new(Code::Unavailable, "enrollment credential unavailable"))?
        {
            None => Ok(None),
            Some(secrets::Secret::Plain(bytes)) if bytes.as_bytes().len() <= 16384 => {
                Ok(Some(bytes))
            }
            Some(_) => Err(Failure::new(
                Code::Unavailable,
                "invalid enrollment credential",
            )),
        }
    }
    pub(crate) async fn store_node_credentials(
        &self,
        caller: &Caller,
        action: Action,
        machine: &w::MachineSnapshot,
        key: Option<&[u8]>,
    ) -> Outcome<()> {
        let mut credentials = Vec::new();
        if let Some(key) = key.filter(|key| !key.is_empty()) {
            credentials.push((
                "tailscale.vm.auth_key",
                secrets::SecretBytes::new(key.to_vec()),
            ));
        }
        if vm::owner(machine)?.is_tag() {
            if let Some(secret) = self.home_credential("tailscale.lobby.client_secret")? {
                credentials.push(("tailscale.vm.client_secret", secret));
            }
        }
        if self.config.settings.disable_key_expiry() {
            if let Some(secret) = self.home_credential("tailscale.lobby.api_token")? {
                credentials.push(("tailscale.vm.api_token", secret));
            }
        }
        for (name, bytes) in credentials {
            self.reauthorize(caller, action, machine).await?;
            self.management()
                .set_secret(&machine.id, name, bytes.as_bytes().to_vec())
                .await
                .map_err(|status| categorize(&status))?;
        }
        Ok(())
    }
    pub(crate) async fn prepare_node(
        &self,
        caller: &Caller,
        action: Action,
        machine: &w::MachineSnapshot,
    ) -> Outcome<()> {
        if machine.tailscale.is_none() {
            return Ok(());
        }
        self.store_node_credentials(caller, action, machine, None)
            .await?;
        let view = vm::project(machine)?;
        let mut tags = view.tags;
        if tags.is_empty() && view.owner.is_tag() {
            tags.push(view.owner.to_string());
        }
        self.reauthorize(caller, action, machine).await?;
        let original = vm::policy_json(machine)
            .ok_or_else(|| Failure::new(Code::Unavailable, "node policy unavailable"))?;
        let policy = self
            .bind_node_identity(
                &w::PolicyDocument {
                    canonical_json: original.into(),
                    ..Default::default()
                },
                &view.owner,
                &tags,
                vm::label(machine, vm::MODE_LABEL),
            )
            .await?;
        if policy.canonical_json != original {
            self.reauthorize(caller, action, machine).await?;
            self.management()
                .update(
                    &machine.id,
                    w::MachineUpdate {
                        policy: Some(w::PolicyUpdate {
                            update: Some(w::policy_update::Update::Set(policy.canonical_json)),
                        }),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|status| categorize(&status))?;
        }
        Ok(())
    }
    fn matches_node(&self, observation: &w::NodeObservation, view: &VmView, dns: &str) -> bool {
        self.config.node_pin.as_ref().is_some_and(|pin| {
            observation.machine_id == view.id
                && observation.owner == view.owner.as_str()
                && observation.tailnet == pin.tailnet
                && observation.dns_name == dns
                && same_tags(&observation.tags, &view.tags)
        })
    }
    pub(crate) fn node_view(&self, machine: &w::MachineSnapshot) -> Outcome<VmView> {
        let mut view = vm::project(machine)?;
        if machine.tailscale.is_none() {
            return Ok(view);
        }
        let dns = self.node_dns(machine);
        let observation = machine.network_observation.as_ref();
        if vm::state(machine) != "running" {
            view.node_state = vm::state(machine).into();
            view.node = dns.clone();
            if vm::state(machine) == "stopped" {
                if let Some(history) = observation
                    .and_then(|observation| observation.historical.as_ref())
                    .filter(|history| self.matches_node(history, &view, &dns))
                {
                    view.node_id.clone_from(&history.node_id);
                    set_expiry(
                        &mut view,
                        history.key_expiry.as_ref(),
                        history.observed_at.as_ref(),
                        true,
                    );
                }
            }
        } else {
            view.node_state = "status unavailable".into();
            if let Some(status) = observation
                .and_then(|observation| observation.live.as_ref())
                .filter(|status| {
                    status.machine_id == machine.id
                        && machine.run_id.as_deref() == Some(status.run_id.as_str())
                })
            {
                let identity_matches = !dns.is_empty()
                    && status.node_id.as_ref().is_some_and(|id| !id.is_empty())
                    && status.dns_name.as_deref() == Some(dns.as_str())
                    && same_tags(&status.tags, &view.tags);
                match w::NodeState::try_from(status.state) {
                    Ok(w::NodeState::Ready) => {
                        if !identity_matches {
                            view.node_state = "state unreadable".into();
                            return Ok(view);
                        }
                        view.node_state = "enrolled".into();
                        view.node = dns.clone();
                        view.node_id = status.node_id.clone().unwrap_or_default();
                        view.addresses.clone_from(&status.addresses);
                        if !view.addresses.is_empty() {
                            view.address = view.addresses.join(",");
                        }
                        if status.key_expiry_known {
                            set_expiry(
                                &mut view,
                                status.key_expiry.as_ref(),
                                status.updated_at.as_ref(),
                                false,
                            );
                        }
                        if vm::timestamp(status.key_expiry.as_ref())
                            .is_some_and(|expiry| expiry <= chrono::Utc::now())
                        {
                            view.node_state = "expired".into();
                            view.node.clear();
                        }
                        if status.error_code.as_deref() == Some("key_expiry_update_failed") {
                            view.node_diagnostics
                                .push("key-expiry policy update pending; netd will retry".into());
                        }
                    }
                    Ok(w::NodeState::ApprovalRequired) => {
                        view.node_state = "pending approval".into();
                        view.approval_url = status.approval_url.clone().unwrap_or_default();
                        if identity_matches
                            && status.error_code.as_deref() == Some("key_expired")
                            && status.key_expiry_known
                            && status.key_expiry.is_some()
                        {
                            set_expiry(
                                &mut view,
                                status.key_expiry.as_ref(),
                                status.updated_at.as_ref(),
                                false,
                            );
                        }
                        if status.error_code.as_deref() == Some("device_approval_required") {
                            view.node_diagnostics.push(
                                "device approval required in the Tailscale admin console".into(),
                            );
                        }
                    }
                    Ok(w::NodeState::Failed) => {
                        view.node_state = "enrollment failed".into();
                        view.node_diagnostics
                            .push("node enrollment failed; inspect network logs".into());
                    }
                    Ok(w::NodeState::Connecting) => view.node_state = "connecting".into(),
                    Ok(w::NodeState::Disconnected) => view.node_state = "disconnected".into(),
                    Ok(w::NodeState::Stopped) => view.node_state = "stopped".into(),
                    _ => {}
                }
                if view.key_expiry == "unknown"
                    && status.error_code.as_deref() != Some("identity_mismatch")
                {
                    if let Some(history) = observation
                        .and_then(|observation| observation.historical.as_ref())
                        .filter(|history| {
                            self.matches_node(history, &view, &dns)
                                && vm::timestamp(history.observed_at.as_ref())
                                    .zip(vm::timestamp(status.updated_at.as_ref()))
                                    .is_some_and(|(old, new)| old <= new)
                        })
                    {
                        set_expiry(
                            &mut view,
                            history.key_expiry.as_ref(),
                            history.observed_at.as_ref(),
                            true,
                        );
                    }
                }
            }
        }
        view.forwards = forward_views(machine, &view.node);
        Ok(view)
    }
    pub(crate) async fn complete_node(
        &self,
        id: &str,
        completion: &mut Completion,
        progress: &Progress,
    ) {
        if self
            .management()
            .inspect(id)
            .await
            .ok()
            .is_none_or(|machine| machine.tailscale.is_none())
        {
            return;
        }
        progress("checking Tailscale onboarding link".into());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let machine = match self.management().inspect(id).await {
                    Ok(machine) => machine,
                    Err(_) => return,
                };
                let view = match self.node_view(&machine) {
                    Ok(view) => view,
                    Err(_) => return,
                };
                completion.node_state.clone_from(&view.node_state);
                completion.node = view.node;
                completion.approval_url = view.approval_url;
                if !completion.approval_url.is_empty()
                    || matches!(
                        completion.node_state.as_str(),
                        "enrolled" | "enrollment failed" | "state unreadable"
                    )
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await;
    }
}
fn same_tags(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left: Vec<_> = left.iter().collect();
    let mut right: Vec<_> = right.iter().collect();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}
fn set_expiry(
    view: &mut VmView,
    expiry: Option<&prost_types::Timestamp>,
    observed: Option<&prost_types::Timestamp>,
    historical: bool,
) {
    view.key_expiry = vm::timestamp(expiry).map_or_else(
        || "never".into(),
        |expiry| expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    );
    view.key_expiry_observed_at = vm::timestamp(observed);
    view.key_expiry_last_known = historical;
}
fn forward_views(machine: &w::MachineSnapshot, node: &str) -> Vec<ForwardView> {
    let Some(root) = vm::policy_json(machine)
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
    else {
        return Vec::new();
    };
    root.get("forwards")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|forward| {
            if forward.get("kind")?.as_str()? != "tailscale" {
                return None;
            }
            let listen = forward
                .get("listen")?
                .as_str()?
                .strip_prefix(':')?
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)?;
            let protocol = forward
                .get("protocol")
                .and_then(serde_json::Value::as_str)
                .filter(|protocol| !protocol.is_empty())
                .unwrap_or("tcp");
            let url = if node.is_empty() {
                String::new()
            } else if protocol == "https" && listen == 443 {
                format!("https://{node}/")
            } else if protocol == "https" {
                format!("https://{node}:{listen}/")
            } else {
                format!("tcp://{node}:{listen}")
            };
            Some(ForwardView {
                name: forward.get("name")?.as_str()?.into(),
                protocol: protocol.into(),
                listen_port: listen,
                target_port: u16::try_from(forward.get("target_port")?.as_u64()?).ok()?,
                url,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::lobby::service::{enrollment::*, testing, vm};
    #[tokio::test]
    async fn stopped_history_and_current_generation_are_fenced() {
        let mut fixture = testing::fixture().await;
        std::sync::Arc::get_mut(&mut fixture.service.config)
            .unwrap()
            .node_pin = Some(NodePin {
            tailnet: "fixture".into(),
            suffix: "tail.test".into(),
            control_url: String::new(),
        });
        let mut machine = w::MachineSnapshot {
            id: "vm".into(),
            name: "dev".into(),
            labels: [
                (vm::OWNER_LABEL.into(), "user:7".into()),
                (vm::TAGS_LABEL.into(), "[\"tag:dev\"]".into()),
            ]
            .into(),
            tailscale: Some(w::MachineTailscale {
                hostname: "dev".into(),
                ..Default::default()
            }),
            status: Some(w::MachineStatus {
                status: Some(w::machine_status::Status::Stopped(())),
            }),
            network_observation: Some(w::NetworkObservation {
                historical: Some(w::NodeObservation {
                    machine_id: "vm".into(),
                    owner: "user:7".into(),
                    tailnet: "fixture".into(),
                    node_id: "node".into(),
                    dns_name: "dev.tail.test".into(),
                    tags: vec!["tag:dev".into()],
                    observed_at: Some(prost_types::Timestamp {
                        seconds: 1000,
                        nanos: 0,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let view = fixture.service.node_view(&machine).unwrap();
        assert_eq!(view.node, "dev.tail.test");
        assert_eq!(view.key_expiry, "never");
        assert!(view.key_expiry_last_known);
        for field in ["owner", "tailnet", "machine", "dns", "tags"] {
            let mut changed = machine.clone();
            let history = changed
                .network_observation
                .as_mut()
                .unwrap()
                .historical
                .as_mut()
                .unwrap();
            match field {
                "owner" => history.owner = "user:8".into(),
                "tailnet" => history.tailnet = "other".into(),
                "machine" => history.machine_id = "other".into(),
                "dns" => history.dns_name = "other.tail.test".into(),
                _ => history.tags.clear(),
            }
            assert_eq!(
                fixture.service.node_view(&changed).unwrap().key_expiry,
                "unknown"
            );
        }
        machine.status = Some(w::MachineStatus {
            status: Some(w::machine_status::Status::Running(
                w::RunningStatus::default(),
            )),
        });
        machine.run_id = Some("current".into());
        machine.network_observation.as_mut().unwrap().live = Some(w::NodeStatus {
            machine_id: "vm".into(),
            run_id: "old".into(),
            state: w::NodeState::Ready as i32,
            node_id: Some("node".into()),
            dns_name: Some("dev.tail.test".into()),
            tags: vec!["tag:dev".into()],
            key_expiry_known: true,
            ..Default::default()
        });
        assert_eq!(
            fixture.service.node_view(&machine).unwrap().node_state,
            "status unavailable"
        );
        machine
            .network_observation
            .as_mut()
            .unwrap()
            .live
            .as_mut()
            .unwrap()
            .run_id = "current".into();
        assert_eq!(
            fixture.service.node_view(&machine).unwrap().node_state,
            "enrolled"
        );
        machine
            .network_observation
            .as_mut()
            .unwrap()
            .live
            .as_mut()
            .unwrap()
            .dns_name = Some("wrong".into());
        assert_eq!(
            fixture.service.node_view(&machine).unwrap().node_state,
            "state unreadable"
        );
    }
    #[tokio::test]
    async fn identity_metadata_is_pinned_and_forward_urls_are_configuration() {
        let mut fixture = testing::fixture().await;
        std::sync::Arc::get_mut(&mut fixture.service.config)
            .unwrap()
            .node_pin = Some(NodePin {
            tailnet: "fixture".into(),
            suffix: "tail.test".into(),
            control_url: "https://control.example.test".into(),
        });
        for (owner, mode, bootstrap) in [
            ("user:7", "interactive", "interactive"),
            ("user:7", "user", "auth_key"),
            ("tag:ci", "tag", "client_secret"),
        ] {
            let owner = Principal::parse(owner).unwrap();
            let policy = fixture
                .service
                .inject_node(None, "exact", &owner, &[], mode)
                .await
                .unwrap();
            let root: serde_json::Value = serde_json::from_str(&policy.canonical_json).unwrap();
            let metadata: serde_json::Value =
                serde_json::from_str(root["metadata"]["io.silo.lobby.node"].as_str().unwrap())
                    .unwrap();
            assert_eq!(metadata["owner"], owner.as_str());
            assert_eq!(metadata["tailnet"], "fixture");
            assert_eq!(metadata["suffix"], "tail.test");
            assert_eq!(metadata["bootstrap"], bootstrap);
        }
        let policy = serde_json::json!({"forwards":[
            {"kind":"tailscale","name":"web","listen":":443","target_port":8080,"protocol":"https"},
            {"kind":"tailscale","name":"other","listen":":8443","target_port":8081,"protocol":"https"},
            {"kind":"tailscale","name":"raw","listen":":9000","target_port":9001},
            {"kind":"host","name":"hidden","listen":":1234","target_port":1234}
        ]}).to_string();
        let machine = w::MachineSnapshot {
            network: Some(w::ResolvedNetwork {
                attachment: Some(w::resolved_network::Attachment::Private(
                    w::PrivateNetwork {
                        policy_json: Some(policy),
                        publish: None,
                    },
                )),
            }),
            ..Default::default()
        };
        let views = forward_views(&machine, "exact.tail.test");
        assert_eq!(
            views
                .iter()
                .map(|view| view.url.as_str())
                .collect::<Vec<_>>(),
            [
                "https://exact.tail.test/",
                "https://exact.tail.test:8443/",
                "tcp://exact.tail.test:9000"
            ]
        );
        assert!(forward_views(&machine, "")
            .iter()
            .all(|view| view.url.is_empty()));
    }

    #[tokio::test]
    async fn credential_writes_are_machine_scoped_and_reauthorized() {
        use silo_secrets::{
            FileStore, MachineScopeId, Secret, SecretBytes, SecretName, SecretScope, SecretStore,
        };
        let fixture = testing::fixture().await;
        let machine = testing::stopped_vm(&fixture, "credential", "user:7").await;
        let caller = testing::caller("user:7", &[Action::Create]);
        fixture
            .service
            .store_node_credentials(
                &caller,
                Action::Create,
                &machine,
                Some(b"private-bootstrap"),
            )
            .await
            .unwrap();
        let name = SecretName::new("tailscale.vm.auth_key").unwrap();
        let store = FileStore::new(fixture.root.path().join("home"));
        assert_eq!(
            store
                .get(
                    &SecretScope::Machine {
                        id: MachineScopeId::new(&machine.id).unwrap()
                    },
                    &name
                )
                .unwrap(),
            Some(Secret::Plain(SecretBytes::new(
                b"private-bootstrap".to_vec()
            )))
        );
        assert!(store.get(&SecretScope::Home, &name).unwrap().is_none());
        let stranger = testing::caller("user:8", &[Action::Create]);
        assert_eq!(
            fixture
                .service
                .store_node_credentials(&stranger, Action::Create, &machine, Some(b"replacement"))
                .await
                .unwrap_err()
                .exit,
            3
        );
    }
}
