use crate::daemon::control::lobby::categorize;
use crate::lobby::{
    failure::{Code, Failure, Outcome},
    identity::{Action, Peer, Principal},
    jobs::Operation,
    service::{
        documents::{valid_document_name, GUEST_PORTS_LABEL, POLICY_LABEL, TEMPLATE_LABEL},
        Service,
    },
    views::{GuestUserView, VmView},
};
use silod_spec::daemon::v1 as w;

pub(crate) const OWNER_LABEL: &str = "io.silo.lobby.owner";
pub(crate) const LOGIN_LABEL: &str = "io.silo.lobby.owner-login";
pub(crate) const NAME_LABEL: &str = "io.silo.lobby.name";
pub(crate) const INSTANCE_LABEL: &str = "io.silo.lobby.instance";
pub(crate) const MODE_LABEL: &str = "io.silo.lobby.node.mode";
pub(crate) const TAGS_LABEL: &str = "io.silo.lobby.node.tags";

pub(crate) fn label<'a>(machine: &'a w::MachineSnapshot, key: &str) -> &'a str {
    machine
        .labels
        .get(key)
        .map(String::as_str)
        .unwrap_or_default()
}
pub(crate) fn owner(machine: &w::MachineSnapshot) -> Outcome<Principal> {
    Principal::parse(label(machine, OWNER_LABEL))
        .map_err(|_| Failure::new(Code::NotFound, "VM not found"))
}
pub(crate) fn managed(machine: &w::MachineSnapshot, instance: &str) -> bool {
    !instance.is_empty()
        && label(machine, INSTANCE_LABEL) == instance
        && label(machine, NAME_LABEL) == machine.name
        && valid_document_name(&machine.name)
        && owner(machine).is_ok()
}
pub(crate) fn state(machine: &w::MachineSnapshot) -> &'static str {
    use w::machine_status::Status;
    match machine
        .status
        .as_ref()
        .and_then(|status| status.status.as_ref())
    {
        Some(Status::Stopped(_)) => "stopped",
        Some(Status::Starting(_)) => "starting",
        Some(Status::Running(_)) => "running",
        Some(Status::Stopping(_)) => "stopping",
        Some(Status::Error(_)) => "error",
        _ => "unknown",
    }
}
pub(crate) fn timestamp(
    value: Option<&prost_types::Timestamp>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    value.and_then(|value| {
        u32::try_from(value.nanos)
            .ok()
            .and_then(|nanos| chrono::DateTime::from_timestamp(value.seconds, nanos))
    })
}
pub(crate) fn policy_json(machine: &w::MachineSnapshot) -> Option<&str> {
    match machine.network.as_ref()?.attachment.as_ref()? {
        w::resolved_network::Attachment::Private(network) => network.policy_json.as_deref(),
        _ => None,
    }
}
pub(crate) fn project(machine: &w::MachineSnapshot) -> Outcome<VmView> {
    let owner = owner(machine)?;
    let hardware = machine
        .spec
        .as_ref()
        .and_then(|spec| spec.hardware.as_ref());
    let guest_user = machine
        .guest
        .as_ref()
        .and_then(|guest| guest.user.as_ref())
        .map(|user| GuestUserView {
            name: user.name.clone(),
            uid: user.uid,
            gid: user.gid,
            home: user.home.clone(),
        });
    Ok(VmView {
        id: machine.id.clone(),
        name: machine.name.clone(),
        owner_login: if owner.is_tag() {
            String::new()
        } else {
            label(machine, LOGIN_LABEL).into()
        },
        owner,
        state: state(machine).into(),
        created: timestamp(machine.created_at.as_ref()).unwrap_or(chrono::DateTime::UNIX_EPOCH),
        default_user: guest_user
            .as_ref()
            .map_or_else(|| "root".into(), |user| user.name.clone()),
        guest_user,
        image: if machine
            .rootfs
            .as_ref()
            .is_some_and(|root| root.source_kind == w::ImageSourceKind::Oci as i32)
        {
            machine.image_ref.clone()
        } else {
            String::new()
        },
        template: label(machine, TEMPLATE_LABEL).into(),
        policy: label(machine, POLICY_LABEL).into(),
        tags: serde_json::from_str(label(machine, TAGS_LABEL)).unwrap_or_default(),
        guest_tcp_ports: serde_json::from_str(label(machine, GUEST_PORTS_LABEL))
            .unwrap_or_default(),
        labels: machine
            .labels
            .iter()
            .filter(|(key, _)| !key.starts_with("io.silo."))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        cpus: hardware
            .and_then(|hardware| hardware.cpus)
            .and_then(|cpus| u8::try_from(cpus).ok())
            .unwrap_or_default(),
        memory: hardware
            .and_then(|hardware| hardware.memory_bytes)
            .unwrap_or_default(),
        disk: machine.root_disk_size.unwrap_or_default(),
        node_state: "none".into(),
        key_expiry: "unknown".into(),
        address: "unknown".into(),
        ..VmView::default()
    })
}

impl Service {
    pub(crate) async fn inspect_for(
        &self,
        peer: &Peer,
        reference: &str,
        action: Action,
    ) -> Outcome<w::MachineSnapshot> {
        self.authorize(peer, action, None)?;
        let machine = self
            .management()
            .inspect(reference)
            .await
            .map_err(|status| categorize(&status))?;
        self.authorize(peer, action, Some(&machine))?;
        if !matches!(action, Action::Read | Action::Logs) {
            self.ensure_secret_scope(&machine).await?;
        }
        Ok(machine)
    }
    pub(crate) async fn ensure_secret_scope(&self, machine: &w::MachineSnapshot) -> Outcome<()> {
        if machine.labels.contains_key(INSTANCE_LABEL)
            && self
                .management()
                .secret_scope(&machine.id)
                .await
                .map_err(|status| categorize(&status))?
                != libvm::SecretScopePolicy::MachineOnly
        {
            return Err(Failure::new(
                Code::Conflict,
                "lobby VM requires Machine-only secret scope",
            ));
        }
        Ok(())
    }
    pub(crate) async fn list(&self, peer: &Peer) -> Outcome<Vec<VmView>> {
        self.authorize(peer, Action::Read, None)?;
        let mut out = Vec::new();
        for entry in self
            .management()
            .inventory()
            .await
            .map_err(|status| categorize(&status))?
        {
            if let Some(machine) = entry.data {
                if managed(&machine, &self.config.instance)
                    && owner(&machine).is_ok_and(|owner| peer.owns(&owner))
                {
                    let machine = self.inspect_for(peer, &machine.id, Action::Read).await?;
                    out.push(self.node_view(&machine)?);
                }
            }
        }
        Ok(out)
    }
    pub(crate) async fn show(&self, peer: &Peer, reference: &str) -> Outcome<VmView> {
        let machine = self.inspect_for(peer, reference, Action::Read).await?;
        let mut view = self.node_view(&machine)?;
        if !view.owner.is_tag() && !peer.login.is_empty() {
            view.owner_login.clone_from(&peer.login);
        }
        Ok(view)
    }
    pub(crate) fn ops(&self, peer: &Peer, id: &str) -> Outcome<Vec<Operation>> {
        self.authorize(peer, Action::Read, None)?;
        if id.is_empty() {
            Ok(self.jobs().list(peer))
        } else {
            Ok(vec![self.jobs().observe(peer, id)?.0])
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::service::{testing, vm::*};
    #[test]
    fn projection_filters_authority_and_native_details() {
        let machine = w::MachineSnapshot {
            id: "id".into(),
            name: "safe".into(),
            labels: [
                (OWNER_LABEL.into(), "user:1".into()),
                (NAME_LABEL.into(), "safe".into()),
                (INSTANCE_LABEL.into(), "instance".into()),
                (LOGIN_LABEL.into(), "alice".into()),
                ("team".into(), "blue".into()),
            ]
            .into(),
            last_error: Some("private path".into()),
            guest: Some(w::GuestConfig {
                user: Some(w::User {
                    name: "guest".into(),
                    uid: 1000,
                    gid: 1000,
                    home: "/home/guest".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(managed(&machine, "instance"));
        assert!(!managed(&machine, "other"));
        let view = project(&machine).unwrap();
        assert_eq!(view.default_user, "guest");
        assert_eq!(view.owner_login, "alice");
        assert_eq!(view.labels.len(), 1);
        assert!(!serde_json::to_string(&view)
            .unwrap()
            .contains("private path"));
        let mut forged = machine.clone();
        forged.name = "other".into();
        assert!(!managed(&forged, "instance"));
        forged = machine.clone();
        forged.labels.insert(OWNER_LABEL.into(), "user:0".into());
        assert!(!managed(&forged, "instance"));
    }
    #[tokio::test]
    async fn principal_isolation_is_not_found() {
        let fixture = testing::fixture().await;
        let alice = testing::caller("user:1", &[Action::Read]);
        let bob = testing::caller("user:2", &[Action::Read]);
        let machine = testing::stopped_vm(&fixture, "owned", "user:1").await;
        assert_eq!(
            fixture
                .service
                .show(&alice.peer, &machine.id)
                .await
                .unwrap()
                .name,
            "owned"
        );
        assert!(fixture.service.list(&bob.peer).await.unwrap().is_empty());
        assert_eq!(
            fixture
                .service
                .show(&bob.peer, &machine.id)
                .await
                .unwrap_err()
                .exit,
            3
        );
    }
    #[tokio::test]
    async fn capability_denial_precedes_machine_lookup() {
        let fixture = testing::fixture().await;
        let denied = testing::caller("tag:ci", &[]);
        for action in [Action::Read, Action::Delete, Action::Start, Action::Shell] {
            assert_eq!(
                fixture
                    .service
                    .inspect_for(&denied.peer, "missing", action)
                    .await
                    .unwrap_err()
                    .exit,
                4
            );
        }
        assert_eq!(
            fixture
                .service
                .preflight_remove(&denied, "missing", false)
                .await
                .err()
                .unwrap()
                .exit,
            4
        );
    }

    #[tokio::test]
    async fn lobby_secret_scope_invariant_refuses_legacy_and_permissive_machines() {
        use crate::lobby::service::lifecycle::{RemoveRequest, SetRequest, StopRequest};
        use crate::lobby::service::{
            files::CopyRequest,
            streams::{tests::captured_io, ExecRequest},
        };
        use crate::lobby::session::SessionExtras;

        let fixture = testing::fixture().await;
        let caller = testing::caller(
            "user:1",
            &[
                Action::Read,
                Action::Create,
                Action::Start,
                Action::Stop,
                Action::Delete,
                Action::Update,
                Action::Shell,
                Action::Exec,
                Action::Files,
            ],
        );
        for legacy in [false, true] {
            let machine = testing::stopped_vm_with_scope(
                &fixture,
                if legacy { "legacy" } else { "permissive" },
                "user:1",
                libvm::SecretScopePolicy::MachineThenHome,
            )
            .await;
            if legacy {
                let pool = sqlx::SqlitePool::connect(&format!(
                    "sqlite://{}",
                    fixture.root.path().join("home/state.db").display()
                ))
                .await
                .unwrap();
                let result = sqlx::query(
                    "UPDATE machine_config SET config_json = jsonb_remove(config_json, '$.secretScope') WHERE id = ?",
                )
                .bind(&machine.id)
                .execute(&pool)
                .await
                .unwrap();
                assert_eq!(result.rows_affected(), 1);
                pool.close().await;
            }
            assert!(fixture
                .service
                .show(&caller.peer, &machine.id)
                .await
                .is_ok());
            assert_eq!(
                fixture
                    .service
                    .start(&caller, &machine.id)
                    .await
                    .unwrap_err()
                    .exit,
                5
            );
            assert_eq!(
                fixture
                    .service
                    .restart(&caller, &machine.id)
                    .await
                    .unwrap_err()
                    .exit,
                5
            );
            assert_eq!(
                fixture
                    .service
                    .stop(&caller, &machine.id, StopRequest::default())
                    .await
                    .unwrap_err()
                    .exit,
                5
            );
            assert_eq!(
                fixture
                    .service
                    .remove(&caller, &machine.id, RemoveRequest::default())
                    .await
                    .unwrap_err()
                    .exit,
                5
            );
            assert_eq!(
                fixture
                    .service
                    .set(
                        &caller,
                        &machine.id,
                        SetRequest {
                            cpus: Some(3),
                            ..Default::default()
                        }
                    )
                    .await
                    .unwrap_err()
                    .exit,
                5
            );
            for action in [Action::Create, Action::Shell, Action::Exec, Action::Files] {
                let error = fixture
                    .service
                    .inspect_for(&caller.peer, &machine.id, action)
                    .await
                    .unwrap_err();
                assert_eq!(error.code, Code::Conflict, "{action}");
                assert_eq!(error.exit, 5, "{action}");
            }
            let mut captured = captured_io(Vec::new(), true);
            let shell = fixture
                .service
                .shell(
                    &caller,
                    &machine.id,
                    "",
                    &mut captured.io,
                    &SessionExtras {
                        prompt: None,
                        approval_shown: None,
                    },
                )
                .await
                .unwrap_err();
            let exec = fixture
                .service
                .exec(
                    &caller,
                    &machine.id,
                    ExecRequest {
                        program: "/bin/true".into(),
                        ..Default::default()
                    },
                    &mut captured.io,
                )
                .await
                .unwrap_err();
            let upload = fixture
                .service
                .copy_to_vm(
                    &caller,
                    CopyRequest {
                        vm: machine.id.clone(),
                        path: "/tmp/file".into(),
                        upload: true,
                        ..Default::default()
                    },
                    &mut captured.io,
                )
                .await
                .unwrap_err();
            let download = fixture
                .service
                .copy_from_vm(
                    &caller,
                    CopyRequest {
                        vm: machine.id.clone(),
                        path: "/tmp/file".into(),
                        ..Default::default()
                    },
                    &mut captured.io,
                )
                .await
                .unwrap_err();
            for error in [shell, exec, upload, download] {
                assert_eq!(error.exit, 5);
                assert_eq!(error.message, "lobby VM requires Machine-only secret scope");
            }
            let foreign = testing::caller("user:2", &[Action::Start]);
            assert_eq!(
                fixture
                    .service
                    .inspect_for(&foreign.peer, &machine.id, Action::Start)
                    .await
                    .unwrap_err()
                    .exit,
                3
            );
        }
        let safe = testing::stopped_vm(&fixture, "safe", "user:1").await;
        for action in [
            Action::Start,
            Action::Stop,
            Action::Delete,
            Action::Update,
            Action::Shell,
            Action::Exec,
            Action::Files,
        ] {
            assert!(
                fixture
                    .service
                    .inspect_for(&caller.peer, &safe.id, action)
                    .await
                    .is_ok(),
                "{action}"
            );
        }
    }
}
