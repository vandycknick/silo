pub(crate) mod create;
pub(crate) mod disk;
pub(crate) mod documents;
pub(crate) mod enrollment;
pub(crate) mod files;
mod guest_identity;
pub(crate) mod lifecycle;
pub(crate) mod store;
pub(crate) mod streams;
#[cfg(test)]
pub(crate) mod testing;
pub(crate) mod vm;

use crate::config::tailscale::TailscaleConfig;
use crate::daemon::control::lobby::{categorize, Management};
use crate::lobby::service::{
    documents::{BoundVM, BoundVmState, Document, DocumentKind, DocumentTier},
    enrollment::{ConsentProvider, NodePin},
    store::{DocumentStore, DocumentValidator, WriteMode},
};
use crate::lobby::{
    audit::{Audit, Decision},
    caller::Caller,
    failure::{Code, Failure, Outcome},
    identity::{Action, Peer, Principal},
    jobs,
    views::{VersionView, WhoAmIView},
};
use futures::future::BoxFuture;
use silod_spec::daemon::v1 as w;
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Instant};

pub(crate) struct ServiceConfig {
    pub(crate) home: PathBuf,
    pub(crate) config_dir: PathBuf,
    pub(crate) management: Management,
    pub(crate) settings: TailscaleConfig,
    pub(crate) capability: String,
    pub(crate) instance: String,
    pub(crate) audit: Audit,
    pub(crate) jobs: Arc<jobs::Registry>,
    pub(crate) visible_names:
        Arc<dyn Fn() -> BoxFuture<'static, Outcome<Vec<String>>> + Send + Sync>,
    pub(crate) node_pin: Option<NodePin>,
    pub(crate) lobby_hostname: String,
    pub(crate) vm_nodes_enabled: bool,
    pub(crate) consent: Option<Arc<dyn ConsentProvider>>,
}

#[derive(Default)]
struct Admission {
    names: HashMap<String, Principal>,
    disks: HashMap<String, u64>,
    audit: HashMap<String, AuditBucket>,
}

struct AuditBucket {
    tokens: f64,
    updated: Instant,
}

impl Admission {
    fn audit(&mut self, node: &str, now: Instant) -> bool {
        if !self.audit.contains_key(node) {
            self.audit
                .retain(|_, bucket| now.duration_since(bucket.updated).as_secs() < 2);
        }
        let bucket = self.audit.entry(node.to_owned()).or_insert(AuditBucket {
            tokens: 40.0,
            updated: now,
        });
        bucket.tokens =
            (bucket.tokens + now.duration_since(bucket.updated).as_secs_f64() * 20.0).min(40.0);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

#[derive(Clone)]
pub(crate) struct Service {
    config: Arc<ServiceConfig>,
    store: Arc<DocumentStore>,
    create_lock: Arc<tokio::sync::Mutex<()>>,
    admission: Arc<parking_lot::Mutex<Admission>>,
}

#[derive(serde::Serialize)]
pub(crate) struct Health {
    pub(crate) runtime: bool,
    pub(crate) tailnet: bool,
}

impl Service {
    pub(crate) fn new(config: ServiceConfig) -> Outcome<Self> {
        let store = DocumentStore::new(config.home.clone(), config.config_dir.clone())?;
        Ok(Self {
            config: Arc::new(config),
            store: Arc::new(store),
            create_lock: Arc::new(tokio::sync::Mutex::new(())),
            admission: Arc::default(),
        })
    }

    pub(crate) fn config(&self) -> &ServiceConfig {
        &self.config
    }
    pub(crate) fn management(&self) -> &Management {
        &self.config.management
    }
    pub(crate) fn jobs(&self) -> &Arc<jobs::Registry> {
        &self.config.jobs
    }
    pub(crate) fn help_defaults(&self) -> std::collections::BTreeMap<String, String> {
        let (cpus, memory, disk) = self.config.settings.vm_defaults();
        [
            ("cpus", cpus.to_string()),
            (
                "memory",
                crate::lobby::grammar::render::human_memory(memory),
            ),
            ("disk", crate::lobby::grammar::render::human_memory(disk)),
        ]
        .into_iter()
        .map(|(key, value)| {
            (
                key.into(),
                format!("{value}; template takes precedence, explicit option overrides both"),
            )
        })
        .collect()
    }

    fn decision(&self, peer: &Peer, action: &str, result: Outcome<()>) -> Outcome<()> {
        let limited = result.is_err()
            || (peer.permissions.actions.is_empty() && matches!(action, "identity" | "whoami"));
        if limited && !self.admission.lock().audit(&peer.node_id, Instant::now()) {
            return Err(Failure::new(Code::Limit, "node audit rate limit reached"));
        }
        self.config
            .audit
            .append(Decision {
                time: chrono::Utc::now(),
                principals: peer.principals.clone(),
                node_id: peer.node_id.clone(),
                action: action.into(),
                allowed: result.is_ok(),
                code: result.as_ref().err().map(|error| error.code),
            })
            .map_err(|_| Failure::new(Code::Unavailable, "audit unavailable"))?;
        result
    }

    pub(crate) fn check_identity(&self, peer: &Peer) -> Outcome<()> {
        self.decision(
            peer,
            "identity",
            if peer.valid() {
                Ok(())
            } else {
                Err(Failure::new(Code::Forbidden, "verified identity required"))
            },
        )
    }

    pub(crate) fn whoami(&self, peer: &Peer) -> Outcome<WhoAmIView> {
        self.decision(
            peer,
            "whoami",
            if peer.valid() {
                Ok(())
            } else {
                Err(Failure::new(Code::Forbidden, "verified identity required"))
            },
        )?;
        Ok(WhoAmIView {
            peer: peer.clone(),
            capability: self.config.capability.clone(),
            explanation: peer.permissions.reason.clone(),
        })
    }

    pub(crate) fn authorize(
        &self,
        peer: &Peer,
        action: Action,
        machine: Option<&w::MachineSnapshot>,
    ) -> Outcome<()> {
        let result = if let Some(machine) = machine {
            if !vm::managed(machine, &self.config.instance) || !peer.owns(&vm::owner(machine)?) {
                Err(Failure::new(Code::NotFound, "VM not found"))
            } else {
                allow(peer, action)
            }
        } else {
            allow(peer, action)
        };
        self.decision(peer, action.as_str(), result)
    }

    pub(crate) async fn health(&self, peer: &Peer) -> Outcome<Health> {
        self.authorize(peer, Action::Read, None)?;
        self.management()
            .inventory()
            .await
            .map_err(|status| categorize(&status))?;
        Ok(Health {
            runtime: true,
            tailnet: true,
        })
    }

    pub(crate) fn versions(&self) -> VersionView {
        VersionView {
            lobby: env!("CARGO_PKG_VERSION").into(),
            silod: env!("CARGO_PKG_VERSION").into(),
            tailscale: "1.102.5".into(),
        }
    }

    pub(crate) async fn reload_documents(&self) -> Outcome<()> {
        self.store.reload_operator(self).await
    }

    pub(crate) async fn documents(
        &self,
        caller: &Caller,
        kind: &str,
        verb: &str,
        name: &str,
        owner: Option<&Principal>,
        raw: &str,
    ) -> Outcome<Vec<Document>> {
        let write = matches!(verb, "create" | "edit" | "rm");
        let peer = if write {
            caller.fresh().await?
        } else {
            caller.peer.clone()
        };
        self.authorize(
            &peer,
            if write {
                Action::TemplateManage
            } else {
                Action::Read
            },
            None,
        )?;
        let kind = match kind {
            "template" => DocumentKind::Template,
            "policy" => DocumentKind::Policy,
            _ => return Err(Failure::new(Code::Usage, "invalid document kind")),
        };
        if verb == "validate" {
            return Ok(vec![self.validate(kind, raw.into()).await?]);
        }
        if verb == "ls" && owner.is_none() && peer.principals.len() > 1 {
            let mut yours = Vec::new();
            let mut operator = Vec::new();
            for (index, principal) in peer.principals.iter().enumerate() {
                for document in self.store.list(kind, principal, self).await? {
                    if document.tier == Some(DocumentTier::Yours) {
                        yours.push(document);
                    } else if index == 0 {
                        operator.push(document);
                    }
                }
            }
            yours.extend(operator);
            return Ok(yours);
        }
        let principal = documents::selected_owner(&peer, owner)?;
        let mut out = self
            .documents_for(kind, verb, name, &principal, raw)
            .await?;
        if kind == DocumentKind::Policy && matches!(verb, "edit" | "rm") {
            let bindings = self
                .list(&peer)
                .await?
                .into_iter()
                .filter(|vm| vm.policy == name && vm.owner == principal)
                .map(|vm| BoundVM {
                    name: vm.name,
                    state: match vm.state.as_str() {
                        "stopped" => BoundVmState::Stopped,
                        "starting" => BoundVmState::Starting,
                        "running" => BoundVmState::Running,
                        "stopping" => BoundVmState::Stopping,
                        "error" => BoundVmState::Error,
                        _ => BoundVmState::Unknown,
                    },
                })
                .collect();
            if let Some(document) = out.first_mut() {
                document.bound_vms = bindings;
            }
        }
        Ok(out)
    }

    async fn documents_for(
        &self,
        kind: DocumentKind,
        verb: &str,
        name: &str,
        owner: &Principal,
        raw: &str,
    ) -> Outcome<Vec<Document>> {
        let document = match verb {
            "ls" => return self.store.list(kind, owner, self).await,
            "show" => self.store.read(kind, owner, name, self).await?,
            "create" | "edit" => {
                self.store
                    .write(
                        kind,
                        owner,
                        name,
                        raw.into(),
                        if verb == "create" {
                            WriteMode::Create
                        } else {
                            WriteMode::Edit
                        },
                        self,
                    )
                    .await?
            }
            "rm" => self.store.remove(kind, owner, name, self).await?,
            _ => return Err(Failure::new(Code::Usage, "invalid document operation")),
        };
        Ok(vec![document])
    }

    async fn parse_policy(&self, raw: &str) -> Outcome<w::PolicyDocument> {
        documents::parse_remote_policy(raw, &mut |request| async {
            self.management()
                .normalize_policy(request)
                .await
                .map_err(|status| categorize(&status))
        })
        .await
    }

    async fn check_secrets(&self, policy: &w::PolicyDocument) -> Outcome<()> {
        documents::check_secrets(policy, |request| async {
            self.management()
                .check_policy_secrets(request)
                .await
                .map_err(|status| categorize(&status))
        })
        .await
    }
}

impl DocumentValidator for Service {
    fn validate(&self, kind: DocumentKind, raw: String) -> BoxFuture<'_, Outcome<Document>> {
        Box::pin(async move {
            documents::validate_document(kind, &raw, &mut |request| async {
                self.management()
                    .normalize_policy(request)
                    .await
                    .map_err(|status| categorize(&status))
            })
            .await
        })
    }
}

fn allow(peer: &Peer, action: Action) -> Outcome<()> {
    if !peer.valid() {
        return Err(Failure::new(Code::Forbidden, "verified identity required"));
    }
    let granted = if action == Action::Restart {
        peer.permissions.has(Action::Start) && peer.permissions.has(Action::Stop)
    } else {
        peer.permissions.has(action)
    };
    if granted {
        Ok(())
    } else {
        Err(Failure::new(
            Code::Forbidden,
            format!("{action} capability required"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::{
        identity::Action,
        service::{allow, testing},
    };

    #[tokio::test]
    async fn flooding_node_is_limited_without_blocking_another_node() {
        let fixture = testing::fixture().await;
        let flood = testing::caller("user:1", &[]);
        for _ in 0..40 {
            assert_eq!(
                fixture
                    .service
                    .authorize(&flood.peer, Action::Read, None)
                    .unwrap_err()
                    .exit,
                4
            );
        }
        assert_eq!(
            fixture
                .service
                .check_identity(&flood.peer)
                .unwrap_err()
                .exit,
            6
        );
        let mut invalid = flood.peer.clone();
        invalid.principals.clear();
        assert_eq!(
            fixture.service.check_identity(&invalid).unwrap_err().exit,
            6
        );
        assert_eq!(
            fixture
                .service
                .authorize(&flood.peer, Action::Read, None)
                .unwrap_err()
                .exit,
            6
        );
        let mut other = testing::caller("user:2", &[Action::Read]).peer;
        other.node_id = "another-node".into();
        assert!(fixture.service.check_identity(&other).is_ok());
        assert!(fixture
            .service
            .authorize(&other, Action::Read, None)
            .is_ok());
        fixture.service.config().audit.close().await.unwrap();
        let records =
            std::fs::read_to_string(fixture.root.path().join("home/lobby/audit.log")).unwrap();
        assert_eq!(records.lines().count(), 42);
    }

    #[tokio::test]
    async fn granted_node_can_issue_more_than_forty_rapid_allowed_commands() {
        let fixture = testing::fixture().await;
        let granted = testing::caller("user:1", &[Action::Read]);
        for _ in 0..100 {
            assert!(fixture.service.check_identity(&granted.peer).is_ok());
            assert!(fixture.service.whoami(&granted.peer).is_ok());
            assert!(fixture
                .service
                .authorize(&granted.peer, Action::Read, None)
                .is_ok());
        }
        fixture.service.config().audit.close().await.unwrap();
        let records =
            std::fs::read_to_string(fixture.root.path().join("home/lobby/audit.log")).unwrap();
        assert_eq!(records.lines().count(), 300);
    }

    #[test]
    fn audit_bucket_refills_and_expires_inactive_nodes() {
        let mut admission = crate::lobby::service::Admission::default();
        let now = std::time::Instant::now();
        for _ in 0..40 {
            assert!(admission.audit("first", now));
        }
        assert!(!admission.audit("first", now));
        assert!(admission.audit("first", now + std::time::Duration::from_millis(50)));
        assert!(!admission.audit("first", now + std::time::Duration::from_millis(50)));
        assert!(admission.audit("second", now + std::time::Duration::from_secs(3)));
        assert!(!admission.audit.contains_key("first"));
    }

    #[tokio::test]
    async fn identity_audit_and_health_use_real_services() {
        let fixture = testing::fixture().await;
        let caller = testing::caller("user:1", &[]);
        assert!(fixture.service.check_identity(&caller.peer).is_ok());
        assert!(fixture.service.whoami(&caller.peer).is_ok());
        assert_eq!(
            fixture
                .service
                .health(&caller.peer)
                .await
                .err()
                .unwrap()
                .exit,
            4
        );
        let reader = testing::caller("user:1", &[Action::Read]);
        assert!(fixture.service.health(&reader.peer).await.unwrap().runtime);
        assert_eq!(
            fixture
                .service
                .check_identity(&Default::default())
                .unwrap_err()
                .exit,
            4
        );
        fixture.service.config().audit.close().await.unwrap();
        let audit =
            std::fs::read_to_string(fixture.root.path().join("home/lobby/audit.log")).unwrap();
        let records: Vec<serde_json::Value> = audit
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 5);
        assert_eq!(records[2]["allowed"], false);
        assert_eq!(records[2]["code"], "forbidden");
        assert_eq!(fixture.service.versions().tailscale, "1.102.5");
        assert_eq!(
            fixture
                .service
                .check_identity(&caller.peer)
                .unwrap_err()
                .code,
            crate::lobby::failure::Code::Unavailable
        );
    }

    #[test]
    fn restart_requires_both_primitive_permissions() {
        for (actions, granted) in [
            (vec![], false),
            (vec![Action::Start], false),
            (vec![Action::Stop], false),
            (vec![Action::Restart], false),
            (vec![Action::Start, Action::Stop], true),
        ] {
            let caller = testing::caller("user:1", &actions);
            assert_eq!(allow(&caller.peer, Action::Restart).is_ok(), granted);
        }
    }
}
