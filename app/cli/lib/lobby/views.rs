use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};

use crate::lobby::identity::{Peer, Principal};
use crate::lobby::service::documents::{
    BoundVmState, Document, DocumentKind, DocumentTier, SecretMetadata, Template,
};

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct GuestUserView {
    pub(crate) name: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VmView {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) owner_login: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_time"
    )]
    pub(crate) key_expiry_observed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) key_expiry_last_known: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) guest_user: Option<GuestUserView>,
    pub(crate) default_user: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) node_diagnostics: Vec<String>,
    pub(crate) node_state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) node_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) addresses: Vec<String>,
    pub(crate) key_expiry: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) approval_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) template: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) policy: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) forwards: Vec<ForwardView>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) guest_tcp_ports: Vec<u16>,
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) owner: Principal,
    pub(crate) state: String,
    pub(crate) node: String,
    pub(crate) address: String,
    pub(crate) cpus: u8,
    pub(crate) memory: u64,
    pub(crate) disk: u64,
    #[serde(serialize_with = "serialize_time")]
    pub(crate) created: DateTime<Utc>,
    pub(crate) image: String,
    pub(crate) labels: BTreeMap<String, String>,
}

impl Default for VmView {
    fn default() -> Self {
        let created = DateTime::UNIX_EPOCH - chrono::TimeDelta::seconds(62_135_596_800);
        Self {
            owner_login: String::new(),
            key_expiry_observed_at: None,
            key_expiry_last_known: false,
            tags: Vec::new(),
            guest_user: None,
            default_user: String::new(),
            node_diagnostics: Vec::new(),
            node_state: String::new(),
            node_id: String::new(),
            addresses: Vec::new(),
            key_expiry: String::new(),
            approval_url: String::new(),
            template: String::new(),
            policy: String::new(),
            forwards: Vec::new(),
            guest_tcp_ports: Vec::new(),
            id: String::new(),
            name: String::new(),
            owner: Principal::default(),
            state: String::new(),
            node: String::new(),
            address: String::new(),
            cpus: 0,
            memory: 0,
            disk: 0,
            created,
            image: String::new(),
            labels: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ForwardView {
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) listen_port: u16,
    pub(crate) target_port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) url: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct BoundVmView {
    pub(crate) name: String,
    pub(crate) state: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct DocumentView {
    pub(crate) name: String,
    pub(crate) tier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner: Option<Principal>,
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) template: Option<Template>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secrets: Option<SecretMetadata>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) bound_vms: Vec<BoundVmView>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WhoAmIView {
    pub(crate) peer: Peer,
    pub(crate) capability: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) explanation: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct VersionView {
    pub(crate) lobby: String,
    pub(crate) silod: String,
    pub(crate) tailscale: String,
}

impl From<Document> for DocumentView {
    fn from(doc: Document) -> Self {
        Self {
            name: doc.name,
            tier: match doc.tier {
                Some(DocumentTier::Yours) => "yours",
                Some(DocumentTier::Operator) => "operator",
                None => "",
            }
            .into(),
            owner: doc.owner,
            kind: match doc.kind {
                DocumentKind::Template => "template",
                DocumentKind::Policy => "policy",
            }
            .into(),
            content: doc.content,
            template: doc.template,
            secrets: doc.secrets,
            bound_vms: doc
                .bound_vms
                .into_iter()
                .map(|vm| BoundVmView {
                    name: vm.name,
                    state: match vm.state {
                        BoundVmState::Stopped => "stopped",
                        BoundVmState::Starting => "starting",
                        BoundVmState::Running => "running",
                        BoundVmState::Stopping => "stopping",
                        BoundVmState::Error => "error",
                        BoundVmState::Unknown => "unknown",
                    }
                    .into(),
                })
                .collect(),
        }
    }
}

fn serialize_time<S: Serializer>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

fn serialize_optional_time<S: Serializer>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(time) => serialize_time(time, serializer),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::service::documents::{
        BoundVM, BoundVmState, Document, DocumentKind, DocumentTier,
    };
    use crate::lobby::views::{DocumentView, VersionView, VmView};

    #[test]
    fn json_preserves_bytes_addresses_and_names() {
        let vm = VmView {
            memory: 1_610_612_736,
            disk: 200_000_000_000,
            address: "100.64.0.1".into(),
            addresses: vec!["100.64.0.1".into()],
            ..VmView::default()
        };
        let json = serde_json::to_value(vm).unwrap();
        assert_eq!(json["memory"], 1_610_612_736u64);
        assert_eq!(json["disk"], 200_000_000_000u64);
        assert_eq!(json["address"], "100.64.0.1");
        assert_eq!(json["addresses"][0], "100.64.0.1");
        assert!(json["created"].is_string());
        assert!(json.get("last_operation").is_none());
        assert!(json.get("guest_user").is_none());
        assert_eq!(
            serde_json::to_value(VersionView::default()).unwrap(),
            serde_json::json!({"lobby":"", "silod":"", "tailscale":""})
        );
    }

    #[test]
    fn document_conversion_preserves_identity_and_bindings() {
        let mut doc = Document::new(DocumentKind::Policy);
        doc.name = "web".into();
        doc.content = "policy".into();
        doc.tier = Some(DocumentTier::Yours);
        doc.bound_vms = vec![BoundVM {
            name: "dev".into(),
            state: BoundVmState::Running,
        }];
        let view = DocumentView::from(doc);
        let json = serde_json::to_value(view).unwrap();
        assert_eq!(json["kind"], "policy");
        assert_eq!(json["tier"], "yours");
        assert_eq!(json["content"], "policy");
        assert_eq!(
            json["bound_vms"],
            serde_json::json!([{"name":"dev", "state":"running"}])
        );
        let view = DocumentView::from(Document::new(DocumentKind::Template));
        assert_eq!(serde_json::to_value(view).unwrap()["tier"], "");
    }
}
