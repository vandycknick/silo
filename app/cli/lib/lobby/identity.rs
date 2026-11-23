use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::tailnet::wire::Whois;
use crate::lobby::units;

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct Principal(String);

impl Principal {
    pub(crate) fn parse(value: &str) -> Outcome<Self> {
        if valid_principal(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(Failure::new(Code::Forbidden, "invalid principal"))
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn is_tag(&self) -> bool {
        self.0.starts_with("tag:")
    }
}

fn valid_principal(value: &str) -> bool {
    let user = value.strip_prefix("user:").is_some_and(|id| {
        !id.starts_with('0')
            && id.bytes().all(|b| b.is_ascii_digit())
            && id.parse::<u64>().is_ok_and(|n| n > 0)
    });
    let tag = value.strip_prefix("tag:").is_some_and(|tag| {
        tag.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    user || tag
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Principal {
    type Err = Failure;
    fn from_str(value: &str) -> Outcome<Self> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn canonical_dns(value: &str) -> String {
    let mut value = value.to_lowercase();
    if value.ends_with('.') {
        value.pop();
    }
    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Action {
    #[serde(rename = "vm.create")]
    Create,
    #[serde(rename = "vm.read")]
    Read,
    #[serde(rename = "vm.start")]
    Start,
    #[serde(rename = "vm.stop")]
    Stop,
    #[serde(rename = "vm.delete")]
    Delete,
    #[serde(rename = "vm.shell")]
    Shell,
    #[serde(rename = "vm.exec")]
    Exec,
    #[serde(rename = "vm.logs")]
    Logs,
    #[serde(rename = "vm.files")]
    Files,
    #[serde(rename = "vm.update")]
    Update,
    #[serde(rename = "template.manage")]
    TemplateManage,
    #[serde(rename = "vm.restart")]
    Restart,
}

impl Action {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Create => "vm.create",
            Self::Read => "vm.read",
            Self::Start => "vm.start",
            Self::Stop => "vm.stop",
            Self::Delete => "vm.delete",
            Self::Shell => "vm.shell",
            Self::Exec => "vm.exec",
            Self::Logs => "vm.logs",
            Self::Files => "vm.files",
            Self::Update => "vm.update",
            Self::TemplateManage => "template.manage",
            Self::Restart => "vm.restart",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(crate) fn actions() -> &'static [Action] {
    &[
        Action::Create,
        Action::Read,
        Action::Start,
        Action::Stop,
        Action::Delete,
        Action::Shell,
        Action::Exec,
        Action::Logs,
        Action::Files,
        Action::Update,
        Action::TemplateManage,
    ]
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Limits {
    pub(crate) vms: u64,
    pub(crate) cpus: u64,
    pub(crate) memory: u64,
    pub(crate) disk: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Permissions {
    pub(crate) actions: Vec<Action>,
    pub(crate) limits: Limits,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) reason: String,
}

impl Permissions {
    pub(crate) fn has(&self, action: Action) -> bool {
        self.actions.contains(&action)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Peer {
    pub(crate) principals: Vec<Principal>,
    pub(crate) node_id: String,
    pub(crate) node_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) login: String,
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) permissions: Permissions,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            principals: Vec::new(),
            node_id: String::new(),
            node_name: String::new(),
            login: String::new(),
            observed_at: DateTime::<Utc>::from_timestamp(-62_135_596_800, 0)
                .unwrap_or(DateTime::<Utc>::MIN_UTC),
            permissions: Permissions::default(),
        }
    }
}

impl Peer {
    pub(crate) fn valid(&self) -> bool {
        !self.principals.is_empty()
            && !self.node_id.is_empty()
            && (self.observed_at.timestamp() != -62_135_596_800
                || self.observed_at.timestamp_subsec_nanos() != 0)
            && self.principals.iter().all(|p| valid_principal(p.as_str()))
    }
    pub(crate) fn owns(&self, owner: &Principal) -> bool {
        self.principals.contains(owner)
    }
}

pub(crate) fn from_whois(whois: &Whois, defaults: Limits) -> Outcome<Peer> {
    if whois.node_id.is_empty() {
        return Err(Failure::new(Code::Forbidden, "WhoIs returned no identity"));
    }
    let mut principals = Vec::new();
    if whois.tags.is_empty() {
        if whois.login_name == "tagged-devices" {
            return Err(Failure::new(Code::Forbidden, "tagged peer has no tags"));
        }
        if whois.user_id <= 0 {
            return Err(Failure::new(Code::Forbidden, "invalid principal"));
        }
        principals.push(Principal(format!("user:{}", whois.user_id)));
    } else {
        for tag in &whois.tags {
            let principal = Principal::parse(tag)?;
            if !principals.contains(&principal) {
                principals.push(principal);
            }
        }
    }
    Ok(Peer {
        principals,
        node_id: whois.node_id.clone(),
        node_name: whois.node_name.clone(),
        login: whois.login_name.clone(),
        observed_at: Utc::now(),
        permissions: parse_capabilities(&whois.capability, defaults),
    })
}

fn denied() -> Permissions {
    Permissions {
        reason: "No valid own-scope lobby capability was granted".into(),
        ..Permissions::default()
    }
}

fn malformed() -> Permissions {
    Permissions {
        reason: "Malformed lobby capability".into(),
        ..Permissions::default()
    }
}

pub(crate) fn parse_capabilities(values: &[Value], defaults: Limits) -> Permissions {
    let mut result = denied();
    for value in values {
        let Some(fields) = value.as_object() else {
            return malformed();
        };
        if let Some(scope) = fields.get("scope") {
            match scope.as_str() {
                Some("own") => {}
                Some(_) => continue,
                None => return malformed(),
            }
        }
        let Some(raw_actions) = fields.get("actions").and_then(Value::as_array) else {
            return malformed();
        };
        if raw_actions.is_empty() || raw_actions.iter().any(|a| !a.is_string()) {
            return malformed();
        }
        let mut limits = defaults;
        if let Some(raw_limits) = fields.get("limits") {
            let Some(fields) = raw_limits.as_object() else {
                return malformed();
            };
            for (name, dest) in [("vms", &mut limits.vms), ("cpus", &mut limits.cpus)] {
                if let Some(value) = fields.get(name) {
                    let Some(value) = value.as_u64() else {
                        return malformed();
                    };
                    *dest = value;
                }
            }
            let mut sizes = [None; 2];
            for (index, name) in ["memory", "disk"].into_iter().enumerate() {
                if let Some(value) = fields.get(name) {
                    let Some(value) = value.as_str() else {
                        return malformed();
                    };
                    sizes[index] = Some(value);
                }
            }
            for (value, dest) in sizes
                .into_iter()
                .zip([&mut limits.memory, &mut limits.disk])
            {
                if let Some(value) = value {
                    let Ok(value) = units::bytes(value) else {
                        return denied();
                    };
                    *dest = value;
                }
            }
        }
        for raw in raw_actions {
            let Some(raw) = raw.as_str() else {
                return malformed();
            };
            if raw == "*" {
                for action in actions() {
                    if !result.has(*action) {
                        result.actions.push(*action);
                    }
                }
            } else if let Some(action) = actions().iter().find(|a| a.as_str() == raw) {
                if !result.has(*action) {
                    result.actions.push(*action);
                }
            } else {
                tracing::info!(action = raw, "ignoring unknown capability action");
            }
        }
        result.limits.vms = result.limits.vms.max(limits.vms);
        result.limits.cpus = result.limits.cpus.max(limits.cpus);
        result.limits.memory = result.limits.memory.max(limits.memory);
        result.limits.disk = result.limits.disk.max(limits.disk);
    }
    result.actions.sort_by_key(|action| action.as_str());
    if !result.actions.is_empty() {
        result.reason.clear();
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::lobby::identity::{
        actions, canonical_dns, from_whois, parse_capabilities, Action, Limits, Peer, Principal,
    };
    use crate::lobby::tailnet::wire::Whois;
    use serde_json::{json, Value};

    fn defaults() -> Limits {
        Limits {
            vms: 5,
            cpus: 8,
            memory: 32 << 30,
            disk: 200 << 30,
        }
    }
    fn parse(raw: &str) -> crate::lobby::identity::Permissions {
        let values: Vec<Value> = serde_json::from_str(&format!("[{raw}]")).unwrap();
        parse_capabilities(&values, defaults())
    }

    #[test]
    fn capability_table() {
        for (raw, count, vms) in [
            ("", 0, 0),
            (r#"{"actions":["vm.read"]}"#, 1, 5),
            (
                r#"{"actions":["vm.read"],"limits":{"vms":2}},{"actions":["vm.exec"],"limits":{"vms":9,"memory":"64GiB"}}"#,
                2,
                9,
            ),
            (r#"{"actions":["*"]}"#, actions().len(), 5),
            (r#"{"actions":["future","vm.read"]}"#, 1, 5),
            (r#"{"actions":["*"],"scope":"all"}"#, 0, 0),
            (r#"{"actions":["vm.read"]},{"actions":"*"}"#, 0, 0),
            (r#"{"actions":["vm.read"],"limits":{"memory":"wat"}}"#, 0, 0),
            ("null", 0, 0),
            (r#"{"limits":{"vms":50}}"#, 0, 0),
            (r#"{"actions":null}"#, 0, 0),
            (r#"{"actions":["vm.read",null]}"#, 0, 0),
            (r#"{"actions":["vm.read",1]}"#, 0, 0),
            (r#"{"actions":["vm.read"],"scope":null}"#, 0, 0),
            (r#"{"actions":["vm.read"],"scope":1}"#, 0, 0),
            (r#"{"actions":["vm.read"],"limits":null}"#, 0, 0),
            (r#"{"actions":["vm.read"],"limits":1}"#, 0, 0),
            (r#"{"actions":["vm.read"],"limits":[]}"#, 0, 0),
            (
                r#"{"actions":["vm.read"]},{"scope":"future","actions":1}"#,
                1,
                5,
            ),
            (
                r#"{"actions":["vm.read"]},{"scope":"future","actions":null,"limits":null}"#,
                1,
                5,
            ),
            (
                r#"{"actions":["vm.read"]},{"scope":"future","actions":[null],"limits":{"vms":-1}}"#,
                1,
                5,
            ),
            (
                r#"{"actions":["vm.read"]},{"scope":"own","actions":[null]}"#,
                0,
                0,
            ),
        ] {
            let permissions = parse(raw);
            assert_eq!(permissions.actions.len(), count, "{raw}");
            assert_eq!(permissions.limits.vms, vms, "{raw}");
        }
    }

    #[test]
    fn limit_defaults_and_types() {
        for (raw, limits) in [
            (r#"{"actions":["vm.read"]}"#, defaults()),
            (
                r#"{"actions":["vm.read"],"scope":"own","limits":{}}"#,
                defaults(),
            ),
            (
                r#"{"actions":["vm.read"],"limits":{"vms":0}}"#,
                Limits {
                    vms: 0,
                    ..defaults()
                },
            ),
            (
                r#"{"actions":["vm.read"],"limits":{"vms":0,"cpus":0,"memory":"0B","disk":"0GiB"}}"#,
                Limits::default(),
            ),
            (
                r#"{"actions":["vm.read"],"limits":{"vms":0,"cpus":0,"memory":"0B","disk":"0B"}},{"actions":["vm.exec"]}"#,
                defaults(),
            ),
        ] {
            let permissions = parse(raw);
            assert!(permissions.has(Action::Read));
            assert_eq!(permissions.limits, limits);
        }
        for field in ["vms", "cpus", "memory", "disk"] {
            let mut bad = vec!["null", "true", "{}", "[]"];
            if field == "vms" || field == "cpus" {
                bad.extend([r#""0""#, "-1", "1.5", "18446744073709551616"]);
            } else {
                bad.extend(["0", "1.5", r#""1.5GiB""#]);
            }
            for value in bad {
                let raw = format!(
                    r#"{{"actions":["vm.read"]}},{{"scope":"own","actions":["vm.exec"],"limits":{{"{field}":{value}}}}}"#
                );
                let permissions = parse(&raw);
                assert!(permissions.actions.is_empty(), "{raw}");
                assert_eq!(permissions.limits, Limits::default(), "{raw}");
            }
        }
    }

    #[test]
    fn whois_and_principal_table() {
        let mut whois: Whois = serde_json::from_value(
            json!({"node_id":"node-1","node_name":"peer","user_id":123,"login_name":"root"}),
        )
        .unwrap();
        let peer = from_whois(&whois, Limits::default()).unwrap();
        assert_eq!(peer.principals, vec![Principal::parse("user:123").unwrap()]);
        assert!(peer.valid());
        whois.tags = vec!["tag:ci".into(), "tag:build".into(), "tag:ci".into()];
        whois.login_name = "forged-owner".into();
        let peer = from_whois(&whois, Limits::default()).unwrap();
        assert_eq!(peer.principals.len(), 2);
        assert_eq!(peer.principals[0].as_str(), "tag:ci");
        whois.tags.clear();
        whois.login_name = "tagged-devices".into();
        assert!(from_whois(&whois, Limits::default()).is_err());
        for value in [
            "",
            "user:0",
            "user:01",
            "user:-1",
            "tag:../x",
            "tag:x/y",
            "user:18446744073709551616",
        ] {
            assert!(Principal::parse(value).is_err(), "{value}");
        }
        for value in ["user:1", "user:18446744073709551615", "tag:CI-12"] {
            assert_eq!(Principal::parse(value).unwrap().as_str(), value);
        }
        assert!(!Peer::default().valid());
        let mut epoch_peer = Peer {
            principals: vec![Principal::parse("user:1").unwrap()],
            node_id: "node".into(),
            ..Peer::default()
        };
        assert!(!epoch_peer.valid());
        epoch_peer.observed_at = chrono::DateTime::default();
        assert!(epoch_peer.valid());
        assert_eq!(canonical_dns("Peer.Tailnet."), "peer.tailnet");
        assert!(!parse(r#"{"actions":["*"]}"#).has(Action::Restart));
        assert_eq!(parse("null").reason, "Malformed lobby capability");
        assert_eq!(
            parse(r#"{"actions":["vm.read"],"limits":{"memory":"wat"}}"#).reason,
            "No valid own-scope lobby capability was granted"
        );
        assert_eq!(
            parse(r#"{"actions":["vm.read"],"limits":{"memory":"wat","disk":null}}"#).reason,
            "Malformed lobby capability"
        );
    }
}
