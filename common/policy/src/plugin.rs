use crate::model::{EndpointFamily, Transport};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EndpointSchema {
    Ip,
    Hosts,
    Registries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConditionKind {
    None,
    Http,
    Facet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FacetKind {
    String,
    StringListMap,
    Int,
    Bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FacetFieldDefinition {
    pub name: String,
    pub kind: FacetKind,
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FacetDefinition {
    pub name: String,
    pub fields: Vec<FacetFieldDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointDefinition {
    pub kind: String,
    pub family: EndpointFamily,
    pub transport: Transport,
    pub default_port: u16,
    pub schema: EndpointSchema,
    pub supports_credentials: bool,
    pub terminates_tls: bool,
}

impl EndpointDefinition {
    pub fn terminates_tls(&self) -> bool {
        self.terminates_tls
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FamilyDefinition {
    pub family: EndpointFamily,
    pub condition: ConditionKind,
    pub facets: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PluginRegistry {
    endpoints: BTreeMap<String, EndpointDefinition>,
    families: BTreeMap<EndpointFamily, FamilyDefinition>,
    facets: BTreeMap<String, FacetDefinition>,
}

impl PluginRegistry {
    pub fn builtins() -> Self {
        let families = BTreeMap::from([
            (
                EndpointFamily::Ip,
                FamilyDefinition {
                    family: EndpointFamily::Ip,
                    condition: ConditionKind::None,
                    facets: Vec::new(),
                },
            ),
            (
                EndpointFamily::Http,
                FamilyDefinition {
                    family: EndpointFamily::Http,
                    condition: ConditionKind::Http,
                    facets: vec!["http".to_owned()],
                },
            ),
            (
                EndpointFamily::Package,
                FamilyDefinition {
                    family: EndpointFamily::Package,
                    condition: ConditionKind::Facet,
                    facets: vec!["http".to_owned(), "package".to_owned()],
                },
            ),
        ]);
        let endpoints = BTreeMap::from([
            (
                "ip".to_owned(),
                EndpointDefinition {
                    kind: "ip".to_owned(),
                    family: EndpointFamily::Ip,
                    transport: Transport::PacketFilter,
                    default_port: 0,
                    schema: EndpointSchema::Ip,
                    supports_credentials: false,
                    terminates_tls: false,
                },
            ),
            (
                "http".to_owned(),
                EndpointDefinition {
                    kind: "http".to_owned(),
                    family: EndpointFamily::Http,
                    transport: Transport::HttpProxy,
                    default_port: 80,
                    schema: EndpointSchema::Hosts,
                    supports_credentials: false,
                    terminates_tls: false,
                },
            ),
            (
                "https".to_owned(),
                EndpointDefinition {
                    kind: "https".to_owned(),
                    family: EndpointFamily::Http,
                    transport: Transport::HttpsMitm,
                    default_port: 443,
                    schema: EndpointSchema::Hosts,
                    supports_credentials: true,
                    terminates_tls: true,
                },
            ),
            (
                "registries".to_owned(),
                EndpointDefinition {
                    kind: "registries".to_owned(),
                    family: EndpointFamily::Package,
                    transport: Transport::TlsTerminate,
                    default_port: 443,
                    schema: EndpointSchema::Registries,
                    supports_credentials: false,
                    terminates_tls: true,
                },
            ),
        ]);
        let facets = BTreeMap::from([
            (
                "http".to_owned(),
                FacetDefinition {
                    name: "http".to_owned(),
                    fields: vec![
                        FacetFieldDefinition {
                            name: "method".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "host".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "path".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "query".to_owned(),
                            kind: FacetKind::StringListMap,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "headers".to_owned(),
                            kind: FacetKind::StringListMap,
                            optional: false,
                        },
                    ],
                },
            ),
            (
                "package".to_owned(),
                FacetDefinition {
                    name: "package".to_owned(),
                    fields: vec![
                        FacetFieldDefinition {
                            name: "ecosystem".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "operation".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "name".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "version".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "identity_known".to_owned(),
                            kind: FacetKind::Bool,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "age_known".to_owned(),
                            kind: FacetKind::Bool,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "age_hours".to_owned(),
                            kind: FacetKind::Int,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "age_source".to_owned(),
                            kind: FacetKind::String,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "malware_data_available".to_owned(),
                            kind: FacetKind::Bool,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "malware".to_owned(),
                            kind: FacetKind::Bool,
                            optional: false,
                        },
                        FacetFieldDefinition {
                            name: "malware_reason".to_owned(),
                            kind: FacetKind::String,
                            optional: true,
                        },
                    ],
                },
            ),
        ]);
        Self {
            endpoints,
            families,
            facets,
        }
    }

    pub fn endpoint(&self, kind: &str) -> Option<EndpointDefinition> {
        self.endpoints.get(kind).cloned()
    }

    pub fn family(&self, family: &EndpointFamily) -> Option<FamilyDefinition> {
        self.families.get(family).cloned()
    }

    pub fn facet(&self, name: &str) -> Option<FacetDefinition> {
        self.facets.get(name).cloned()
    }
}

pub(crate) fn parse_https_origin(value: &str) -> Option<(String, u16)> {
    if value.contains(['?', '#']) {
        return None;
    }
    let remainder = value.strip_prefix("https://")?;
    let authority = remainder.split('/').next()?;
    if authority.is_empty() || authority.contains('@') || authority.chars().any(char::is_whitespace)
    {
        return None;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            443
        } else {
            suffix.strip_prefix(':')?.parse().ok()?
        };
        if host.is_empty() || host.chars().any(char::is_whitespace) || port == 0 {
            return None;
        }
        return Some((host.to_ascii_lowercase(), port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, 443),
    };
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

#[cfg(test)]
mod tests {
    use crate::model::{EndpointFamily, Transport};
    use crate::plugin::{
        parse_https_origin, ConditionKind, EndpointSchema, FamilyDefinition, PluginRegistry,
    };

    #[test]
    fn builtins_expose_endpoint_metadata() {
        let registry = PluginRegistry::builtins();

        let https = registry.endpoint("https").expect("https endpoint");
        assert_eq!(https.family, EndpointFamily::Http);
        assert_eq!(https.transport, Transport::HttpsMitm);
        assert_eq!(https.default_port, 443);
        assert!(https.supports_credentials);
        assert!(https.terminates_tls());

        let ip = registry.endpoint("ip").expect("ip endpoint");
        assert_eq!(ip.schema, EndpointSchema::Ip);
        assert!(!ip.supports_credentials);
        assert!(!ip.terminates_tls());

        assert_eq!(
            registry.family(&EndpointFamily::Http),
            Some(FamilyDefinition {
                family: EndpointFamily::Http,
                condition: ConditionKind::Http,
                facets: vec!["http".to_owned()],
            })
        );
    }

    #[test]
    fn parses_https_intelligence_origin() {
        assert_eq!(
            parse_https_origin("https://malware-list.example.test/base"),
            Some(("malware-list.example.test".to_owned(), 443))
        );
        assert_eq!(
            parse_https_origin("https://malware-list.example.test:8443"),
            Some(("malware-list.example.test".to_owned(), 8443))
        );
        assert_eq!(parse_https_origin("http://example.test"), None);
        assert_eq!(parse_https_origin("https://[]"), None);
        assert_eq!(parse_https_origin("https://example.test:0"), None);
        assert_eq!(
            parse_https_origin("https://example.test/feed?token=x"),
            None
        );
        assert_eq!(parse_https_origin("https://example.test/#fragment"), None);
        assert_eq!(parse_https_origin("https://bad host.example.test"), None);
        assert_eq!(
            parse_https_origin("https://[2001:DB8::1]:8443/feed"),
            Some(("2001:db8::1".to_owned(), 8443))
        );
    }
}
