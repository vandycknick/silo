use crate::canonical::NetworkPolicy;
use crate::plugin::{EndpointSchema, PluginRegistry};
use serde_json::{json, Value};

fn value(value: &Value) -> String {
    value.to_string().replace("${", "$${").replace("%{", "%%{")
}

fn attribute(output: &mut String, key: &str, expression: &str) {
    output.push_str(&format!("  {key} = {expression}\n"));
}

fn reference(kind: &str, name: &str) -> String {
    format!("{kind}[{}]", value(&json!(name)))
}

impl NetworkPolicy {
    /// Deterministic HCL for the executable policy. Canonical metadata is not an HCL declaration.
    pub fn to_hcl_string(&self) -> Result<String, String> {
        let policy = self.clone().normalized();
        let mut output = format!("settings {{\n  default_action = {}\n  audit {{\n    body_buffer_bytes = {}\n    body_storage_bytes = {}\n  }}\n}}\n\n", value(&json!(policy.settings.default_action)), policy.settings.audit.body_buffer_bytes, policy.settings.audit.body_storage_bytes);
        let plugins = PluginRegistry::builtins();
        let endpoint_ref = |name: &str| {
            policy
                .endpoints
                .iter()
                .find(|endpoint| endpoint.name == name)
                .map(|endpoint| reference(&endpoint.kind, name))
                .ok_or_else(|| format!("missing endpoint {name:?}"))
        };
        for endpoint in &policy.endpoints {
            output.push_str(&format!(
                "endpoint {} {} {{\n",
                value(&json!(endpoint.kind)),
                value(&json!(endpoint.name))
            ));
            let schema = plugins
                .endpoint(&endpoint.kind)
                .ok_or_else(|| format!("unknown endpoint kind {:?}", endpoint.kind))?
                .schema;
            match schema {
                EndpointSchema::Ip => {
                    attribute(
                        &mut output,
                        "source_cidrs",
                        &value(&json!(endpoint.source_cidrs)),
                    );
                    attribute(
                        &mut output,
                        "destination_cidrs",
                        &value(&json!(endpoint.destination_cidrs)),
                    );
                    attribute(&mut output, "protocol", &value(&json!(endpoint.protocol)));
                    let ports = endpoint
                        .ports
                        .iter()
                        .map(|port| {
                            if port.start == port.end {
                                json!(port.start)
                            } else {
                                json!(format!("{}-{}", port.start, port.end))
                            }
                        })
                        .collect::<Vec<_>>();
                    attribute(&mut output, "ports", &value(&json!(ports)));
                }
                EndpointSchema::Hosts => {
                    attribute(&mut output, "hosts", &value(&json!(endpoint.hosts)))
                }
                EndpointSchema::Registries => {
                    for (key, item) in &endpoint.config {
                        attribute(&mut output, key, &value(item));
                    }
                }
            }
            output.push_str("}\n\n");
        }
        for credential in &policy.credentials {
            output.push_str(&format!(
                "credential {} {} {{\n",
                value(&json!(credential.kind)),
                value(&json!(credential.name))
            ));
            attribute(
                &mut output,
                "endpoint",
                &endpoint_ref(&credential.endpoint)?,
            );
            for (key, item) in [
                ("username", &credential.username),
                ("header", &credential.header),
                ("prefix", &credential.prefix),
                ("condition", &credential.condition),
            ] {
                if let Some(item) = item {
                    attribute(&mut output, key, &value(&json!(item)));
                }
            }
            if credential.kind == "bearer_token" {
                attribute(
                    &mut output,
                    "idempotency_key",
                    &value(&json!(credential.idempotency_key)),
                );
            }
            output.push_str("}\n\n");
        }
        for tunnel in &policy.tailscale {
            output.push_str(&format!("tailscale {} {{\n", value(&json!(tunnel.name))));
            attribute(&mut output, "tags", &value(&json!(tunnel.tags)));
            attribute(&mut output, "ephemeral", &value(&json!(tunnel.ephemeral)));
            if let Some(hostname) = &tunnel.hostname {
                attribute(&mut output, "hostname", &value(&json!(hostname)));
            }
            if let Some(url) = &tunnel.control_url {
                attribute(&mut output, "control_url", &value(&json!(url)));
            }
            output.push_str("}\n\n");
        }
        for (index, rule) in policy.rules.iter().enumerate() {
            output.push_str("rule");
            if let Some(name) = &rule.name {
                output.push_str(&format!(" {}", value(&json!(name))));
            } else {
                let mut name = format!("generated_rule_{index}");
                while policy
                    .rules
                    .iter()
                    .any(|other| other.name.as_deref() == Some(&name))
                {
                    name.push('_');
                }
                output.push_str(&format!(" {}", value(&json!(name))));
            }
            output.push_str(" {\n");
            let endpoints = rule
                .endpoints
                .iter()
                .map(|name| endpoint_ref(name))
                .collect::<Result<Vec<_>, _>>()?;
            attribute(
                &mut output,
                "endpoints",
                &format!("[{}]", endpoints.join(", ")),
            );
            if let Some(name) = &rule.credential {
                let credential = policy
                    .credentials
                    .iter()
                    .find(|credential| &credential.name == name)
                    .ok_or_else(|| format!("missing credential {name:?}"))?;
                attribute(
                    &mut output,
                    "credential",
                    &reference(&credential.kind, name),
                );
            }
            if let Some(name) = &rule.tunnel {
                attribute(&mut output, "tunnel", &reference("tailscale", name));
            }
            if let Some(condition) = &rule.condition {
                attribute(&mut output, "condition", &value(&json!(condition)));
            }
            attribute(&mut output, "verdict", &value(&json!(rule.verdict)));
            attribute(&mut output, "priority", &rule.priority.to_string());
            attribute(&mut output, "disabled", &rule.disabled.to_string());
            attribute(&mut output, "reason", &value(&json!(rule.reason)));
            output.push_str("}\n\n");
        }
        for forward in &policy.forwards {
            output.push_str(&format!(
                "forward {} {} {{\n",
                value(&json!(forward.kind)),
                value(&json!(forward.name))
            ));
            attribute(&mut output, "target", &value(&json!(forward.target)));
            attribute(&mut output, "target_port", &forward.target_port.to_string());
            if !forward.listen.is_empty() {
                attribute(&mut output, "listen", &value(&json!(forward.listen)));
            }
            if let Some(tunnel) = &forward.tunnel {
                attribute(&mut output, "tunnel", &reference("tailscale", tunnel));
            }
            output.push_str("}\n\n");
        }
        // The authoritative parser also validates generated references and expressions.
        NetworkPolicy::from_hcl_str(&output).map_err(|error| error.to_string())?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::NetworkPolicy;

    #[test]
    fn canonical_names_round_trip_through_literal_index_references() {
        for name in ["1api", "1420", "api", "api-name", "_api"] {
            let policy = NetworkPolicy::builder()
                .endpoint(name, |endpoint| endpoint.https().host("api.example.com"))
                .credential(name, |credential| credential.bearer_token().endpoint(name))
                .tailscale(name, |tunnel| tunnel.ephemeral(true))
                .rule("access", |rule| {
                    rule.endpoint(name).credential(name).tunnel(name).allow()
                })
                .forward("relay", |forward| {
                    forward.tailscale(name).target("name:web").target_port(80)
                })
                .build()
                .unwrap();
            let json = serde_json::to_string(&policy).unwrap();
            let loaded = NetworkPolicy::from_json_str(&json).unwrap();
            let hcl = loaded.to_hcl_string().unwrap();
            assert!(hcl.contains(&format!("https[\"{name}\"]")), "{hcl}");
            assert!(hcl.contains(&format!("bearer_token[\"{name}\"]")), "{hcl}");
            assert!(hcl.contains(&format!("tailscale[\"{name}\"]")), "{hcl}");
            let round_trip = NetworkPolicy::from_hcl_str(&hcl).unwrap();
            assert_eq!(round_trip.endpoints(), loaded.endpoints());
            assert_eq!(round_trip.credentials(), loaded.credentials());
            assert_eq!(round_trip.tailscale(), loaded.tailscale());
            assert_eq!(round_trip.rules(), loaded.rules());
            assert_eq!(round_trip.forwards(), loaded.forwards());
            assert_eq!(round_trip.to_hcl_string().unwrap(), hcl);
        }
    }

    #[test]
    fn literal_references_reject_dynamic_indices_and_extra_operators() {
        for reference in [
            "https[other]",
            "https[1420]",
            "https[\"1api\"].extra",
            "https[*]",
            "https[\"bad.name\"]",
            "https[\"${other}\"]",
        ] {
            let source = format!("endpoint \"https\" \"1api\" {{ hosts = [\"api.example.com\"] }}\ncredential \"bearer_token\" \"token\" {{ endpoint = {reference} }}");
            assert!(NetworkPolicy::from_hcl_str(&source).is_err(), "{reference}");
        }
        let source = "endpoint \"https\" \"1420\" { hosts = [\"api.example.com\"] }\ncredential \"bearer_token\" \"token\" { endpoint = https.1420 }";
        assert!(
            NetworkPolicy::from_hcl_str(source).is_ok(),
            "legacy numeric traversal must remain accepted"
        );
    }

    #[test]
    fn hcl_strings_preserve_quotes_unicode_controls_and_template_literals() {
        for reason in [
            "quotes: \"quoted\" and \\backslash",
            "controls: \n\t\r",
            "unicode: café 💡",
            "literal: ${not_a_variable} %{if not_a_directive}",
        ] {
            let policy = NetworkPolicy::builder()
                .endpoint("1api", |endpoint| endpoint.https().host("api.example.com"))
                .rule("1rule", |rule| rule.endpoint("1api").reason(reason).allow())
                .build()
                .unwrap();
            let hcl = policy.to_hcl_string().unwrap();
            let loaded = NetworkPolicy::from_hcl_str(&hcl).unwrap();
            assert_eq!(loaded.rules()[0].reason, reason, "{hcl}");
            assert_eq!(loaded.to_hcl_string().unwrap(), hcl);
        }
    }

    #[test]
    fn generated_machine_policy_preserves_explicit_hostname_and_fills_absent_or_empty() {
        for hostname in [None, Some("")] {
            let json =
                serde_json::json!({"version":1,"tailscale":[{"name":"vm","hostname":hostname}]});
            let policy = NetworkPolicy::from_json_str(&json.to_string()).unwrap();
            let generated = policy.clone().with_default_tailscale_hostname("exact");
            assert_eq!(generated.tailscale()[0].hostname.as_deref(), Some("exact"));
            assert_eq!(policy.tailscale()[0].hostname.as_deref(), hostname);
        }
        let policy =
            NetworkPolicy::from_hcl_str("tailscale \"vm\" { hostname = \"explicit\" }").unwrap();
        assert_eq!(
            policy.with_default_tailscale_hostname("exact").tailscale()[0]
                .hostname
                .as_deref(),
            Some("explicit")
        );
    }

    #[test]
    fn formatted_ip_registry_and_forward_contracts_are_stable() {
        let source = r#"
endpoint "ip" "local" {
 destination = ["127.0.0.0/8"]
 protocol = "tcp"
 ports = [22, "80-90"]
}
endpoint "registries" "registry" {
 registries = ["npm"]
 malware_feed = "https://intelligence.example.com"
}
rule "local" {
 endpoint = ip.local
 verdict = "allow"
}
forward "host" "ssh" {
 target = "name:web"
 target_port = 22
 listen = "127.0.0.1:2222"
}
"#;
        let policy = NetworkPolicy::from_hcl_str(source).unwrap();
        let rendered = policy.to_hcl_string().unwrap();
        let reparsed = NetworkPolicy::from_hcl_str(&rendered).unwrap();
        assert_eq!(policy.endpoints(), reparsed.endpoints());
        assert_eq!(policy.forwards(), reparsed.forwards());
        assert_eq!(reparsed.to_hcl_string().unwrap(), rendered);
    }

    #[test]
    fn tailscale_hcl_json_builder_and_formatter_contract() {
        let policy = NetworkPolicy::from_hcl_str("tailscale \"vm\" {\n ephemeral = true\n hostname = \"dev\"\n tags = [\"tag:test\"]\n }").unwrap();
        assert!(policy.tailscale()[0].ephemeral);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(NetworkPolicy::from_json_str(&json).unwrap().tailscale()[0].ephemeral);
        let formatted = policy.to_hcl_string().unwrap();
        let reparsed = NetworkPolicy::from_hcl_str(&formatted).unwrap();
        assert_eq!(reparsed.tailscale(), policy.tailscale());
        assert_eq!(reparsed.to_hcl_string().unwrap(), formatted);
        assert!(
            !NetworkPolicy::from_hcl_str("tailscale \"vm\" {}")
                .unwrap()
                .tailscale()[0]
                .ephemeral
        );
        for error in [
            NetworkPolicy::from_hcl_str("tailscale \"first\" {}\ntailscale \"second\" {}")
                .unwrap_err()
                .to_string(),
            NetworkPolicy::from_json_str(
                r#"{"version":1,"tailscale":[{"name":"first"},{"name":"second"}]}"#,
            )
            .unwrap_err()
            .to_string(),
            NetworkPolicy::builder()
                .tailscale("first", |t| t)
                .tailscale("second", |t| t)
                .build()
                .unwrap_err()
                .to_string(),
        ] {
            assert!(
                error.contains("first") && error.contains("second"),
                "{error}"
            );
        }
    }

    #[test]
    fn formatted_policy_preserves_references_and_conditions() {
        let source = r#"
settings { default_action = "deny" }
endpoint "https" "api" { hosts = ["api.example.com"] }
credential "bearer_token" "token" { endpoint = https.api }
rule "access" {
 endpoints = [https.api]
 credential = bearer_token.token
 verdict = "allow"
 condition = "http.method == 'GET'"
}
"#;
        let policy = NetworkPolicy::from_hcl_str(source).unwrap();
        let rendered = policy.to_hcl_string().unwrap();
        let reparsed = NetworkPolicy::from_hcl_str(&rendered).unwrap();
        assert_eq!(policy.endpoints(), reparsed.endpoints());
        assert_eq!(policy.credentials(), reparsed.credentials());
        assert_eq!(policy.rules(), reparsed.rules());
        assert_eq!(reparsed.to_hcl_string().unwrap(), rendered);
    }
}
