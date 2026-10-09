use serde_json::{json, Value};
use silo_policy::{ForwardCertificateProvider, ForwardProtocol, ForwardTls, NetworkPolicy, Policy};

fn forward(extra: &str) -> String {
    format!("forward \"tailscale\" \"web\" {{\n listen = \":00443\"\n target = \"self\"\n target_port = 8080\n{extra}\n}}")
}

fn canonical_forward() -> Value {
    json!({"version": 1, "forwards": [{"name": "web", "kind": "tailscale", "target": "self", "target_port": 8080, "listen": ":443"}]})
}

#[test]
fn forward_transport_round_trips_and_defaults() {
    for (extra, protocol) in [
        ("", ForwardProtocol::Tcp),
        ("protocol = \"tcp\"", ForwardProtocol::Tcp),
        (
            "protocol = \"https\"\n tls { provider = \"tailscale\" }",
            ForwardProtocol::Https,
        ),
    ] {
        let policy = NetworkPolicy::from_hcl_str(&forward(extra)).unwrap();
        assert_eq!(policy.version(), 1);
        assert_eq!(policy.forwards()[0].protocol, protocol);
        assert_eq!(policy.forwards()[0].listen, ":443");
        assert_eq!(policy.forwards()[0].tunnel, None);
        assert!(policy.secret_requirements().is_empty());
        let hcl = policy.to_hcl_string().unwrap();
        assert!(hcl.contains("protocol ="));
        assert_eq!(
            NetworkPolicy::from_hcl_str(&hcl).unwrap().forwards(),
            policy.forwards()
        );
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(NetworkPolicy::from_json_str(&json).unwrap(), policy);
    }
    let implicit = NetworkPolicy::from_json_str(&canonical_forward().to_string()).unwrap();
    assert_eq!(implicit.forwards()[0].protocol, ForwardProtocol::Tcp);
    let explicit = format!(
        "tailscale \"vm\" {{}}\n{}",
        forward("tunnel = tailscale.vm")
    );
    let policy = NetworkPolicy::from_hcl_str(&explicit).unwrap();
    assert_eq!(policy.forwards()[0].tunnel.as_deref(), Some("vm"));
    assert_eq!(
        NetworkPolicy::from_hcl_str(&policy.to_hcl_string().unwrap())
            .unwrap()
            .forwards(),
        policy.forwards()
    );
}

#[test]
fn forward_builders_select_kind_independently_of_binding() {
    let tls = ForwardTls {
        provider: ForwardCertificateProvider::Tailscale,
    };
    let policy = NetworkPolicy::builder()
        .forward("web", |f| {
            f.tailscale()
                .target("self")
                .target_port(8080)
                .listen(":00443")
                .protocol(ForwardProtocol::Https)
                .tls(tls.clone())
        })
        .build()
        .unwrap();
    assert_eq!(
        policy.forwards(),
        NetworkPolicy::from_hcl_str(&forward(
            "protocol = \"https\"\n tls { provider = \"tailscale\" }"
        ))
        .unwrap()
        .forwards()
    );
    let bound = NetworkPolicy::builder()
        .tailscale("vm", |t| t)
        .forward("web", |f| {
            f.tailscale()
                .tunnel("vm")
                .target("self")
                .target_port(8080)
                .listen(":443")
        })
        .build()
        .unwrap();
    assert_eq!(bound.forwards()[0].tunnel.as_deref(), Some("vm"));
    assert!(NetworkPolicy::builder()
        .forward("web", |f| f
            .tailscale()
            .tunnel("vm")
            .protocol(ForwardProtocol::Https)
            .tls(tls)
            .host()
            .target("name:web")
            .target_port(8080))
        .build()
        .is_err());
}

#[test]
fn forward_hcl_rejects_invalid_authoring_and_references() {
    let base = forward("");
    let mut invalid = vec![
        forward("protocol = \"https\""),
        forward("tls { provider = \"tailscale\" }"),
        forward("protocol = \"udp\""),
        forward("protocol = \"https\"\n tls {}"),
        forward("protocol = \"https\"\n tls \"label\" { provider = \"tailscale\" }"),
        forward("protocol = \"https\"\n tls { provider = \"tailscale\" }\n tls { provider = \"tailscale\" }"),
        forward("protocol = \"https\"\n tls { provider = \"other\" }"),
        forward("protocol = \"https\"\n tls { provider = \"tailscale\"\n key = \"secret\" }"),
        forward("protocol = \"https\"\n tls { provider = \"tailscale\"\n nested {} }"),
        forward("tunnel = tailscale.missing"),
        forward("unexpected = true"),
        base.replace("\"tailscale\"", "\"host\""),
        base.replace("\"self\"", "\"name:web\""),
        base.replace("8080", "0"),
        base.replace("8080", "65536"),
        base.replace("8080", "-1"),
    ];
    for listen in [
        "",
        ":0",
        ":22",
        ":00022",
        ":65536",
        "443",
        "127.0.0.1:443",
        ":[443]",
        ":+443",
        ": 443",
        ":443 ",
    ] {
        invalid.push(base.replace(":00443", listen));
    }
    invalid.push(format!(
        "{base}\n{}",
        base.replace("\"web\"", "\"second\"")
            .replace(":00443", ":443")
    ));
    invalid.push(format!(
        "tailscale \"vm\" {{}}\n{}",
        forward("protocol = \"https\"\n tls { provider = \"tailscale\" }\n tunnel = tailscale.vm")
            .replace("\"self\"", "\"name:web\"")
    ));
    for source in invalid {
        assert!(
            Policy::parse_str("forward.hcl", &source).is_err(),
            "authoring parser accepted {source}"
        );
        assert!(
            NetworkPolicy::from_hcl_str(&source).is_err(),
            "canonical parser accepted {source}"
        );
    }
}

#[test]
fn forward_json_rejects_direct_schema_bypass() {
    for (key, value) in [
        ("protocol", json!("udp")),
        ("protocol", json!("https")),
        ("tls", json!({"provider":"tailscale"})),
        ("tls", json!({})),
        ("tls", json!({"provider":"other"})),
        ("tls", json!({"provider":"tailscale", "key":"secret"})),
        ("kind", json!("host")),
        ("kind", json!("unknown")),
        ("target", json!("name:web")),
        ("target", json!("selfish")),
        ("target_port", json!(0)),
        ("target_port", json!(65536)),
        ("listen", json!(":22")),
        ("listen", json!(":0")),
        ("listen", json!(":65536")),
        ("listen", json!("0.0.0.0:443")),
        ("tunnel", json!("missing")),
    ] {
        let mut doc = canonical_forward();
        doc["forwards"][0][key] = value;
        assert!(
            NetworkPolicy::from_json_str(&doc.to_string()).is_err(),
            "accepted {doc}"
        );
    }
    let mut doc = canonical_forward();
    let mut second = doc["forwards"][0].clone();
    second["name"] = json!("second");
    second["listen"] = json!(":00443");
    second["protocol"] = json!("https");
    second["tls"] = json!({"provider":"tailscale"});
    doc["forwards"].as_array_mut().unwrap().push(second);
    assert!(NetworkPolicy::from_json_str(&doc.to_string()).is_err());
    for (kind, target) in [
        ("host", "name:web"),
        ("host", "self"),
        ("tailscale", "name:web"),
    ] {
        let mut doc = canonical_forward();
        doc["tailscale"] = json!([{"name":"vm"}]);
        doc["forwards"][0]["kind"] = json!(kind);
        doc["forwards"][0]["target"] = json!(target);
        doc["forwards"][0]["tunnel"] = json!("vm");
        doc["forwards"][0]["protocol"] = json!("https");
        doc["forwards"][0]["tls"] = json!({"provider":"tailscale"});
        assert!(
            NetworkPolicy::from_json_str(&doc.to_string()).is_err(),
            "accepted {doc}"
        );
    }
}

#[test]
fn forward_historical_selector_schema_remains_tcp() {
    for target in ["name:web", "id:123", "label:app=web"] {
        let source = format!("forward \"host\" \"web\" {{\n listen = \"127.0.0.1:2222\"\n target = \"{target}\"\n target_port = 22\n}}");
        let policy = NetworkPolicy::from_hcl_str(&source).unwrap();
        assert_eq!(policy.forwards()[0].protocol, ForwardProtocol::Tcp);
        assert_eq!(
            NetworkPolicy::from_hcl_str(&policy.to_hcl_string().unwrap())
                .unwrap()
                .forwards(),
            policy.forwards()
        );
        let source = format!(
            "tailscale \"vm\" {{}}\n{}",
            source
                .replace("\"host\"", "\"tailscale\"")
                .replace(" target =", " tunnel = tailscale.vm\n target =")
        );
        assert!(NetworkPolicy::from_hcl_str(&source).is_ok());
    }
}

#[test]
fn forward_builder_validation_preserves_authoring_boundaries() {
    for (protocol, tls) in [
        (ForwardProtocol::Https, None),
        (
            ForwardProtocol::Tcp,
            Some(ForwardTls {
                provider: ForwardCertificateProvider::Tailscale,
            }),
        ),
    ] {
        assert!(NetworkPolicy::builder()
            .forward("web", |f| {
                let f = f
                    .tailscale()
                    .target("self")
                    .target_port(8080)
                    .listen(":443")
                    .protocol(protocol);
                match tls {
                    Some(tls) => f.tls(tls),
                    None => f,
                }
            })
            .build()
            .is_err());
    }
    for (listen, target_port) in [
        (":22", 8080),
        (":0", 8080),
        (":65536", 8080),
        ("127.0.0.1:443", 8080),
        (":443", 0),
    ] {
        assert!(NetworkPolicy::builder()
            .forward("web", |f| f
                .tailscale()
                .target("self")
                .target_port(target_port)
                .listen(listen))
            .build()
            .is_err());
    }
    assert!(NetworkPolicy::builder()
        .forward("first", |f| f
            .tailscale()
            .target("self")
            .target_port(8080)
            .listen(":443"))
        .forward("second", |f| f
            .tailscale()
            .target("self")
            .target_port(8081)
            .listen(":00443"))
        .build()
        .is_err());
    assert!(NetworkPolicy::builder()
        .forward("web", |f| f
            .tailscale()
            .target("name:web")
            .target_port(8080)
            .listen(":443"))
        .build()
        .is_err());
}
