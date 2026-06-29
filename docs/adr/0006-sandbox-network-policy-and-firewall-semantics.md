# 6. Sandbox Network Policy and Firewall Semantics

Date: 2026-06-18

## Status

Proposed

## Summary

Virtual machines give Bentobox an isolation boundary, but that boundary does not make network access safe by itself. Code inside a sandbox can do a lot of things: install packages, run build hooks, execute generated programs, and talk to services. We need these workloads to use the network without trusting them to hold policy state, protect long-lived credentials, or accurately report what they are doing.

This document defines the Bentobox sandbox network policy. It is a typed HCL specification for describing firewall endpoints, rule evaluation, credential injection, outbound Tailscale routing, raw TCP forwards, and traffic audit records. The first implementation will be the `netd` driver. The policy language and semantics are intentionally driver-independent. This means future network drivers should be able to implement the same policy contract rather than inventing their own firewall language.

The policy is endpoint-first. For example, `endpoint "ip"` describes L3/L4 traffic, `endpoint "http"` describes cleartext HTTP, and `endpoint "https"` describes HTTPS MITM. Rules are evaluated by endpoint family rather than by transport. This means one HTTP-family rule can cover both cleartext and TLS-backed HTTP while still preserving the runtime behavior of each transport.

Credentials are tied to endpoints and used to modify requests. They are not secrets placed in the virtual machine, and they are not ambient default behavior. A credential can only be selected after the endpoint has been classified at L7, and the secret material is only resolved after an explicit `allow`. If the policy falls through to `settings.default_action = "allow"`, it is still an outbound fallback, but it will never inject credentials and never select a Tailscale tunnel.

Audit is a stream of information we can use to see what happened. It is not a policy verdict. Implementations write structured, redacted, versioned JSONL records to `audit.jsonl` so operators can see what was allowed, denied, forwarded, tunneled, or failed without turning audit into a secret sink.

## Context

The problem is not just packet filtering. Bentobox sandboxes are useful because they behave like normal development environments. They fetch dependencies, clone repositories, call APIs, open sockets, and run tools the user did not personally inspect. That is the point. It is also the risk.

Some of those workloads need access to sensitive services. They may need to talk to GitHub, cloud APIs, package registries, internal services, or a tailnet. But putting OAuth refresh tokens, cloud signing keys, API keys, or broad network policy state inside the VM makes the guest part of the trust boundary. We should avoid that.

The safer shape is that the VM makes ordinary network requests and the host-side network runtime decides what happens. It decides whether the traffic is allowed, whether it belongs to a configured endpoint, whether a credential may be injected, whether a Tailscale tunnel should be used, and what audit record should be written.

We also need one policy language, not a different firewall model for every driver. `netd` is the first implementation because it is the current driver path. This ADR defines the HCL schema and firewall semantics separately from that implementation. A future driver should not need different meanings for endpoints, priorities, credential predicates, default actions, Tailscale routing, or audit fields.

The policy therefore needs to cover:

- L3/L4 IP traffic,
- transparent cleartext HTTP filtering,
- HTTPS MITM filtering,
- endpoint-bound credential injection,
- outbound Tailscale routing,
- inbound host and Tailscale forwards,
- structured audit records,
- future protocol-aware endpoints without rewriting the policy model.

The policy must be easy to review. If traffic is allowed or denied, the reason should come from explicit endpoint, rule, priority, credential, tunnel, and default-action semantics. Driver-specific behavior can exist, but it should be isolated, documented, and tested against this policy contract.

## Determinations

The rest of this document follows from these decisions.

1. The sandbox network policy is one HCL file. There are no includes, imports, profiles, or multi-file policy sets.
2. `netd` is the first implementation of this policy contract, not the definition of the contract itself.
3. Endpoint kinds, credential kinds, facets, transports, and capabilities are registered statically by the implementing policy runtime. This is not a dynamic plugin system.
4. Rules have only terminal verdicts: `allow` and `deny`. Audit is not a verdict.
5. `settings.default_action` defaults to `allow`. It applies only when no explicit rule matches at the relevant stage.
6. L7 transports may classify configured HTTP/HTTPS traffic under default deny, but classification punch-through never permits upstream contact, credential injection, or data forwarding by itself.
7. HTTPS no-SNI classification is allowed only for explicit raw-IP HTTPS endpoint bindings. No-SNI HTTPS without such a binding fails closed before upstream contact.
8. HTTP-family proxy and MITM behavior follows a transparent proxy model: rules evaluate on the request, WebSocket frames are opaque after upgrade, `CONNECT` is treated as an HTTP method, and synthetic denials/errors are returned without upstream contact where possible.
9. Credentials are endpoint-bound request modifiers. `rule.credential` is a predicate over the selected credential identity, not an injection trigger.
10. Secret lookup, refresh, signing, and injection occur only after an explicit allow. Runtime credential failures return synthetic `502` responses and do not fall back to unauthenticated forwarding.
11. Tailscale outbound routing is selected only by an explicit allow rule with `tunnel = tailscale.<name>`. Default allow never tunnels.
12. Inbound forwards are configured exposures and are outside the outbound endpoint/rule/default-action policy model. Initial forwards are raw TCP byte proxies only.
13. Audit records are JSONL with `version = 1`, UUIDv7 IDs, RFC3339Nano UTC timestamps, an optional raw policy-file `policy_hash`, and no `profile_name` field.
14. Policy-load warnings are non-fatal and visible in service logs and runtime status, not in `audit.jsonl`.

## Goals

The policy needs to:

- make the policy file readable at a glance,
- keep matching, ordering, defaults, credential selection, and tunnels deterministic,
- support explicit L3/L4 policy with `endpoint "ip"`,
- support transparent HTTP policy without guest proxy environment variables,
- support HTTPS MITM policy and credential injection on configured HTTPS endpoints,
- support L7 policy under default deny without upstream contact before policy evaluation,
- keep credentials out of the VM, policy defaults, service logs, and audit records,
- reject invalid or ambiguous policy at load time whenever possible,
- fail closed when runtime policy evaluation, credential handling, or selected tunnel routing cannot be performed safely,
- provide enough audit data to explain what happened without making audit records a secret sink.

## Non-Goals

We are not adding:

- dynamic endpoint, credential, facet, transport, or tunnel plugins,
- policy `profile` blocks,
- guest credential environment variables,
- credential placeholders exported into guest processes,
- a concrete secret store integration contract,
- request or response body matching in CEL,
- WebSocket frame policy,
- QUIC or HTTP/3 inspection,
- HITL approval verdicts,
- policy includes/imports,
- final detailed schemas for future `kubernetes`, `postgres`, or `ssh` endpoints.

`profile_name` stays runtime/UI metadata only. It is not a policy selector and it is not part of the audit schema.

## Vocabulary

These terms show up throughout the rest of the document.

An endpoint kind is the first label on an `endpoint` block. It identifies the user-facing endpoint type and schema. Examples are `ip`, `http`, `https`, and future `postgres`.

An endpoint instance is one named endpoint block. For example, `endpoint "https" "github"` creates the endpoint reference `https.github`.

A family is the policy compatibility domain for endpoint instances. Rules can reference multiple endpoints only when all referenced endpoints share one family. `http` and `https` endpoint kinds both use the `http` family even though they use different transports.

A facet is a reusable set of request variables, validation rules, and audit fields. The initial `http` facet exposes `http.method`, `http.host`, `http.path`, `http.query`, and `http.headers`.

A transport is the gateway data path used for a matched endpoint. `packet-filter` handles L3/L4 flow decisions, `http-proxy` handles transparent cleartext HTTP interception, and `https-mitm` handles HTTPS MITM.

A capability is a named behavior supported by an endpoint kind or credential kind. Examples are `rules`, `credentials`, `credential_conditions`, `request_audit`, and `classify_without_upstream`.

A credential kind is the first label on a `credential` block. It defines policy attributes, compatible endpoint capabilities, secret slots, and injection behavior.

A credential identity is the fully qualified reference to a credential block, such as `bearer_token.github_api`. This identity is stable and is the policy-visible handle for out-of-band secret material.

A rule is a named policy statement that references one endpoint or a list of endpoints, optionally evaluates a condition, and returns `allow` or `deny`.

An explicit allow is an `allow` verdict returned by a matching rule. It is different from falling through to `settings.default_action = "allow"`.

An owned L7 request is an HTTP-family request classified to a configured `http` or `https` endpoint. Unknown L7 traffic is traffic on an L7-capable path that does not match any configured endpoint.

## Policy File Contract

We intentionally keep policy source simple: one HCL document, one hash, no include tree. Implementations load exactly one policy file. Include/import syntax, multiple policy files, and future multi-file policy sets are unsupported and are load errors.

Top-level blocks are:

```hcl
settings { ... }

endpoint "ip" "name" { ... }
endpoint "http" "name" { ... }
endpoint "https" "name" { ... }

credential "kind" "name" { ... }

tailscale "name" { ... }

forward "host" "name" { ... }
forward "tailscale" "name" { ... }

rule "name" { ... }
```

Unknown top-level blocks are load errors. Unknown attributes inside known blocks are load errors, including unknown attributes inside nested blocks such as `settings.audit` or `forward.target`.

Duplicate endpoint names within the same endpoint kind are load errors. Duplicate credential names within the same credential kind are load errors. Duplicate rule names are load errors.

Endpoint and credential names must be valid HCL traversal identifiers because policy references use typed traversal syntax such as `https.github` and `bearer_token.github_api`. Rule names are labels only and are never referenced by policy expressions, so they may use human-readable names such as `github-read-only`.

The policy loader compiles the full document before enforcement starts. If a policy cannot be parsed, validated, or compiled, the implementation does not enforce it. A partially loaded policy must never be enforced.

## Settings

`settings` is intentionally small. It controls the global fallback decision and the audit body sampling limits.

```hcl
settings {
  default_action = "deny"

  audit {
    body_buffer  = "1MiB"
    body_storage = "4KiB"
  }
}
```

`settings` is optional. If omitted, `default_action` defaults to `allow`, `audit.body_buffer` defaults to `"1MiB"`, and `audit.body_storage` defaults to `"4KiB"`.

Only one `settings` block is valid. Multiple settings blocks are a load error.

### `default_action`

`default_action` accepts only `allow` or `deny`. It applies only when no explicit rule matches at the relevant evaluation stage.

`default_action = "allow"` allows outbound IP flows that do not match any `endpoint "ip"` or owned L7 endpoint. This is a real fallback for unknown outbound traffic. Audit records should report `verdict = "allow"`, `rule = null`, `endpoint = null`, and a reason such as `default_allow`. Default allow never injects credentials and never uses a Tailscale tunnel.

`default_action = "deny"` denies unknown outbound traffic after any valid L7 classification opportunity is exhausted. This includes unknown IP flows, unknown HTTP hosts, and unknown HTTPS hosts. L7 classification punch-through under default deny is permission to classify configured L7 candidates, not permission to forward.

### `settings.audit`

The audit block here is only for body sampling knobs. It is not where we configure sinks, enablement, verdicts, durability guarantees, or traffic policy.

| Attribute      | Type        | Default  | Semantics                                                                                                 |
| -------------- | ----------- | -------- | --------------------------------------------------------------------------------------------------------- |
| `body_buffer`  | size string | `"1MiB"` | Maximum request body bytes an implementation may buffer for HTTP-family operational and audit processing. |
| `body_storage` | size string | `"4KiB"` | Maximum body preview bytes persisted in audit JSONL samples.                                              |

Size strings must be positive. Implementations should accept human-readable values such as `"64KiB"`, `"1MiB"`, and bare byte counts. Invalid, zero, and negative sizes are load errors.

If `body_buffer < body_storage`, the policy remains valid but the implementation should emit a warning to service logs and runtime status. Warnings never change enforcement behavior.

Unknown nested `settings.audit` attributes are load errors.

## Endpoint Blocks

Endpoints are named pieces of network surface that policy can reason about. Each endpoint kind owns its schema, validation, normalization, family, facets, transport, and capabilities.

### `endpoint "ip"`

The `ip` endpoint kind is the L3/L4 part of the policy. It matches flow metadata, not hostnames or application requests.

```hcl
endpoint "ip" "private_https" {
  source      = ["192.168.127.0/24"]
  destination = ["10.0.0.0/8"]
  protocol    = "tcp"
  ports       = [443, "8443-9443"]
}
```

Schema:

| Attribute     | Type                       | Required | Semantics                                                      |
| ------------- | -------------------------- | -------- | -------------------------------------------------------------- |
| `source`      | list of CIDR strings       | No       | Source IP prefixes.                                            |
| `destination` | list of CIDR strings       | No       | Destination IP prefixes.                                       |
| `protocol`    | string                     | No       | `any`, `tcp`, or `udp`. Defaults to `any`.                     |
| `ports`       | list of integers or ranges | No       | Destination ports, valid only when protocol is `tcp` or `udp`. |

At least one of `source` or `destination` is required. If both are present, both must match. `protocol = "any"` cannot be combined with `ports`.

Ports may be exact integers from `1` through `65535` or inclusive string ranges in the form `"start-end"`, where both bounds are valid ports and `start <= end`. The loader should normalize exact ports and ranges into a single internal interval representation.

IPv4 and IPv6 CIDRs are valid policy input even if a specific runtime backend initially supports only IPv4 enforcement. Runtime IPv6 limitations must be explicit runtime capability limitations, not parser behavior.

`ip` endpoints do not support `rule.condition`. The endpoint selector is the complete L3/L4 match surface for the initial policy language.

`ip` endpoints are strictly CIDR/IP based. They do not accept DNS names, Tailscale MagicDNS names, or hostnames. Hostname-aware policy belongs in `http` and `https` endpoints, where Host/SNI authority is visible. This avoids DNS resolution timing, cache invalidation, rebinding, and audit ambiguity in L3/L4 policy.

### `endpoint "http"`

The `http` endpoint kind matches cleartext HTTP requests intercepted transparently by the implementing runtime. The guest does not need to know the proxy exists.

```hcl
endpoint "http" "metadata_service" {
  hosts = ["metadata.internal", "metadata.internal:8080"]
}
```

Schema:

| Attribute | Type                  | Required | Semantics                                                               |
| --------- | --------------------- | -------- | ----------------------------------------------------------------------- |
| `hosts`   | list of host patterns | Yes      | Exact hosts, exact authorities, IP literals, or wildcard host patterns. |

The default port for `http` endpoints is `80`. A host entry may include a non-default port. Host entries must not include a URL scheme, path, query string, or fragment.

`http` uses the `http` family and the `http` facet. Its transport is `http-proxy`. This proxy is transparent interception. The guest does not need `HTTP_PROXY`, `HTTPS_PROXY`, or any other proxy environment configuration.

Plain HTTP endpoints do not support credentials. They may be allowed, denied, proxied, and audited, but `credential` blocks cannot bind to them and rules targeting only `http` endpoints cannot use `rule.credential`.

For traffic classified as owned by a configured HTTP endpoint, the request must have a valid Host/authority before rule evaluation. Missing or invalid authority fails closed with synthetic `400 Bad Request` and reason `missing_host`. If the authority is present but does not match the endpoint selected by transport, port, and dispatch path, the request fails with synthetic `421 Misdirected Request` and reason `host_mismatch`. No upstream connection is opened for either response.

Unknown HTTP hosts under `default_action = "allow"` pass through raw without credential selection or injection. Unknown HTTP hosts under `default_action = "deny"` are denied after classification opportunity is exhausted.

### `endpoint "https"`

The `https` endpoint kind gives the policy the same HTTP request surface as `http`, but through the `https-mitm` transport. It also supports endpoint-bound credentials.

```hcl
endpoint "https" "github" {
  hosts = ["api.github.com", "*.githubusercontent.com"]
}
```

Schema:

| Attribute | Type                  | Required | Semantics                                                               |
| --------- | --------------------- | -------- | ----------------------------------------------------------------------- |
| `hosts`   | list of host patterns | Yes      | Exact hosts, exact authorities, IP literals, or wildcard host patterns. |

The default port for `https` endpoints is `443`. A host entry may include a non-default port. Configured non-default HTTPS ports must actually route into the `https-mitm` transport. It is not enough for the parser to accept `host:8443` while the gateway only MITMs port `443`.

`https` uses the `http` family and the `http` facet. Its transport is `https-mitm`. It supports credentials and credential conditions.

HTTPS classification uses TLS SNI when present. If SNI matches a configured HTTPS endpoint binding, the implementation may MITM the connection, decrypt the HTTP request, and require the decrypted Host/authority to match the classified endpoint. Missing authority returns synthetic `400 Bad Request` with reason `missing_host`. SNI/Host mismatch returns synthetic `421 Misdirected Request` with reason `host_mismatch`. No upstream connection is opened in either case.

HTTPS endpoint `hosts` may include exact IP literal bindings, including `IP:port` authorities. If TLS has no SNI, the implementation may classify only by destination IP/port against these explicit raw-IP HTTPS bindings. If no explicit raw-IP HTTPS binding matches, no-SNI HTTPS fails closed before upstream contact, regardless of `default_action`, with a reason such as `missing_sni` or `unclassified_https`.

For raw-IP HTTPS classification, the decrypted HTTP Host/authority must normalize to the same `IP[:port]` binding that selected the endpoint. Missing authority returns `400 missing_host`; differing authority returns `421 host_mismatch`. This prevents a raw-IP endpoint from becoming a tunnel for arbitrary encrypted HTTP hosts.

Unknown HTTPS hosts with SNI under `default_action = "allow"` pass through raw without credential selection or injection. Unknown HTTPS hosts under `default_action = "deny"` are denied after classification opportunity is exhausted.

## HTTP-Family Host Matching

HTTP-family matching is deliberately boring: normalize the policy binding, normalize the request authority, then compare with deterministic precedence.

Normalization rules:

- Hostnames are lowercased.
- A host without a port uses the endpoint kind default, `80` for `http` and `443` for `https`.
- A `host:port` binding keeps the explicit port.
- Request hosts with default ports are equivalent to hosts without explicit ports.
- IPv4 literals and IPv4 `IP:port` authorities are valid exact bindings.
- IPv6 literals must use bracketed authority form, such as `[2001:db8::1]` or `[2001:db8::1]:8443`.
- Schemes, paths, queries, and fragments are invalid in endpoint `hosts`.
- Policy and request hostnames compare after lowercase ASCII/punycode form. Unicode hostname and IDNA conversion are not required in v1.

Host patterns can be exact hosts or wildcard suffixes. `*.example.com` matches `api.example.com` and `deep.api.example.com`, but does not match `example.com`.

Wildcard IP patterns are invalid for IPv4 and IPv6. For example, `*.0.0.1`, `*.168.1.1`, and `*.[2001:db8::1]` are load errors.

When multiple endpoint host patterns could match one request, precedence is deterministic:

1. Exact host matches win over wildcard matches.
2. Among wildcard matches, the longest suffix wins.
3. If precedence still ties between two endpoint bindings on the same transport and port, the policy is invalid and load fails.

Duplicate normalized exact host bindings across endpoints sharing the same transport and port are load errors. The check crosses endpoint kinds. Overlapping wildcards are allowed because longest-suffix precedence makes them deterministic.

## Rule Blocks

Rules are where endpoint matches turn into `allow` or `deny` decisions.

```hcl
rule "github-read-only" {
  endpoint  = https.github
  condition = "http.method in ['GET', 'HEAD']"
  verdict   = "allow"
  priority  = 100
  reason    = "read-only GitHub API access"
}
```

Schema:

| Attribute    | Type                        | Required                                 | Semantics                                                                      |
| ------------ | --------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------ |
| `endpoint`   | endpoint reference          | Exactly one of `endpoint` or `endpoints` | Single endpoint target.                                                        |
| `endpoints`  | list of endpoint references | Exactly one of `endpoint` or `endpoints` | Multiple endpoint targets in the same family.                                  |
| `condition`  | string                      | No                                       | CEL expression compiled against the endpoint family facets.                    |
| `credential` | credential reference        | No                                       | Predicate requiring the selected credential to match.                          |
| `tunnel`     | Tailscale reference         | No                                       | Route an explicitly allowed outbound request or flow through a Tailscale node. |
| `verdict`    | string                      | Yes                                      | `allow` or `deny`.                                                             |
| `priority`   | integer                     | No                                       | Higher values evaluate first. Defaults to `0`.                                 |
| `disabled`   | bool                        | No                                       | Disabled rules are validated but removed from evaluation. Defaults to `false`. |
| `reason`     | string                      | No                                       | Human-readable reason for logs and audit.                                      |

Exactly one of `endpoint` or `endpoints` is required. A rule with neither is a load error. A rule with both is a load error.

Every referenced endpoint must exist. In a multi-endpoint rule, all endpoints must share the same family. Transports do not need to match. This allows one HTTP-family rule to cover both `http` and `https` endpoints, but prevents a rule from mixing `ip` and `https` or future `sql` and `ssh` endpoints.

Rules evaluate separately per policy stage. Within a stage, enabled rules are ordered by descending `priority`; declaration order is the stable tie-breaker. The first matching terminal rule returns its verdict. Disabled rules are validated and then excluded from evaluation.

`verdict` accepts only `allow` or `deny`. Audit is observability, not a verdict.

`condition` is supported only when the endpoint family exposes a condition environment. The initial `ip` family does not. The initial `http` family does.

`reason` has no policy effect. It exists for diagnostics, logs, and audit records.

`tunnel` is allowed only on `allow` rules and only when the selected transport can route through the referenced Tailscale node. It is an outbound routing effect for the winning explicit allow rule. It does not affect rule matching, credential selection, or default allow fallback. A request or flow allowed only by `settings.default_action = "allow"` is forwarded by the normal network path and does not use a Tailscale tunnel.

## HTTP Facet and CEL Model

The initial `http` facet keeps the policy surface narrow. It exposes only these variables to CEL:

| Variable       | Type                        | Semantics                                                      |
| -------------- | --------------------------- | -------------------------------------------------------------- |
| `http.method`  | string                      | Request method, matched case-insensitively.                    |
| `http.host`    | string                      | Normalized policy host, lowercase and default-port-normalized. |
| `http.path`    | string                      | Parsed path component only, excluding query string.            |
| `http.query`   | `map<string, list<string>>` | Parsed query parameters.                                       |
| `http.headers` | `map<string, list<string>>` | Request headers with case-insensitive key lookup.              |

`http.method` comparisons must be case-insensitive. Runtimes can satisfy this by normalizing method values in the CEL adapter before equality and membership checks.

`http.host` is the normalized policy host used for endpoint matching. It is not necessarily byte-for-byte identical to the raw Host header.

`http.path` uses the parsed path from Go's HTTP parser, excludes the query string, and does not expose raw escaped path bytes. Malformed request targets are malformed HTTP and fail closed for owned endpoints. There is no `http.raw_path` or `http.escaped_path` in v1.

`http.query` is a parsed map of URL query parameters, excluding the leading `?`. Keys and values are percent-decoded using normal URL query parsing. Repeated keys preserve all values in request order. Query key matching is case-sensitive. Missing query parameters evaluate as an empty list. The raw query string is not exposed to CEL in v1.

`http.headers` is intentionally list-based. It is a `map<string, list<string>>`; there are no scalar first-value aliases, `http.header.*` shortcuts, or raw-header aliases in v1. Header lookup is case-insensitive regardless of key spelling. Duplicate differently-cased wire headers normalize into one list in request order. Missing headers evaluate as an empty list. Audit records may use Go canonical header names.

Bodies stay out of policy CEL. There is no `http.body` or `http.body_json` variable. Body capture described later is audit-only and must not affect rule matching.

CEL parse errors, type errors, and references to unavailable variables are policy load errors.

Runtime condition errors fail closed. When evaluation reaches a rule whose endpoint and credential predicates match, but whose `condition` errors at runtime, rule evaluation stops immediately and the request or flow is denied with reason `condition_error`. The runtime must not skip the broken rule and continue to lower-priority rules. Higher-priority rules that already matched still win because evaluation never reaches the broken rule.

## Evaluation Model

Evaluation is layered for one reason: an L7 allow cannot undo an explicit L3/L4 deny.

Policy load proceeds in this order:

1. If a policy file is provided, read the single raw HCL policy file and compute `policy_hash`.
2. Parse HCL.
3. Validate top-level block types, unknown attributes, and duplicate names.
4. Decode `settings` and validate audit size limits.
5. Decode endpoint blocks through the endpoint registry.
6. Normalize endpoint match keys and validate host binding conflicts.
7. Decode credential blocks through the credential registry.
8. Validate credential endpoint compatibility and compile credential conditions.
9. Decode Tailscale blocks and validate policy-level Tailscale fields.
10. Decode forward blocks and validate listener syntax, listener kind, target selector syntax, and duplicate listener addresses.
11. Decode rules, validate endpoint references, family compatibility, tunnel references, credential predicates, and compile rule conditions.
12. Build per-family ordered rule tables.
13. Build transport dispatch tables, tunnel routing tables, and inbound forward listener tables.

Runtime evaluation for an outbound intercepted flow or request proceeds in this order:

1. Build the L3/L4 flow context.
2. Evaluate explicit `ip` rules matching the flow.
3. If an explicit `ip` deny matches, deny immediately and do not enter any L7 transport.
4. If an explicit `ip` allow matches, the lower layer permits the flow to continue to L7 classification or raw forwarding.
5. If no explicit `ip` rule matches, decide whether a configured L7 transport may classify the traffic before upstream contact.
6. If no L7 classification is possible, apply `settings.default_action` at the flow stage.
7. If L7 classification is possible, classify the request without opening an upstream connection.
8. Match the classified request to an L7 endpoint by transport, port, and host precedence.
9. If no endpoint owns the classified request, apply `settings.default_action` for unknown L7 traffic.
10. If an endpoint owns the request and supports credentials, select credential metadata for that endpoint and request.
11. Evaluate ordered rules for the endpoint family.
12. If a rule matches, apply its explicit verdict.
13. If no rule matches, apply `settings.default_action` as the L7 fallback.
14. If the final decision is an explicit allow and a credential was selected, resolve secret material and inject credentials.
15. If the winning explicit allow has `tunnel = tailscale.<name>`, route the upstream connection through that Tailscale node.
16. If the final decision is default allow, forward without credential injection and without Tailscale tunnel routing.
17. Emit audit/log events with redacted credential and routing metadata.

The phrase explicit `ip` rule means a matching enabled rule that references an `ip` endpoint. `settings.default_action = "deny"` at the flow layer does not automatically prevent L7 classification for configured L7 endpoints. Instead, L7 classification punch-through applies as defined below.

## L7 Classification Punch-Through

Default deny creates a chicken-and-egg problem for L7 policy: the gateway must read enough bytes to classify a request before it can know whether an L7 rule allows it. Treating that classification as a normal network allow would either break all default-deny L7 policy or accidentally contact upstream services before policy evaluation.

Classification punch-through is permission for the runtime to accept and inspect enough guest traffic to classify a configured L7 endpoint. It is not permission to connect to the upstream service, forward application data, inject credentials, select a Tailscale tunnel, or return a policy allow decision.

Punch-through is allowed only when the selected transport can classify before upstream contact. The initial transports behave as follows:

| Transport       | Punch-through under default deny | Reason                                                                                                             |
| --------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `http-proxy`    | Yes                              | It can parse the HTTP request line and headers before upstream contact.                                            |
| `https-mitm`    | Yes                              | It can classify SNI or explicit raw-IP HTTPS bindings and decrypted HTTP request metadata before upstream contact. |
| `packet-filter` | No                               | Raw forwarding has no higher-layer classification step.                                                            |

Future transports must declare this property explicitly. A future `postgres-proxy` may use punch-through only if it can classify startup/query metadata before upstream contact or before any upstream-visible side effect. A future `ssh-proxy` may use it only if it can classify login/channel/command intent before upstream authentication or command execution effects.

Configured but invalid L7 traffic fails closed in both default modes before upstream contact. Examples include malformed HTTP for an owned endpoint, missing required host information, HTTPS SNI/Host mismatch, no-SNI HTTPS without an explicit raw-IP endpoint binding, unsupported TLS behavior for a configured MITM endpoint, runtime condition errors, credential condition errors, and credential ambiguity.

Unknown L7 hosts use `settings.default_action`. Under `default_action = "allow"`, unknown hosts pass through without credential selection, credential injection, or Tailscale tunnel routing. Under `default_action = "deny"`, unknown hosts are denied. Unknown hosts must not borrow wildcard/default credentials.

## HTTP-Family Proxy Behavior

Once transport classification says an HTTP-family request is owned by an endpoint, the proxy behavior below applies. It covers `http-proxy`, `https-mitm`, and future HTTP-like transports unless a future endpoint kind explicitly narrows it.

### Synthetic Responses

When policy rejects a request before upstream work begins, the runtime returns a gateway-generated response and does not contact upstream.

| Condition                                                      | Status                    | Reason                                   |
| -------------------------------------------------------------- | ------------------------- | ---------------------------------------- |
| Missing/invalid HTTP Host or authority for owned endpoint      | `400 Bad Request`         | `missing_host`                           |
| SNI/Host, raw-IP/Host, or dispatch/Host mismatch               | `421 Misdirected Request` | `host_mismatch`                          |
| Explicit deny                                                  | `403 Forbidden`           | rule/default reason                      |
| Default deny                                                   | `403 Forbidden`           | `default_deny`                           |
| Runtime rule condition error                                   | `403 Forbidden`           | `condition_error`                        |
| Runtime credential condition error                             | `403 Forbidden`           | `credential_condition_error`             |
| Ambiguous credentials                                          | `403 Forbidden`           | `ambiguous_credentials`                  |
| Credential secret lookup/refresh/signing/injection failure     | `502 Bad Gateway`         | specific credential error reason         |
| Selected Tailscale tunnel unavailable or failed                | `502 Bad Gateway`         | `tunnel_not_connected` or `tunnel_error` |
| Upstream dial, TLS, or round-trip failure after explicit allow | `502 Bad Gateway`         | `upstream_error`                         |

Credential runtime reasons should be specific and redacted, such as `credential_secret_error`, `credential_refresh_error`, `credential_signing_error`, or `credential_injection_error`.

If an error occurs before dialing upstream, no upstream connection is opened. If an upstream error occurs after dialing, audit records include redacted upstream error metadata.

### Request Header Sanitation

Before forwarding normal intercepted HTTP-family requests upstream, the runtime strips hop-by-hop, proxy-only, forwarding, and internal control headers that should not leak upstream. The request strip set includes:

- `Connection`
- `Keep-Alive`
- `Proxy-Authenticate`
- `Proxy-Authorization`
- `Te`
- `Trailers`
- `Transfer-Encoding`
- `Upgrade`
- `Cf-Worker`
- `Cf-Ray`
- `Cf-Ew-Via`
- `Cf-Connecting-Ip`
- `Cdn-Loop`
- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`
- `Via`
- implementation-internal retry/control headers, if any are later introduced.

`Proxy-Authorization` is always redacted in audit and is never treated as an upstream credential.

For forwarded requests, the runtime normalizes the upstream request target for origin-form forwarding: scheme and authority are set for the selected upstream, `Host` is set to the normalized authority, and proxy-form request metadata is not forwarded as-is.

### Response Header Sanitation

Before returning upstream or synthetic HTTP-family responses to the guest, the runtime strips credential-bearing response headers that could leak upstream authentication state:

- `Set-Cookie`
- `Set-Cookie2`
- `WWW-Authenticate`
- `Proxy-Authenticate`
- `Authentication-Info`
- `Proxy-Authentication-Info`

Normal HTTP responses may preserve Basic `WWW-Authenticate` challenges where needed for Git-over-HTTPS compatibility. Synthetic responses and WebSocket upgrade responses use the stripping behavior above.

The runtime strips `Alt-Svc` from intercepted HTTP-family responses to avoid teaching clients to retry owned HTTPS traffic over HTTP/3/QUIC, which is not inspected in v1.

### WebSocket Upgrades

WebSocket upgrade requests use the same endpoint classification, credential selection, rule evaluation, and explicit allow/deny behavior as other HTTP-family requests.

For an allowed `101 Switching Protocols` response, policy and credential decisions happen at the upgrade request. After the upgrade, the runtime relays WebSocket frames raw and opaque. There is no frame-level CEL policy, no post-upgrade credential decision, no frame rewrite contract, no frame logging, no frame hashes, and no frame body samples.

WebSocket upgrade request forwarding preserves the headers required for the handshake, especially `Connection` and `Upgrade`. The normal request-header strip block is not applied to WebSocket upgrade requests. The raw WebSocket bridge forwards request headers in the upgrade request except for `Host`, which is set from the selected upstream authority.

The raw `101 Switching Protocols` response path strips credential-bearing response headers and `Alt-Svc` while preserving the handshake headers needed for the upgrade.

Audit for WebSocket traffic is limited to upgrade request/response metadata, policy/credential/tunnel metadata, duration, byte counts, and errors.

### CONNECT

`CONNECT` is treated as an HTTP method for policy matching. Rules can match `http.method == "CONNECT"` like any other method.

If denied, the runtime returns the normal synthetic denial. If allowed, the runtime applies the same header sanitation and upstream round-trip path as other non-WebSocket HTTP-family requests. We are not adding explicit-proxy tunnel semantics or connection hijacking for `CONNECT` in v1.

### QUIC and HTTP/3

We are not inspecting QUIC or HTTP/3 in v1.

For owned HTTPS endpoints, the runtime strips `Alt-Svc` from intercepted responses so clients do not learn to retry over HTTP/3. If future HTTP/3 advertisement mechanisms are relevant, they should be stripped from intercepted responses as well.

UDP/443 is denied or dropped only when the runtime can confidently associate the destination with an inspected HTTPS endpoint, for example through DNS/VIP/routing state. Unknown or pass-through UDP/443 follows normal `endpoint "ip"` and `settings.default_action` behavior. This avoids turning a configured HTTPS endpoint into a blanket UDP/443 deny for unrelated traffic.

## Credential Blocks

Credentials are request modifiers, not VM secrets. They are tied to endpoints, selected by policy metadata and request context, and resolved only after an explicit allow.

```hcl
credential "bearer_token" "github_api" {
  endpoint        = https.github
  condition       = "http.path.startsWith('/repos/')"
  idempotency_key = "github-api"
}
```

Common schema:

| Attribute   | Type               | Required | Semantics                                                   |
| ----------- | ------------------ | -------- | ----------------------------------------------------------- |
| `endpoint`  | endpoint reference | Yes      | The single endpoint this credential can apply to.           |
| `condition` | string             | No       | CEL expression compiled against the endpoint family facets. |

`credential.endpoint` is a fully qualified typed endpoint reference such as `https.github`. Credentials bind to exactly one endpoint for now. There is no `credential.endpoints` attribute.

`credential.secret` is not part of the policy file. Secret material is resolved out of band by credential identity and credential-kind-defined slots. For example, `bearer_token.github_api` has a `token` slot. The concrete secret store remains outside this policy contract.

`credential.condition` is optional. It is allowed only when the endpoint kind has the `credential_conditions` capability. The initial `https` endpoint can use `http.*` variables. A future `kubernetes` endpoint can use both `http.*` and `k8s.*` variables. Credential conditions cannot reference `credential.*` variables or secret values.

Credential conditions are compiled at policy load. Compile/type errors are load errors. During credential selection, if a credential bound to the classified endpoint has matching static scope but its condition errors at runtime, selection stops immediately and the request fails closed with reason `credential_condition_error`. The runtime must not ignore the broken credential and select no credential or another lower-specificity credential.

Multiple credentials may bind to the same endpoint because request conditions can make selection unambiguous at runtime. The loader should warn, not reject, suspicious cases such as multiple unconditional credentials on the same endpoint or duplicate non-empty condition strings on the same endpoint. Runtime ambiguity is always fatal for that request.

## Credential Selection and Injection

Credential selection happens after L7 endpoint classification and before L7 rule evaluation. Selection picks an identity, not secret bytes. It does not read secrets, refresh tokens, sign requests, or modify outbound headers.

For the classified endpoint and request context:

| Matching credentials | Result                                                        |
| -------------------- | ------------------------------------------------------------- |
| `0`                  | No credential is selected.                                    |
| `1`                  | That credential is selected.                                  |
| `2+`                 | The request fails closed with reason `ambiguous_credentials`. |

Credential selection is part of classifying an endpoint request. If an endpoint supports credentials and multiple credentials match, the request fails closed with `ambiguous_credentials` before rule evaluation, even under `default_action = "allow"` and even if a later allow rule would omit `rule.credential`.

Secret lookup, refresh, signing, and header injection occur only after the final policy decision is an explicit `allow`. They never occur for denied requests, default-denied requests, unknown hosts, or default-allowed fallback requests.

If secret lookup, refresh, signing, or injection fails after an explicit allow, the request returns synthetic `502 Bad Gateway` with a redacted reason such as `credential_secret_error`, `credential_refresh_error`, `credential_signing_error`, or `credential_injection_error`. If the failure occurs before dialing upstream, no upstream connection is opened.

If a credential is selected and the final matching rule is an explicit allow, the selected credential is injected even if that rule did not specify `rule.credential`. `rule.credential` is a predicate, not the injection trigger.

Credential injection overwrites guest-supplied authentication headers for the header being managed. For credential kinds that set `Authorization` or a configured header, the runtime removes existing guest-supplied values for that header, records redacted audit metadata that a guest value was present, and injects the selected credential value. This supports stale or placeholder auth clients while avoiding ambiguous upstream behavior.

## `rule.credential`

Rules may include an optional credential predicate.

```hcl
rule "github-api-with-token" {
  endpoint   = https.github
  credential = bearer_token.github_api
  condition  = "http.path.startsWith('/repos/')"
  verdict    = "allow"
}
```

`rule.credential` is a fully qualified typed credential reference such as `bearer_token.github_api`. It is validated at policy load.

The attribute is a match predicate only. It does not request injection, select a credential, read a secret, or change the request by itself. If omitted, the rule can match both credentialed and uncredentialed requests. If specified, the rule matches only when the selected credential identity equals the referenced credential.

`rule.credential` is allowed on `allow` and `deny` rules.

For a rule with `endpoint = ...`, the referenced credential must bind to that endpoint. For a rule with `endpoints = [...]`, the referenced credential's endpoint must appear directly in the endpoint list. This validation is syntactic and direct. There is no profile expansion, endpoint group expansion, or hidden membership check in this ADR.

`rule.credential` is invalid on rules targeting endpoint kinds that cannot have credentials, such as `ip` and `http`.

## Credential Kind Registry

Credential kinds live in a static registry. A credential kind defines policy attributes, compatible endpoint capabilities, secret slots, redaction tokens, and injection behavior. The evaluator uses that registry instead of baking every credential type into rule evaluation.

The initial credential kinds are:

| Kind                 | Policy attributes           | Secret slots                                                   | Initial behavior                                                        |
| -------------------- | --------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `basic_auth`         | `username`                  | `password`                                                     | Sets `Authorization: Basic base64(username:password)`.                  |
| `bearer_token`       | optional `idempotency_key`  | `token`                                                        | Sets `Authorization: Bearer <token>`.                                   |
| `header_token`       | `header`, optional `prefix` | `token`                                                        | Sets the configured header to `prefix + token`.                         |
| `github_oauth`       | none                        | OAuth token material                                           | Supports GitHub API bearer auth and Git smart HTTP-compatible auth.     |
| `openai_codex_oauth` | none                        | OAuth token material                                           | Sets OpenAI Codex auth headers and refreshes tokens when needed.        |
| `aws_credential`     | none                        | `access_key_id`, `secret_access_key`, optional `session_token` | Performs generic AWS SigV4 re-signing on compatible `endpoint "https"`. |

`basic_auth.username`, `header_token.header`, and `header_token.prefix` are policy metadata, not secrets. Secret slots are never logged.

`aws_credential` initially supports generic AWS SigV4 re-signing on HTTPS endpoints. EKS bearer minting belongs with a future `kubernetes` endpoint because it depends on Kubernetes request semantics, not generic HTTPS alone.

Credential kind and endpoint compatibility is validated at policy load. For example, `bearer_token` can bind to `https` but not `http`; `aws_credential` can bind to compatible HTTPS-family endpoints that support request signing; future `postgres` and `ssh` credentials must declare their own compatibility.

## Tailscale Runtime Blocks

A Tailscale block names an embedded node the runtime can use later. Defining the node does not route anything by itself; routing still comes from an explicit allow rule or a configured inbound forward.

```hcl
tailscale "main" {
  hostname        = "bento-devbox"
  auth_key_secret = "tailscale-authkey"
  tags            = ["tag:bentobox"]
  control_url     = "https://controlplane.tailscale.com"
}
```

Schema:

| Attribute             | Type           | Required | Semantics                                                     |
| --------------------- | -------------- | -------- | ------------------------------------------------------------- |
| `hostname`            | string         | No       | Tailnet hostname for the embedded node.                       |
| `auth_key_secret`     | secret handle  | No       | Out-of-band secret handle for a Tailscale auth key.           |
| `oauth_client_secret` | secret handle  | No       | Out-of-band secret handle for OAuth client-secret based auth. |
| `tags`                | list of string | No       | Tailscale tags requested by the node.                         |
| `control_url`         | string         | No       | Optional alternate control plane URL.                         |

At most one of `auth_key_secret` and `oauth_client_secret` may be set. If neither is set, the node starts in interactive-login mode and surfaces the login URL through runtime status/logging. This is valid policy, not a load error.

`oauth_client_secret` requires at least one `tags` entry at policy load. OAuth-created Tailscale auth keys must be tag-scoped. `auth_key_secret` and interactive-login mode may leave `tags` unset.

Each `tags` entry must be a non-empty string in Tailscale's normal `tag:<name>` form. Empty tags and non-`tag:` values are load errors.

`hostname` receives lightweight load-time validation as a single DNS-label-like hostname: non-empty, no dots, spaces, or path characters. Tailscale runtime remains responsible for hostname collisions, ACL/control-plane acceptance, and other runtime failures.

`control_url` must be an absolute `http://` or `https://` URL with a host. Relative URLs, missing hosts, and unsupported schemes are load errors. Reachability, auth, and control-plane failures remain runtime errors.

Secret handles are stable runtime identifiers, not concrete secret store paths. The concrete secret store remains outside this policy contract.

Tailscale state is persisted under the implementation runtime state directory, not inside the VM. Shutdown must close embedded nodes cleanly. Auth failures, missing secrets, ACL denial, DNS failure, and dial timeouts are surfaced as redacted runtime/audit metadata, never as secret material.

### Outbound Tailscale Routing

Outbound use of Tailscale is selected by a winning `allow` rule with `tunnel = tailscale.<name>`:

```hcl
endpoint "ip" "tailnet_postgres" {
  destination = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
  protocol    = "tcp"
  ports       = [5432]
}

rule "allow-tailnet-postgres" {
  endpoint = ip.tailnet_postgres
  verdict  = "allow"
  tunnel   = tailscale.main
}
```

Initial outbound Tailscale tunneling is TCP-only. `tunnel = tailscale.<name>` is allowed only for TCP-capable transports initially: `http`, `https`, and TCP `endpoint "ip"` flows.

If a UDP flow matches an explicit allow rule selecting a Tailscale tunnel, the flow fails closed and audit records use reason `tunnel_unsupported_protocol`. UDP tunneling can be considered later only after semantics, audit aggregation, and Tailscale dial behavior are specified cleanly.

If a rule-selected Tailscale node is not connected, fails to authenticate, cannot dial, or otherwise cannot carry the selected flow/request, the result is synthetic `502 Bad Gateway` for HTTP-family traffic or an equivalent connection failure for raw TCP, with reason such as `tunnel_not_connected` or `tunnel_error`. The runtime must not fall back to direct internet routing. A rule-selected tunnel is part of the allow decision.

`tunnel` does not smuggle hostnames into `endpoint "ip"`; host-level policy still belongs in `http` or `https` endpoint matching where Host/SNI is visible.

## Inbound Forward Blocks

A forward is an exposure, not an outbound firewall rule. It creates a host-side or tailnet-side listener and proxies accepted connections into a VM target. Endpoint blocks describe VM egress policy; forward blocks describe inbound listener configuration.

```hcl
forward "host" "ssh" {
  listen = "tcp/127.0.0.1:2222"

  target {
    port = 22
  }
}

forward "tailscale" "api" {
  tailscale = tailscale.main
  listen    = "tcp/:8080"

  target {
    selector = "label:app=api"
    port     = 8080
  }
}
```

The first `forward` label selects the listener kind. The second label is the forward name. The initial listener kinds are `host` and `tailscale`.

Common forward schema:

| Attribute   | Type          | Required                  | Semantics                                                     |
| ----------- | ------------- | ------------------------- | ------------------------------------------------------------- |
| `listen`    | string        | Yes                       | Listener address such as `tcp/127.0.0.1:2222` or `tcp/:8080`. |
| `target`    | nested block  | No                        | VM target selector and port.                                  |
| `tailscale` | Tailscale ref | `tailscale` forwards only | Embedded Tailscale node that owns the listener.               |

Inbound forwards are outside the outbound endpoint/rule/`settings.default_action` policy model. A configured forward is an explicit inbound exposure. If its listener exists, the runtime accepts/proxies matching connections and audits them. Outbound endpoint/rule/default-action policy is not evaluated for inbound forwarded connections.

Initial inbound forwards support only raw TCP byte proxying. They do not parse HTTP, do not inject credentials, do not run L7 policy, and do not emit L7 request audit fields even if the listener is on port `80` or `443`. Forward audit is transport-level: listener, source, target, routing metadata, bytes, duration, and errors.

UDP forwards are a deliberate extension.

`forward "host"` starts localhost-only. Wildcard or non-loopback host binds fail startup by default. Tailscale forwards are the intended remote-access path. A future explicit opt-in is required before allowing `0.0.0.0`, `::`, or non-loopback LAN listeners.

`forward "tailscale"` exposure relies on Tailscale identity/ACLs plus the explicit configured forward block. We are not adding an additional inbound policy rule language or per-source allowlist for Tailscale forwards. Runtimes record source tailnet identity/IP when available.

Duplicate listener addresses for the same listener kind are load errors. Invalid listener syntax, unsupported protocols, host-bind policy violations, missing Tailscale references, bind failures, and Tailscale listener creation failures are load/startup errors because the configured exposure does not exist.

Target selection and lease availability errors are resolved per connection. If the listener exists but the target is missing, ambiguous, detached, cross-network, has no current guest IP lease, or the default target is ambiguous, the listener remains up. Each accepted connection attempts target resolution. If resolution fails, that connection receives a connection failure and the runtime writes audit/log metadata such as `target_unresolved`, `target_ambiguous`, or `target_no_lease`.

### Shared Target Resolution

`target` blocks use one shared shape for host and Tailscale forwards:

```hcl
target {
  selector = "label:app=api"
  port     = 8080
}
```

Schema:

| Attribute  | Type   | Required | Semantics                                                |
| ---------- | ------ | -------- | -------------------------------------------------------- |
| `selector` | string | No       | VM selector. If omitted, resolve the network default VM. |
| `port`     | int    | No       | VM destination port. If omitted, use the listener port.  |

Supported user-facing selector forms are:

- `name:<machine-name>`
- `id:<machine-id-or-unambiguous-prefix>`
- `label:<key>=<value>`

Annotation selectors are not user-facing. Bento-owned annotations may be used internally to mark a default target, but policy authors do not reference annotations directly.

`id:<prefix>` may use unambiguous machine ID prefixes. Per-connection resolution fails with `target_ambiguous` if more than one machine matches the prefix and `target_unresolved` if none match.

`name:<machine-name>` is an exact, case-sensitive match against the canonical machine name provided to the runtime.

`label:<key>=<value>` must resolve to exactly one machine per connection. Zero matches fail with `target_unresolved`; multiple matches fail with `target_ambiguous`. Load balancing and fanout are out of scope for v1.

Default target rules:

1. A private single-VM network uses its attached/owner VM as the default target.
2. A named network with one attached VM may use that VM as the default target.
3. A named network with multiple attached VMs requires exactly one Bento-owned internal default-target marker.
4. Missing, detached, cross-network, no-lease, or ambiguous targets fail per connection as described above.

Target resolution returns the machine identity, machine name, labels needed for audit, guest MAC when available, current guest IP lease, selected port, and selector/default reason. The resolver is a policy/runtime abstraction so a future Linux bridge or eBPF backend can populate equivalent maps without changing policy syntax.

## Audit Semantics

Audit should answer "what happened?" without becoming the decision engine or a secret sink. It is an observability stream emitted by the runtime, not a policy action. The policy file does not include `audit` rules or audit sink configuration.

The first runtime sink is append-only JSONL at `audit.jsonl` in the same runtime directory as the implementation service log. For the first `netd` implementation, that service log is `netd.log`. The audit path is not user-configurable in HCL, global config, or CLI. An implementation may receive an internal runtime path from the launcher, but the user-facing contract is location-by-runtime-directory. Service/debug logs stay separate; traffic audit records belong in `audit.jsonl`.

The record shape and redaction requirements are part of the policy contract. The contract deliberately does not over-specify post-start write guarantees, backpressure behavior, fsync policy, or fail-open/fail-closed behavior for audit sink failures. Implementations should make audit write failures visible in service logs and runtime health.

All audit records are JSON objects, one per line. Every record includes the common fields below, with `policy_hash` present only when a policy file was loaded:

| Field         | Type                | Semantics                                                                                                                                                                     |
| ------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`     | integer             | Audit schema version. Initially `1`.                                                                                                                                          |
| `phase`       | string              | Lifecycle phase for the record. Current terminal records use `end`; future lifecycle records may use `start` where that adds value.                                           |
| `family`      | string              | Traffic family for the record. Current values are `ip` and `http`; inbound forwarding uses `forward` when implemented.                                                          |
| `timestamp`   | string              | UTC RFC3339Nano timestamp.                                                                                                                                                    |
| `policy_hash` | string/omitted      | `sha256:<64 lowercase hex chars>` over exact raw bytes of the single loaded policy HCL file. Omitted when no policy file is provided and the implicit default policy is used. |
| `vm_id`       | string/null/omitted | Stable VM identity when known/applicable.                                                                                                                                     |
| `network_id`  | string/null/omitted | Stable network identity when known/applicable.                                                                                                                                |

`profile_name` must not appear in audit records.

`policy_hash` is audit metadata only. When present, it ties JSONL records to the exact loaded policy source file. Comments, formatting, disabled rules, and other source bytes are part of the hash. There are no includes/imports or multi-file hash semantics. When no policy file is provided, the implicit default policy has no source file bytes and audit records omit `policy_hash`.

Audit IDs use UUIDv7 strings for stable uniqueness and useful time ordering:

- `flow_id` identifies one L3/L4 flow.
- `request_id` identifies one inspected L7 request.
- `parent_flow_id` links an L7 request record to its underlying TCP `flow_id` when available.

Parsers should tolerate unknown fields on known record versions so new metadata can be added without breaking older tooling.

### Phases And Families

Audit records are organized by lifecycle `phase` and traffic `family`, not by a separate event-name taxonomy. Current runtime audit records are terminal records with `phase = "end"`. A later implementation may add `phase = "start"` where a lifecycle pair is useful, but terminal `end` records remain the authoritative completed audit stream.

The current traffic families are:

| Family    | Semantics                                                  |
| --------- | ---------------------------------------------------------- |
| `ip`      | Outbound L3/L4 TCP or UDP traffic.                         |
| `http`    | Intercepted HTTP-family traffic, including HTTPS MITM.     |
| `forward` | Inbound forwarding traffic when forwarding is implemented. |

For denied traffic or errors that never open an upstream/target connection, audit emits only a terminal record with `phase = "end"`, the relevant `family`, and verdict/reason/status populated.

### L3/L4 Flow Audit

IP decisions use `family = "ip"` records because there is no L7 request lifecycle. `netd` logs all L3/L4 actions by default: default allow, default deny, explicit rule allow, explicit rule deny, classification handoff, and terminal forwarding errors. These records use `phase = "end"` in the initial implementation.

TCP emits a terminal `family = "ip"` record when the flow is denied, completed, handed to an L7 proxy, or errored. UDP traffic is aggregated by 5-tuple in a later implementation and emits an aggregate terminal `family = "ip"` record when the implementation-defined idle timeout or close condition fires. Denied UDP can emit a single terminal record without creating long-lived aggregate state.

The UDP aggregation timeout is intentionally implementation-defined for now.

L3/L4 audit metadata includes enough context for:

- `flow_id`,
- `direction`, such as VM egress,
- `protocol`, `ip_version`, source/destination IPs, and source/destination ports,
- `policy.endpoint_kind`, `policy.endpoint_name`, and `policy.rule_name` when policy endpoint/rule metadata is available,
- verdict and reason,
- tunnel metadata when routing uses Tailscale,
- duration, byte counts, packet counts when available,
- redacted error metadata.

`policy` presence means an outbound policy endpoint matched, was selected, or an explicit rule matched. `policy.endpoint_kind` and `policy.endpoint_name` identify the selected endpoint. `policy.rule_name` identifies the explicit matching rule. When `policy` is omitted, the action came from default behavior or an implementation/runtime failure before endpoint selection.

### HTTP-Family Request Audit

Intercepted HTTP-family traffic uses `family = "http"` records for both cleartext HTTP and HTTPS MITM. The `http.scheme` field identifies the observed transport scheme (`http` or `https`). Terminal records use `phase = "end"` after deny, forward completion, or error. If a later implementation adds a start phase, it must only emit `phase = "start"` after classification/rule context is known and proxy/upstream work is about to begin.

Body hashes and samples appear only on terminal HTTP-family records. Terminal records carry final request/response byte counts, hashes, samples, status, and errors so each body sample is recorded once.

HTTP-family audit metadata includes:

- `request_id`,
- `parent_flow_id` when available,
- `policy.endpoint_kind`, `policy.endpoint_name`, and `policy.rule_name` when policy endpoint/rule metadata is available,
- `family = "http"`, with `http.scheme` as `http` or `https`,
- final verdict, reason, and guest-visible status code,
- `http.request.method`, normalized host, path, parsed query, and redacted request headers,
- `http.response.status` and redacted response headers that reflect what the guest saw,
- TLS metadata for HTTPS when available,
- credential kind/name/status/error reason without values,
- tunnel metadata when an explicit allow uses Tailscale,
- upstream error metadata when applicable,
- duration and byte counts.

Example terminal HTTPS record:

```json
{
    "version": 1,
    "phase": "end",
    "family": "http",
    "timestamp": "2026-06-18T20:41:33.123456789Z",
    "policy_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "request_id": "018f2f7d-8a0b-7c6d-9e10-111213141516",
    "parent_flow_id": "018f2f7d-89ff-7c6d-9e10-111213141516",
    "vm_id": "vm_123",
    "network_id": "net_123",
    "policy": {
        "endpoint_kind": "https",
        "endpoint_name": "github",
        "rule_name": "github-read-only"
    },
    "verdict": "allow",
    "reason": "read-only GitHub API access",
    "http": {
        "scheme": "https",
        "request": {
            "method": "GET",
            "host": "api.github.com",
            "path": "/repos/nickvd/bentobox",
            "query": "per_page=100",
            "headers": { "Authorization": ["<redacted>"] }
        },
        "response": {
            "status": 200,
            "headers": { "Content-Type": ["application/json"] }
        }
    },
    "tls": {
        "sni": "api.github.com",
        "intercepted": true,
        "client_version": "TLS1.3",
        "upstream_version": "TLS1.3"
    },
    "credential": {
        "kind": "bearer_token",
        "name": "github_api",
        "status": "injected"
    },
    "request_body": {
        "sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "bytes": 0
    },
    "response_body": {
        "content_encoding": "gzip",
        "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bytes": 4096,
        "sample": {
            "encoding": "decoded:gzip",
            "truncated": true,
            "value": "{\"items\":["
        }
    },
    "bytes_in": 123,
    "bytes_out": 456,
    "duration_ms": 42
}
```

### Forward Audit

Inbound forward audit uses `family = "forward"` records. Terminal forwarding records use `phase = "end"`. A later implementation may add `phase = "start"` after target resolution has selected a concrete target and proxying is about to begin.

Forward audit metadata includes:

- forward kind and name,
- listener protocol/address,
- source address and, for Tailscale forwards, source tailnet identity/IP when available,
- target selector, selector/default reason, resolved machine ID/name, labels needed for audit, guest MAC when available, guest IP lease, and target port,
- connection result, reason, errors,
- duration and byte counts.

For target resolution failures before proxying begins, emit only a terminal `family = "forward"` record with a reason such as `target_unresolved`, `target_ambiguous`, or `target_no_lease`.

### TLS Audit

HTTPS audit should record TLS metadata when available:

- ClientHello SNI,
- whether the connection was intercepted, passed through, or denied before interception,
- client-facing TLS version/cipher/ALPN,
- upstream TLS version/cipher/ALPN,
- upstream certificate subject, issuer, DNS names, validity range, and validation error.

TLS audit must never log private keys, certificate PEM bodies, session keys, decrypted TLS secrets, or raw authorization material.

### Body Sampling

Audit body sampling is always-on and bounded for intercepted HTTP-family traffic only. It does not apply to L3/L4 payloads, unknown/pass-through traffic, or WebSocket frames after `101 Switching Protocols`.

For request and response bodies, audit may include:

- SHA-256 hash over original wire body bytes,
- total original wire byte count,
- original HTTP `Content-Encoding` when present,
- bounded redacted sample object.

Sample objects are structured:

```json
{
    "encoding": "utf-8",
    "truncated": true,
    "value": "sample text"
}
```

`encoding` describes the persisted preview representation, not necessarily the original wire content. Valid initial values include:

- `utf-8` for direct textual samples,
- `binary` for base64-encoded binary samples,
- `decoded:gzip`, `decoded:br`, `decoded:deflate`, or `decoded:zstd` for decoded compressed previews.

For `encoding = "binary"`, `value` is base64. Textual samples store UTF-8 strings directly.

For compressed bodies, the runtime may decode captured prefixes for audit preview readability for `gzip`, `br`, `deflate`, and `zstd`, with a separate decoded-output cap and truncation marker. Hashes and byte counts remain over original wire bytes. `content_encoding` records the original HTTP content encoding; sample `encoding` records how the persisted preview is represented.

### Redaction

Redaction is mandatory.

Sensitive headers are redacted case-insensitively, including:

- `Authorization`,
- `Proxy-Authorization`,
- `Cookie`,
- `Set-Cookie`,
- any header name matching auth/token/secret/key/password/cookie.

Known selected/injected credential values are redaction tokens across the entire intercepted HTTP-family exchange. The runtime redacts these values from request headers, response headers, request body samples, and response body samples, even when a value appears coincidentally in unrelated text. Redaction prefers false positives over leaking secrets. When multiple known secret values overlap, redaction applies longest-first.

Credential audit metadata may include kind, name, selected/injected/skipped/error status, and high-level error reason. It must never include token values, passwords, authorization header values, signing keys, refreshed OAuth tokens, or injected header values.

## Policy Warnings

Warnings are for suspicious but still-valid policy. They should be non-fatal and still let the runtime start:

- `settings.audit.body_buffer < body_storage`,
- multiple unconditional credentials on one endpoint,
- duplicate credential condition strings on one endpoint.

Warnings are written to service logs and runtime status. They never appear in `audit.jsonl` and never change enforcement behavior. True runtime ambiguity still fails closed.

## Future Endpoint Extension Model

Adding a protocol should mean adding registry entries and transport adapters, not forking the rule engine.

The high-level process for a new endpoint kind is:

1. Add an endpoint registry entry with its HCL schema, validation, normalization, family, facets, transport, and capabilities.
2. Add or reuse a facet that defines CEL variables, typed request context, and audit fields.
3. Add or reuse a transport that can classify requests before upstream side effects when policy needs default-deny L7 behavior.
4. Declare compatible credential kinds and injection hooks.
5. Add host, port, or protocol dispatch entries as needed.
6. Add load-time validation and runtime tests for rule matching, credential selection, default behavior, and audit redaction.

### Future `endpoint "kubernetes"`

Kubernetes should be modeled as its own endpoint kind, not as raw HTTPS with a pile of ad hoc HTTP conditions. Its likely registry entry is:

| Kind         | Family | Facets        | Transport    | Credentials |
| ------------ | ------ | ------------- | ------------ | ----------- |
| `kubernetes` | `k8s`  | `http`, `k8s` | `https-mitm` | Yes         |

The endpoint can reuse `https-mitm` because Kubernetes API traffic is HTTPS. It should compose the `http` facet with a `k8s` facet. The `http` facet supplies method, host, path, query, and headers. The `k8s` facet can add parsed API group, version, resource, namespace, name, verb, and subresource fields.

Rules for `kubernetes` endpoints should use family `k8s`, not `http`, even though the transport and base facet are shared. That prevents a broad HTTP rule from accidentally applying to Kubernetes semantics unless the policy author explicitly targets a Kubernetes endpoint. Credential kinds such as `aws_credential` may later mint EKS bearer tokens here because this endpoint has Kubernetes-aware request context.

### Future `endpoint "postgres"`

PostgreSQL should be a protocol-aware SQL endpoint rather than an IP endpoint with a port number. Its likely registry entry is:

| Kind       | Family | Facets | Transport        | Credentials |
| ---------- | ------ | ------ | ---------------- | ----------- |
| `postgres` | `sql`  | `sql`  | `postgres-proxy` | Yes         |

The `postgres-proxy` transport would classify the startup message, database, username, TLS mode, and query boundaries before forwarding upstream effects. The `sql` facet can expose fields such as database, user, statement type, and normalized operation metadata. The first version does not need to parse every SQL dialect perfectly; it does need to be explicit about which fields are reliable enough for policy.

Punch-through under default deny is valid for Postgres only if the transport can classify the needed startup/query metadata before upstream contact or before any upstream-visible action. If that cannot be guaranteed for a policy field, that field must not be available for pre-allow decisions.

Postgres credentials should bind to a `postgres` endpoint and inject through protocol-native authentication, not through HTTP headers. The shared policy model still handles endpoint classification, credential selection, `rule.credential` predicates, and audit redaction.

### Future `endpoint "ssh"`

SSH should be a protocol-aware endpoint for login, channel, and command policy. Its likely registry entry is:

| Kind  | Family | Facets | Transport   | Credentials |
| ----- | ------ | ------ | ----------- | ----------- |
| `ssh` | `ssh`  | `ssh`  | `ssh-proxy` | Yes         |

The `ssh` facet can expose login user, requested subsystem, exec command, channel type, and remote forwarding intent as those fields become available. The transport must be careful about the timing of authentication and command execution. A policy allow should happen before upstream-visible authentication or command side effects whenever the rule depends on fields available before those effects.

SSH credentials should use SSH-native key or agent behavior rather than pretending every credential is an HTTP header. The common policy model should still provide endpoint binding, credential predicates, ambiguity handling, explicit allow injection timing, and redacted audit records.

## Security Considerations

The core security rule is simple: if a policy decision depends on inspected metadata, the allow must happen before upstream-visible effects. L7 classification punch-through exists to satisfy that rule under default deny. It must not become a hidden allow path.

Credentials are outside the VM and outside the policy file. A selected credential is injected only after an explicit allow. Default allow, unknown hosts, denied requests, condition errors, ambiguous credentials, and tunnel failures do not read or inject secrets.

Redaction is part of the security model. Audit data is valuable precisely because it is detailed; that detail must not turn `audit.jsonl` into a secret dump. Header redaction, body sample limits, known credential value redaction, and TLS secret exclusions are mandatory.

Inbound forwards are explicit exposures. Host forwards are localhost-only by default to avoid accidental LAN/public listeners. Tailscale forwards rely on Tailscale identity/ACLs plus the explicit forward block, and should audit source identity when available.

No-SNI HTTPS is intentionally narrow. It can be MITM'd only for explicit raw-IP HTTPS bindings. Without such a binding, no-SNI HTTPS fails closed rather than guessing ownership.

## Consequences

### Positive

- The policy file has one consistent shape across IP, HTTP, HTTPS, and future protocol-aware endpoints.
- Endpoint kind, family, facet, transport, and capability separation avoids duplicating rule evaluation for every new protocol.
- Default-deny L7 policy works without contacting upstream services before policy evaluation.
- Credentials are selected deterministically and injected only after explicit allow.
- Removing `credential.secret` keeps policy review focused on intent instead of storage plumbing.
- Removing `audit` as a verdict keeps policy decisions terminal and audit behavior observable but separate.
- Audit records have stable IDs, versions, timestamps, policy-source identity, and body-sample structure from the start.
- Future `kubernetes`, `postgres`, and `ssh` endpoints have a clear extension path.

### Negative

- The registry model adds upfront structure compared with direct `switch kind` code.
- Host and credential ambiguity checks make policy loading stricter.
- L7 classification punch-through requires each transport to be precise about when upstream contact is allowed.
- Credential conditions introduce a second CEL evaluation surface that must be tested as carefully as rule conditions.
- Audit records are intentionally detailed, which increases redaction and sampling responsibility.
- Single-file policy keeps source identity simple but rules out include-based policy composition.

### Constraints

- The registry is static for now. Adding endpoint and credential kinds requires code changes.
- No endpoint kind may bypass the common rule ordering, default action, credential selection, or redaction semantics.
- Transports must declare whether they can classify before upstream contact.
- Secret values and injected authorization material must never appear in logs or audit records.
- Default allow must never imply credential injection or Tailscale tunnel routing.
- Inbound forwards must not accidentally become L7 policy or credential injection paths.

## Appendix A: Complete Policy Example

This example denies by default, allows DNS to the local resolver, allows read-only GitHub API access over HTTPS with a bearer token, allows cleartext HTTP to an internal metadata service without credentials, and exposes local SSH through a localhost-only host forward.

```hcl
settings {
  default_action = "deny"

  audit {
    body_buffer  = "1MiB"
    body_storage = "4KiB"
  }
}

endpoint "ip" "local_dns_udp" {
  destination = ["192.168.127.1/32"]
  protocol    = "udp"
  ports       = [53]
}

endpoint "ip" "local_dns_tcp" {
  destination = ["192.168.127.1/32"]
  protocol    = "tcp"
  ports       = [53]
}

endpoint "http" "metadata" {
  hosts = ["metadata.internal", "metadata.internal:8080"]
}

endpoint "https" "github" {
  hosts = ["api.github.com", "*.githubusercontent.com"]
}

credential "bearer_token" "github_api" {
  endpoint        = https.github
  condition       = "http.path.startsWith('/repos/')"
  idempotency_key = "github-api"
}

forward "host" "ssh" {
  listen = "tcp/127.0.0.1:2222"

  target {
    port = 22
  }
}

rule "allow-dns" {
  endpoints = [ip.local_dns_udp, ip.local_dns_tcp]
  verdict   = "allow"
  priority  = 100
  reason    = "local DNS resolver"
}

rule "allow-metadata-reads" {
  endpoint  = http.metadata
  condition = "http.method == 'GET'"
  verdict   = "allow"
  priority  = 100
  reason    = "metadata reads"
}

rule "deny-github-writes" {
  endpoint  = https.github
  condition = "!(http.method in ['GET', 'HEAD'])"
  verdict   = "deny"
  priority  = 200
  reason    = "GitHub writes are not allowed"
}

rule "allow-github-reads-with-token" {
  endpoint   = https.github
  credential = bearer_token.github_api
  condition  = "http.method in ['GET', 'HEAD']"
  verdict    = "allow"
  priority   = 100
  reason     = "read-only GitHub API access"
}
```

Under this policy, `default_action = "deny"` does not block `https-mitm` from reading enough of a GitHub TLS/HTTP request to classify it. It does block any upstream connection until the GitHub rule explicitly allows the request. If the request is allowed by the final rule, the bearer token is resolved and injected. If no rule matches, the request is denied and no secret is read.

The host forward is not outbound policy. It listens on localhost and proxies raw TCP to the default VM target on port `22`, auditing the forward but not parsing SSH or applying outbound rules.

## Appendix B: Tailscale Examples

Interactive login mode:

```hcl
tailscale "dev" {
  hostname = "bento-devbox"
}
```

OAuth auth with required tags:

```hcl
tailscale "prod" {
  hostname            = "bento-prod"
  oauth_client_secret = "tailscale-oauth-client-secret"
  tags                = ["tag:bentobox"]
}
```

Outbound HTTP-family routing through Tailscale:

```hcl
endpoint "https" "tailnet_grafana" {
  hosts = ["grafana.tailnet.ts.net"]
}

rule "allow-tailnet-grafana" {
  endpoint = https.tailnet_grafana
  verdict  = "allow"
  tunnel   = tailscale.dev
}
```

Inbound Tailscale forward:

```hcl
forward "tailscale" "api" {
  tailscale = tailscale.dev
  listen    = "tcp/:8080"

  target {
    selector = "label:app=api"
    port     = 8080
  }
}
```

## Appendix C: Invalid Policy Examples

This rule is invalid because it mixes endpoint families:

```hcl
rule "mixed" {
  endpoints = [ip.private, https.github]
  verdict   = "allow"
}
```

This endpoint is invalid because `protocol = "any"` cannot have ports:

```hcl
endpoint "ip" "bad" {
  destination = ["10.0.0.0/8"]
  protocol    = "any"
  ports       = [443]
}
```

This endpoint is invalid because `endpoint "ip"` does not accept hostnames:

```hcl
endpoint "ip" "tailnet" {
  destination = ["grafana.tailnet.ts.net"]
}
```

This credential is invalid because plain HTTP endpoints cannot have credentials:

```hcl
endpoint "http" "api" {
  hosts = ["api.internal"]
}

credential "bearer_token" "api" {
  endpoint = http.api
}
```

This rule is invalid because the credential's endpoint is not directly referenced by the rule:

```hcl
endpoint "https" "github" {
  hosts = ["api.github.com"]
}

endpoint "https" "openai" {
  hosts = ["api.openai.com"]
}

credential "bearer_token" "github_api" {
  endpoint = https.github
}

rule "wrong-credential" {
  endpoint   = https.openai
  credential = bearer_token.github_api
  verdict    = "allow"
}
```

This host configuration is invalid because two endpoints on the same transport and port own the same exact normalized host:

```hcl
endpoint "https" "github_a" {
  hosts = ["api.github.com"]
}

endpoint "https" "github_b" {
  hosts = ["api.github.com:443"]
}
```

This wildcard host is invalid because wildcard IP patterns are not supported:

```hcl
endpoint "https" "bad_ip_wildcard" {
  hosts = ["*.0.0.1"]
}
```

This Tailscale block is invalid because OAuth auth requires at least one valid `tag:` entry:

```hcl
tailscale "bad" {
  oauth_client_secret = "tailscale-oauth-client-secret"
}
```

This host forward is invalid by default because it binds a non-loopback address:

```hcl
forward "host" "public_ssh" {
  listen = "tcp/0.0.0.0:2222"

  target {
    port = 22
  }
}
```
