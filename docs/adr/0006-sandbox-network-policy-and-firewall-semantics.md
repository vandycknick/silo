# 6. Sandbox Network Policy and Firewall Semantics

Date: 2026-06-18

## Status

Proposed

## The Problem

A microVM gives us a strong compute boundary. The workload runs inside a VM-backed sandbox, using a runtime such as libkrun or Apple's Virtualization.framework, so the guest kernel, processes, filesystem, and memory are isolated from the host.

That does not, by itself, make the workload safe on the network.

A sandboxed workload can still fetch code, talk to package registries, call APIs, scan local networks, exfiltrate data, or use credentials it should never possess. If the VM has ordinary network access, then the VM boundary contains compute but not intent. The host can say "this workload is isolated," but it cannot yet say "this workload may only talk to these services, under these rules, with these credentials, and with this audit trail."

This ADR defines that missing layer: a host-side firewall and policy engine for microVM networking. It also defines the glue layer between `libvm`, durable machine configuration, launch-time secret material, and the networking components that enforce policy.

## Why The VM Boundary Is Not Enough

Network access is where a useful sandbox becomes dangerous.

A development workload often needs to do legitimate network work. It may clone from GitHub, download packages, call model APIs, reach internal services through a tailnet, or expose a local debug port back to the host. Blocking all network access makes the sandbox useless for most real tasks.

Allowing all network access is not acceptable either. A workload with broad egress can reach services unrelated to its job. A workload with secrets inside the guest can leak those secrets. A workload with unmediated access to a tailnet can turn a local development VM into a bridge into a private network.

The host needs to remain the authority. The guest should make ordinary network requests. The host-side networking runtime should decide what those requests mean, whether they are allowed, whether credentials may be applied, whether a tunnel should be used, and what record should be written for later inspection.

## What The Firewall Engine Must Decide

The engine has to do more than match IP addresses.

Some decisions are L3/L4 decisions: allow UDP DNS to `1.1.1.1:53`, deny raw TCP to private networks, or route a specific connection through a tailnet.

Other decisions are L7 decisions: allow HTTPS to `chatgpt.com`, inject an OAuth credential only for that endpoint, deny requests whose HTTP method or path does not match a condition, or audit the request without leaking credential material.

Inbound exposure is a different decision again. A host port forward or tailnet forward is not an outbound firewall rule. It is an explicit exposure declaration that needs its own audit trail.

This means the policy engine needs a canonical model for endpoints, credentials, rules, tunnels, forwards, CEL conditions, defaults, and audit records. That model must be independent from any one VM runtime, networking implementation, or authoring interface.

## Determination

We define `NetworkPolicy` as the canonical policy contract for sandbox networking.

`libvm` owns policy assembly, validation, normalization, persistence, and launch-time materialization. Host-side networking components consume normalized policy JSON through `--policy-file` and receive secret material separately through scoped environment variables.

The policy JSON is the engine contract. It is optimized for stable enforcement, durable configuration, and component boundaries. It is not required to be the only way humans author policy.

The key determinations are:

1. `NetworkPolicy` is the canonical policy contract.
2. `libvm` owns policy assembly, validation, normalization, persistence, and runtime materialization.
3. Host-side networking components consume normalized canonical policy JSON and launch-time environment variables only.
4. Canonical policy JSON never contains secret values, refresh tokens, secret-store paths, source layout, parser handles, or implementation indexes.
5. Secret material is passed separately through network-scoped environment variables.
6. CEL condition source strings live in canonical policy. Components compile and evaluate those conditions before enforcement.
7. `settings.default_action` defaults to `allow`. It applies only when no explicit rule matches at the relevant stage.
8. Rules have only terminal verdicts: `allow` and `deny`. Audit is not a verdict.
9. L7 transports may classify configured HTTP/HTTPS traffic under default deny, but classification punch-through never permits upstream contact, credential injection, or data forwarding by itself.
10. Credentials are endpoint-bound request modifiers. `rule.credential` is a predicate over the selected credential identity, not an injection trigger.
11. Secret lookup, refresh, signing, and injection occur only after an explicit allow. Runtime credential failures fail closed and do not fall back to unauthenticated forwarding.
12. Tailscale outbound routing is selected only by an explicit allow rule with a tunnel reference. Default allow never tunnels.
13. Inbound forwards are configured exposures and are outside the outbound endpoint/rule/default-action policy model.
14. Policy-load warnings are non-fatal and visible in service logs and runtime status, not in policy audit events.
15. Policy changes are durable full-policy replacements. Starting a machine never replaces policy.

## Policy Lifecycle

The policy lifecycle has four distinct artifacts.

1. An authored input is what a user or tool writes.
2. A `NetworkPolicy` is the typed policy value.
3. A normalized policy is the durable machine network configuration.
4. Network launch material is the per-start secret and hook configuration.

First, an authored input is turned into a typed `NetworkPolicy`. That can happen through Rust builders, canonical JSON loading, CLI operations, tests, or any future frontend.

Second, the policy is validated and normalized. Defaults become explicit. Unknown fields are rejected. References are resolved. Rule array order is preserved because it is semantically meaningful.

Third, the normalized policy is persisted as part of durable machine network configuration. Persisting the normalized value avoids changes in future frontend defaults from changing stop/start behavior.

Fourth, start options supply launch-time material only. They do not alter the durable policy. If a policy requires secret material, the caller starting the machine supplies the required network secret slots for that launch.

Finally, `libvm` writes the normalized policy to a runtime JSON file and starts the selected networking component with:

```sh
--policy-file /runtime/.../network-policy.json
```

That file is generated by `libvm`. It is not a user-authored source file.

## Vocabulary

A **NetworkPolicy** is the canonical policy value defined by this ADR.

A **frontend** is any authoring mechanism that produces a `NetworkPolicy`.

A **normalized policy** is a `NetworkPolicy` with defaults filled, unknown fields rejected, references resolved, and effective rule order preserved.

A **host-side networking component** enforces policy for a sandbox network attachment.

An **endpoint kind** defines how traffic is classified, such as `ip`, `http`, or `https`.

An **endpoint instance** is one named endpoint declaration.

A **family** is the rule-evaluation family derived from an endpoint kind. Initial families are `ip` and `http`.

A **credential declaration** describes how a credential may be selected and injected after policy allows a request. It does not contain secret values.

A **credential kind** defines required secret slots and injection behavior, such as `basic_auth`, `bearer_token`, or `openai_codex_oauth`.

A **network secret slot** is a derived launch-time secret name required by policy declarations. Slots are not serialized into policy JSON.

An **explicit allow** is an `allow` verdict returned by a matching rule. Default allow is not explicit allow.

An **owned L7 request** is a request that the networking component can classify and answer without creating upstream-visible effects first.

## Rust API Shape

Policy can be built directly:

```rust
let policy = NetworkPolicy::builder()
    .default_deny()
    .endpoint("chatgpt", |e| e.https().host("chatgpt.com"))
    .credential("codex", |c| c.openai_codex_oauth().endpoint("chatgpt"))
    .rule("allow-chatgpt", |r| {
        r.endpoint("chatgpt")
            .credential("codex")
            .allow()
    })
    .build()?;

let machine = runtime
    .machine()
    .image("ubuntu")
    .network(|n| n.private().policy(policy))
    .create()
    .await?;
```

Canonical JSON can also be loaded into the same type:

```rust
let policy = NetworkPolicy::from_json_file("policy.json")?;
let policy = NetworkPolicy::from_json_str(source)?;
let policy = NetworkPolicy::from_json_slice(bytes)?;
```

Start uses one closure shape. Launch material can be supplied inline:

```rust
machine
    .start_with(|s| {
        s.network(|n| {
            n.secret("codex.oauth.access_token", access_token)
                .secret("codex.oauth.expires_at", expires_at)
                .oauth_refresh_hook(refresh_hook)
        })
    })
    .await?;
```

The same launch material can be prepared separately and applied through the same builder:

```rust
let network_launch = NetworkLaunch::new()
    .secret("codex.oauth.access_token", access_token)
    .secret("codex.oauth.expires_at", expires_at)
    .oauth_refresh_hook(refresh_hook);

machine
    .start_with(|s| {
        s.network(|n| n.apply(network_launch))
    })
    .await?;
```

`NetworkStartBuilder` supports `.secret(...)`, `.secret_bytes(...)`, `.oauth_refresh_hook(...)`, and `.apply(NetworkLaunch)`.

Policy changes use durable update helpers. They do not require callers to rebuild the entire network attachment just to change policy:

```rust
machine
    .update(MachineUpdate::new().set_network_policy(updated_policy))
    .await?;

machine
    .update(MachineUpdate::new().clear_network_policy())
    .await?;
```

`set_network_policy(policy)` preserves the existing network attachment kind and succeeds only when that attachment supports per-machine policy. Initial support is private policy-capable networking. `none()` and named/shared network modes reject per-machine policy until their ownership and merge semantics are designed.

Full network replacement remains available for changing the attachment itself.

## Canonical Policy Contract

Normalized policy JSON has this top-level shape:

```json
{
  "version": 1,
  "metadata": {},
  "settings": {
    "default_action": "allow",
    "audit": {
      "body_buffer_bytes": 1048576,
      "body_storage_bytes": 4096
    }
  },
  "endpoints": [],
  "credentials": [],
  "rules": [],
  "tailscale": [],
  "forwards": []
}
```

Rules:

- `version` is required and initially `1`.
- There is no `$schema` field in the runtime payload.
- Unknown fields are rejected.
- Defaults are explicit in normalized JSON.
- The policy is a single merged object, not a `documents[]` structure.
- `metadata` is a JSON object and defaults to `{}`.
- Networking components never make policy decisions from `metadata`.
- Every audit event includes `metadata` unchanged.
- Canonical JSON does not include source filenames, parser diagnostics, compiled CEL IDs, FFI handles, implementation indexes, or `policy_hash`.

Frontends may put source-specific data in `metadata`. `metadata` must not contain secrets.

### Identity And References

Policy object names use the identifier grammar accepted by the current policy implementation.

Endpoint names are unique across endpoints. Credential names are unique across credentials. Tailscale tunnel names are unique across tunnels. Forward names are unique across forwards.

Canonical references are plain strings. Rules reference endpoint, credential, and tunnel names directly:

```json
{
  "endpoints": ["chatgpt"],
  "credential": "codex",
  "tunnel": "worktail"
}
```

### Settings

`settings.default_action` is either `allow` or `deny`. If omitted by an authoring frontend, it defaults to `allow`. Normalized JSON emits the effective value.

Audit body settings are:

```json
{
  "audit": {
    "body_buffer_bytes": 1048576,
    "body_storage_bytes": 4096
  }
}
```

If `body_buffer_bytes < body_storage_bytes`, the policy is valid but produces a warning from the frontend or validator.

## Firewall Semantics

The policy is endpoint-first.

An `ip` endpoint describes L3/L4 traffic. An `http` endpoint describes transparent cleartext HTTP. An `https` endpoint describes HTTPS MITM. Rules are evaluated by endpoint family rather than by transport. This lets one HTTP-family rule cover both cleartext and TLS-backed HTTP while preserving the runtime behavior of each transport.

### Endpoints

Endpoints are stored in one `endpoints` array. Each endpoint has a `kind` and kind-specific semantic fields.

Canonical endpoint objects do not serialize derived registry facts such as family, transport, facet, capability, or default port. Networking components derive those facts from `kind`.

Initial endpoint kinds are:

- `ip`
- `http`
- `https`

An `ip` endpoint declares L3/L4 matching:

```json
{
  "name": "dns",
  "kind": "ip",
  "source_cidrs": ["0.0.0.0/0"],
  "destination_cidrs": ["1.1.1.1/32"],
  "protocol": "udp",
  "ports": [{ "start": 53, "end": 53 }]
}
```

`source_cidrs` and `destination_cidrs` contain CIDR strings. Either may be empty if the endpoint should not constrain that side.

`protocol` is one of `any`, `tcp`, or `udp`.

`ports` contains inclusive ranges. An empty list means any port.

IP endpoints have no hostnames, credentials, or CEL conditions.

An `http` endpoint declares transparent cleartext HTTP host matching:

```json
{
  "name": "metadata",
  "kind": "http",
  "hosts": ["metadata.example.internal"]
}
```

HTTP endpoints do not support credentials.

An `https` endpoint declares HTTPS MITM host matching and may be used with credentials:

```json
{
  "name": "chatgpt",
  "kind": "https",
  "hosts": ["chatgpt.com", "*.chatgpt.com"]
}
```

HTTPS no-SNI classification is allowed only for explicit raw-IP HTTPS endpoint bindings. No-SNI HTTPS without such a binding fails closed before upstream contact.

HTTP-family host matching uses these rules:

- names are normalized before matching;
- wildcard bindings match exactly one or more labels before the suffix;
- exact bindings take precedence over wildcard bindings;
- duplicate exact bindings are invalid;
- a request with SNI and Host mismatch fails closed where the transport can observe both values before upstream contact.

### Rules

Normalized rule example:

```json
{
  "name": "allow-chatgpt",
  "endpoints": ["chatgpt"],
  "credential": "codex",
  "condition": "http.method == 'POST'",
  "tunnel": null,
  "verdict": "allow",
  "priority": 0,
  "disabled": false,
  "reason": "allow Codex API"
}
```

Rules are evaluated by:

1. higher `priority` first;
2. JSON array order as tie-breaker.

There is no implementation-only `order` field.

Disabled rules are preserved and skipped.

Rule `name` is optional.

All rule endpoint references must belong to the same family. Conditions are valid only for HTTP-family rules. `rule.credential` is valid only for HTTP-family rules and must be compatible with the directly referenced endpoint set.

### CEL Conditions

CEL condition source strings live in canonical JSON. `libvm` should validate CEL syntax at build/update time when possible. Networking components must validate before enforcement.

HTTP condition variables:

- `http.method`
- `http.host`
- `http.path`
- `http.query`
- `http.headers`

HTTP request and response bodies are not available to CEL.

CEL parse errors, type errors, and unavailable variables are load errors when validation is performed. Runtime condition evaluation errors fail closed and stop evaluation with a condition-error outcome.

### Evaluation Model

The firewall evaluation model is:

1. Load and validate canonical policy.
2. Build endpoint, credential, rule, tunnel, and forward indexes internally.
3. Evaluate L3/L4 context against IP rules.
4. IP deny is terminal.
5. IP allow may permit L7 classification when possible.
6. L7-capable components classify without upstream-visible effects.
7. Match HTTP-family endpoints by normalized host.
8. Select endpoint-bound credentials before rule evaluation.
9. Evaluate family-compatible rules by priority and array order.
10. Inject credentials only after explicit allow.
11. Apply Tailscale tunnel only after explicit allow.
12. Emit audit event.

Default allow does not inject credentials and does not select tunnels.

Runtime CEL errors fail closed.

### L7 Punch-Through

A deny-default policy may still permit a transparent proxy or MITM component to classify traffic without creating upstream-visible effects. Packet-filter-only components cannot do this.

Invalid configured L7 handling fails closed. Unknown hosts use the default action and never receive credentials.

### HTTP-Family Proxy Behavior

HTTP-family components may return synthetic responses for denials and runtime policy failures.

Request header handling:

- credentials are injected only after explicit allow;
- hop-by-hop headers are sanitized before upstream forwarding;
- credential material is removed from audit records;
- policy denial happens before upstream-visible effects where possible.

Response header handling:

- hop-by-hop headers are sanitized;
- `Alt-Svc` is stripped when HTTP/3 is unsupported;
- response bodies are never matched by CEL.

WebSocket upgrades are policy-checked as ordinary HTTP requests. After a successful `101 Switching Protocols`, frames are opaque.

`CONNECT` is treated as an HTTP method. QUIC and HTTP/3 inspection are out of scope.

## Credentials And Network Secrets

Credential declarations describe injection behavior. They never contain secret values or secret reference names.

Example:

```json
{
  "name": "codex",
  "kind": "openai_codex_oauth",
  "endpoint": "chatgpt"
}
```

Credential declarations may include kind-specific non-secret fields such as username, header name, prefix, idempotency behavior, or condition source.

Credential selection and injection use these rules:

- credentials are endpoint-bound;
- credentials may only reference HTTPS endpoints;
- credential conditions are evaluated before rule evaluation;
- runtime credential condition errors fail closed;
- multiple matching credentials for one request are ambiguous and fail closed;
- selected credentials are injected only after explicit allow;
- `rule.credential` is a predicate over selected credential identity, not the injection trigger.

Initial credential kinds:

| Kind | Required slots | Optional slots | Behavior |
| ---- | -------------- | -------------- | -------- |
| `basic_auth` | `password` | | Adds HTTP Basic auth using declaration username plus secret password. |
| `bearer_token` | `token` | | Adds bearer token authorization or a kind-specific header. |
| `header_token` | `token` | | Adds a configured header with optional prefix. |
| `github_oauth` | `oauth.access_token`, `oauth.expires_at` | `oauth.account_id` | Adds GitHub OAuth access material. |
| `openai_codex_oauth` | `oauth.access_token`, `oauth.expires_at` | `oauth.account_id` | Adds OpenAI Codex OAuth access material. |
| `aws_credential` | `access_key_id`, `secret_access_key` | `session_token`, `profile` | Signs supported AWS requests. |

OAuth refresh tokens are not network secret slots and are never passed to networking components.

Required and optional network secret slots are derived from policy declarations. `libvm` computes allowed slots from the persisted policy before launch.

`libvm` rejects:

- missing required slots;
- unknown supplied slots;
- empty supplied values.

`libvm` does not parse OAuth timestamps, inspect token contents, or validate credential-specific formats. CLI/app code may do so for user feedback. Networking components must validate formats before enforcement.

Secret values are passed to networking components as base64 environment variables:

```sh
SILO_NET_SECRET_CODEX_OAUTH_ACCESS_TOKEN=<base64>
SILO_NET_SECRET_CODEX_OAUTH_EXPIRES_AT=<base64>
SILO_NET_SECRET_CODEX_OAUTH_ACCOUNT_ID=<base64>
```

Values are base64 encoded unconditionally. The `libvm` API should support byte secrets internally and string helpers ergonomically.

Logs may mention slot names and status, never values.

## OAuth Refresh Hook

OAuth refresh tokens are never passed to networking components.

OAuth credentials supply access material through network secret slots. Durable refresh material remains behind the caller, CLI, keychain, or secret store.

If refresh is needed, the networking component invokes one network-level refresh hook.

Hook config is passed as base64 JSON in:

```sh
SILO_NET_OAUTH_REFRESH_HOOK=<base64-json>
```

Hook authorization material is passed separately:

```sh
SILO_NET_OAUTH_REFRESH_AUTH=<base64>
```

If hook config is set, hook auth is required.

Decoded hook config:

```json
{
  "version": 1,
  "command": "/usr/local/bin/secret-helper",
  "args": ["refresh-oauth"],
  "timeout_ms": 10000,
  "refresh_skew_seconds": 300
}
```

`command` must be absolute. The networking component executes it directly with `args`. There is no shell execution, PATH lookup, or command string parsing.

The hook subprocess receives a sanitized environment containing `SILO_NET_OAUTH_REFRESH_AUTH` and a minimal safe baseline. It does not receive `SILO_NET_SECRET_...` values.

Hook IO uses LSP-style framing:

```text
Content-Length: N\r\n
\r\n
<json>
```

Each refresh attempt starts one process, writes one framed request to stdin, reads one framed response from stdout, and waits for process exit.

Request:

```json
{
  "version": 1,
  "operation": "oauth_refresh",
  "credential": {
    "name": "codex",
    "kind": "openai_codex_oauth",
    "endpoint": "chatgpt"
  },
  "reason": "expires_soon",
  "expires_at": "2026-07-03T12:34:56Z"
}
```

Success response:

```json
{
  "version": 1,
  "status": "ok",
  "oauth": {
    "access_token": "new-access-token",
    "expires_at": "2026-07-03T13:34:56Z",
    "account_id": "optional-account-id"
  }
}
```

Error response:

```json
{
  "version": 1,
  "status": "error",
  "error": {
    "code": "unauthorized",
    "message": "refresh token is not available for credential",
    "retryable": false
  }
}
```

Initial error codes:

- `unauthorized`
- `not_found`
- `provider_unavailable`
- `provider_rejected`
- `rate_limited`
- `invalid_request`
- `internal_error`

Failure semantics:

- exit `0` plus `status: "ok"` succeeds;
- exit `0` plus `status: "error"` is a domain failure;
- non-zero exit, timeout, malformed framing, invalid JSON, missing fields, or schema failure is execution failure;
- non-zero exit ignores stdout even if a response exists;
- missing `retryable` defaults to false.

Hook stdout is never logged raw. Hook stderr may be logged only as service-log diagnostic text, never as policy audit.

Refresh lifecycle:

- refresh is scheduled proactively at `expires_at - refresh_skew_seconds`;
- default skew is 300 seconds;
- default timeout is 10 seconds;
- while refresh is in progress and the current token is valid, requests continue using the current token;
- if the token is expired, requests needing that credential wait up to the hook timeout;
- if refresh fails after expiry, requests fail closed;
- if no hook is configured, unexpired OAuth access tokens may be used, but expired credentials fail closed.

Refresh attempts and results are service logs only. A request audit event may record an outcome such as `credential_expired` or `credential_refresh_failed`.

## Tailscale

Tailscale declarations live in canonical policy but contain no auth keys, OAuth client secrets, refresh material, or state files.

Example:

```json
{
  "name": "worktail",
  "tags": ["tag:dev"]
}
```

Required Tailscale secret slots are derived from tunnel declarations and passed through `SILO_NET_SECRET_...`.

Outbound Tailscale routing requires explicit allow with a tunnel reference. Initial routing is TCP-only. UDP through a selected tunnel fails closed until supported. Tunnel failure does not fall back to direct routing.

## Inbound Forwards

Inbound forwards are exposure declarations, not outbound firewall rules.

Forward declarations live in `forwards`. Initial forwards are raw TCP byte proxies.

Host forwards bind localhost by default. Tailscale forwards expose through a configured tailnet identity. Target selectors may resolve by name, ID, or label according to the component's runtime inventory.

Forward audit records are independent from outbound endpoint/rule/default-action decisions.

## Audit And Observability

Audit is observability, not policy action.

Every audit event includes the top-level policy `metadata` object unchanged.

`policy_hash` is not required by the canonical contract. Frontends that want source hashes may put them in `metadata`.

The common audit envelope is:

```json
{
  "version": 1,
  "timestamp": "2026-07-03T12:34:56.789Z",
  "phase": "decision",
  "family": "http",
  "metadata": {}
}
```

Audit records must be redacted. They must not include secret values, refresh tokens, raw Authorization headers, credential material, or hook stdout.

Policy-load warnings are not audit events. OAuth refresh lifecycle events are not audit events. A request audit event may record outcomes such as `credential_expired` or `credential_refresh_failed` if those outcomes determine the request.

Representative audit event shapes are included in Appendix A.

## Tradeoffs

### JSON File Instead Of Environment Or Stdin

Policies can be large enough that environment variables are a poor fit. A generated runtime file is debuggable, matches the existing process-launch shape, and avoids inventing a streaming startup protocol. The file is still not an authored source file; `libvm` owns writing it.

### No Policy Hash In The Contract

A hash is useful only when the hashing input is clear. Different authoring frontends may care about different identities: source bytes, normalized JSON, CLI command input, or another provenance value. Instead of picking one canonical hash, the policy has an opaque top-level `metadata` object that is copied into audit events.

### No Secret References In Policy

Putting secret reference names in policy would make the policy a partial secret-resolution document. That would couple networking components to the caller's secret store. Instead, credentials imply required slots by credential kind and name, and launch material supplies values for those slots.

### No Partial Policy Patches

Rule order is semantic, references cross policy sections, and required secret slots are derived from the whole policy. Full replacement keeps validation understandable. CLI commands may still offer ergonomic edits by loading, modifying, validating, and replacing the full policy.

## Security Considerations

- Secret values never appear in policy JSON.
- Secret values are not passed into the VM.
- OAuth refresh tokens are never passed to networking components.
- Credential injection occurs only after explicit allow.
- Tunnel routing occurs only after explicit allow.
- Runtime evaluation, credential, and refresh failures fail closed.
- Hook stdout is never logged raw because successful responses contain access tokens.
- Audit records are redacted and must not become a secret sink.

## Consequences

- Host-side networking components have a stable JSON contract.
- Authoring interfaces can evolve independently from enforcement semantics.
- Secret stores and keychains stay outside networking components.
- `libvm` becomes the policy assembly and launch boundary.
- Existing source-specific policy references move out of `libvm`.
- Networking components consume only `--policy-file` canonical JSON.

## What This Does Not Decide

This ADR does not define:

- source syntax or source diagnostics;
- named policy search paths or CLI policy discovery;
- persisted secret values in `libvm`;
- refresh tokens in networking components;
- hot policy update for running machines;
- partial policy patch semantics;
- dynamic endpoint, credential, or tunnel plugins;
- guest-visible credential environment variables;
- HTTP request or response body matching in CEL;
- WebSocket frame policy after upgrade;
- QUIC or HTTP/3 inspection;
- human-in-the-loop verdicts.

## Appendix A: Audit Event Examples

These examples are representative shapes, not a complete schema.

### IP Decision

```json
{
  "version": 1,
  "timestamp": "2026-07-03T12:34:56.789Z",
  "phase": "decision",
  "family": "ip",
  "metadata": {},
  "flow": {
    "source_ip": "100.64.0.10",
    "destination_ip": "1.1.1.1",
    "protocol": "udp",
    "destination_port": 53
  },
  "endpoint": "dns",
  "rule": "allow-dns",
  "verdict": "allow",
  "defaulted": false
}
```

### HTTP Decision

```json
{
  "version": 1,
  "timestamp": "2026-07-03T12:34:56.789Z",
  "phase": "decision",
  "family": "http",
  "metadata": {},
  "request": {
    "method": "POST",
    "host": "chatgpt.com",
    "path": "/backend-api/conversation"
  },
  "endpoint": "chatgpt",
  "credential": "codex",
  "rule": "allow-chatgpt",
  "verdict": "allow",
  "defaulted": false
}
```

### Credential Failure

```json
{
  "version": 1,
  "timestamp": "2026-07-03T12:34:56.789Z",
  "phase": "decision",
  "family": "http",
  "metadata": {},
  "request": {
    "method": "POST",
    "host": "chatgpt.com",
    "path": "/backend-api/conversation"
  },
  "endpoint": "chatgpt",
  "credential": "codex",
  "verdict": "deny",
  "reason": "credential_expired"
}
```

### Forward Decision

```json
{
  "version": 1,
  "timestamp": "2026-07-03T12:34:56.789Z",
  "phase": "accepted",
  "family": "forward",
  "metadata": {},
  "forward": "ssh",
  "kind": "host",
  "listen": "127.0.0.1:2222",
  "target": "name:web",
  "target_port": 22
}
```
