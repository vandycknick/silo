# 7. HCL Network Policy Frontend

Date: 2026-07-04

## Status

Proposed

## The Problem

ADR 0006 defines the firewall engine contract as normalized JSON. That is the right shape for enforcement, persistence, and component boundaries. It is not always the right shape for humans.

A useful microVM network policy needs to be reviewed independently from the code that launches the VM. Someone should be able to ask: which endpoints are allowed, which credentials may be used, which tunnel is selected, what is denied by default, and what gets audited?

Plain JSON can answer those questions, but it is noisy. SDK builders are worse as an audit artifact because the policy is mixed into application code. Both are workable machine interfaces. Neither is the best human policy language.

We need a policy language that is pleasant to write, easy to review, easy to diff, and portable across multiple VMs.

## Why A Policy Language Exists

HCL gives us a reviewable policy document.

It has comments, named blocks, concise references, and stable formatting. It can be checked into a repository, reused across multiple machines, diffed in code review, and audited without reading Rust code or generated JSON.

The goal is not to make HCL another enforcement contract. The goal is to make it a frontend for producing the canonical `NetworkPolicy` from ADR 0006.

That distinction is important. The HCL document is where humans work. The canonical policy is what `libvm` persists and what networking components enforce.

## Determination

HCL is a human-facing authoring frontend that lowers to canonical `NetworkPolicy`.

The Rust policy API exposes direct HCL ingestion:

```rust
let policy = NetworkPolicy::from_hcl_str(hcl_source)?;
let policy = NetworkPolicy::from_hcl_file(path)?;
```

HCL parsing can produce multiple diagnostics. Load failures return structured diagnostics rather than a single string:

```rust
pub struct PolicyLoadError {
    pub diagnostics: Vec<PolicyDiagnostic>,
}
```

The HCL frontend owns:

- HCL syntax;
- HCL diagnostics;
- HCL reference resolution;
- HCL-to-canonical lowering;
- HCL-specific metadata injection.

ADR 0006 owns:

- canonical JSON/value shape;
- firewall semantics;
- credential and secret slot model;
- audit behavior;
- `libvm` and host-side networking component boundaries.

Host-side networking components never consume HCL.

## User Experience

A user can author this policy:

```hcl
settings {
  default_action = "deny"
}

endpoint "https" "chatgpt" {
  hosts = ["chatgpt.com", "*.chatgpt.com"]
}

credential "openai_codex_oauth" "codex" {
  endpoint = https.chatgpt
}

rule "allow_chatgpt" {
  endpoints = [https.chatgpt]
  credential = openai_codex_oauth.codex
  condition = "http.method == 'POST'"
  verdict = "allow"
  priority = 10
  reason = "Codex API"
}
```

That document answers the review questions directly. The default is deny. There is one HTTPS endpoint. There is one OAuth credential bound to that endpoint. There is one allow rule, and it only applies to POST requests.

The same policy can be loaded and attached to a machine:

```rust
let policy = NetworkPolicy::from_hcl_file("network-policy.hcl")?;

let machine = runtime
    .machine()
    .image("ubuntu")
    .network(|n| n.private().policy(policy))
    .create()
    .await?;
```

Secrets are not part of the HCL document. They are supplied as launch-time network material:

```rust
machine
    .start_with(|s| {
        s.network(|n| {
            n.secret("codex.oauth.access_token", access_token)
                .secret("codex.oauth.expires_at", expires_at)
        })
    })
    .await?;
```

This separation keeps the policy reviewable without making it a secret container. The document says which credential may be used. The launch path supplies the value for the derived secret slot.

## Lowering Model

The HCL frontend lowers a complete HCL policy input into one canonical `NetworkPolicy`.

Current top-level HCL blocks:

```hcl
settings { ... }

endpoint "https" "chatgpt" { ... }

credential "openai_codex_oauth" "codex" { ... }

tailscale "worktail" { ... }

forward "host" "ssh" { ... }

rule "allow_chatgpt" { ... }
```

The lowered canonical policy has the same shape as any other authoring path:

```json
{
  "version": 1,
  "metadata": {
    "hcl": {
      "source_hash": "sha256:..."
    }
  },
  "settings": {
    "default_action": "deny",
    "audit": {
      "body_buffer_bytes": 1048576,
      "body_storage_bytes": 4096
    }
  },
  "endpoints": [
    {
      "name": "chatgpt",
      "kind": "https",
      "hosts": ["chatgpt.com", "*.chatgpt.com"]
    }
  ],
  "credentials": [
    {
      "name": "codex",
      "kind": "openai_codex_oauth",
      "endpoint": "chatgpt"
    }
  ],
  "rules": [
    {
      "name": "allow_chatgpt",
      "endpoints": ["chatgpt"],
      "credential": "codex",
      "condition": "http.method == 'POST'",
      "tunnel": null,
      "verdict": "allow",
      "priority": 10,
      "disabled": false,
      "reason": "Codex API"
    }
  ],
  "tailscale": [],
  "forwards": []
}
```

HCL source layout, filenames, parser document IDs, and diagnostics do not appear in canonical policy except where intentionally represented as opaque `metadata`.

Omitted defaults are filled by canonical normalization. Rule order in HCL source becomes JSON array order and is the tie-breaker after priority.

## Metadata

The HCL frontend may populate canonical top-level `metadata`.

Recommended HCL metadata:

```json
{
  "hcl": {
    "source_hash": "sha256:..."
  }
}
```

The HCL frontend must not place secrets in metadata.

## References

HCL may use qualified references for readability:

```hcl
endpoint = https.chatgpt
credential = openai_codex_oauth.codex
tunnel = tailscale.worktail
```

Lowering resolves these to canonical plain names:

```json
{
  "endpoints": ["chatgpt"],
  "credential": "codex",
  "tunnel": "worktail"
}
```

If a qualified HCL reference cannot be resolved unambiguously, the HCL frontend reports a load error.

## HCL Schema

### Settings

HCL:

```hcl
settings {
  default_action = "deny"

  audit {
    body_buffer_bytes = 1048576
    body_storage_bytes = 4096
  }
}
```

Canonical lowering:

```json
{
  "settings": {
    "default_action": "deny",
    "audit": {
      "body_buffer_bytes": 1048576,
      "body_storage_bytes": 4096
    }
  }
}
```

### Endpoints

HCL IP endpoint:

```hcl
endpoint "ip" "dns" {
  destination_cidrs = ["1.1.1.1/32"]
  protocol = "udp"
  ports = [53]
}
```

Canonical lowering:

```json
{
  "name": "dns",
  "kind": "ip",
  "source_cidrs": [],
  "destination_cidrs": ["1.1.1.1/32"],
  "protocol": "udp",
  "ports": [{ "start": 53, "end": 53 }]
}
```

HCL HTTPS endpoint:

```hcl
endpoint "https" "chatgpt" {
  hosts = ["chatgpt.com", "*.chatgpt.com"]
}
```

Canonical lowering:

```json
{
  "name": "chatgpt",
  "kind": "https",
  "hosts": ["chatgpt.com", "*.chatgpt.com"]
}
```

### Credentials

HCL:

```hcl
credential "openai_codex_oauth" "codex" {
  endpoint = https.chatgpt
}
```

Canonical lowering:

```json
{
  "name": "codex",
  "kind": "openai_codex_oauth",
  "endpoint": "chatgpt"
}
```

Secret values and secret reference names are not part of HCL policy. The CLI/app layer resolves secrets separately and supplies launch-time network secret slots to `libvm`.

### Rules

HCL:

```hcl
rule "allow_chatgpt" {
  endpoints = [https.chatgpt]
  credential = openai_codex_oauth.codex
  condition = "http.method == 'POST'"
  verdict = "allow"
  priority = 10
  reason = "Codex API"
}
```

Canonical lowering:

```json
{
  "name": "allow_chatgpt",
  "endpoints": ["chatgpt"],
  "credential": "codex",
  "condition": "http.method == 'POST'",
  "tunnel": null,
  "verdict": "allow",
  "priority": 10,
  "disabled": false,
  "reason": "Codex API"
}
```

### CEL Conditions

HCL condition strings lower unchanged into canonical policy.

The HCL frontend should validate CEL syntax and available variables when possible. `libvm` should validate CEL syntax at build/update time when possible. Host-side networking components must still validate CEL before enforcement.

CEL runtime behavior is defined by ADR 0006.

### Tailscale

HCL:

```hcl
tailscale "worktail" {
  tags = ["tag:dev"]
}
```

Canonical lowering:

```json
{
  "name": "worktail",
  "tags": ["tag:dev"]
}
```

Tailscale auth keys and OAuth secret material are not represented in HCL policy. Required launch-time secret slots are derived from the canonical Tailscale declaration.

### Forwards

HCL:

```hcl
forward "host" "ssh" {
  listen = "127.0.0.1:2222"
  target = "name:web"
  target_port = 22
}
```

Canonical lowering:

```json
{
  "name": "ssh",
  "kind": "host",
  "listen": "127.0.0.1:2222",
  "target": "name:web",
  "target_port": 22
}
```

Forward enforcement and audit semantics are defined by ADR 0006.

## Diagnostics

The HCL frontend reports load errors for:

- unknown top-level blocks;
- unknown attributes;
- duplicate names;
- invalid identifiers;
- invalid references;
- unsupported endpoint, credential, tunnel, or forward kinds;
- invalid field types;
- incompatible credential and endpoint kinds;
- incompatible rule families;
- CEL parse/type errors when validated by the frontend.

Diagnostics should include enough structure for callers to render useful messages:

```rust
pub struct PolicyDiagnostic {
    pub severity: PolicyDiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub source: Option<PolicyDiagnosticSource>,
}
```

Warnings are frontend/service diagnostics, not policy audit events.

Representative warnings:

- audit `body_buffer_bytes` less than `body_storage_bytes`;
- multiple unconditional credentials for one endpoint;
- duplicate credential condition strings.

## Invalid Examples

Duplicate endpoint name:

```hcl
endpoint "https" "api" {
  hosts = ["api.example.com"]
}

endpoint "http" "api" {
  hosts = ["api.example.com"]
}
```

Invalid credential endpoint:

```hcl
endpoint "ip" "api_ip" {
  destination_cidrs = ["203.0.113.10/32"]
}

credential "bearer_token" "api_token" {
  endpoint = ip.api_ip
}
```

Unknown rule reference:

```hcl
rule "bad" {
  endpoint = https.missing
  verdict = "allow"
}
```

Secret material in HCL is invalid:

```hcl
credential "bearer_token" "api_token" {
  endpoint = https.api
  token = "secret"
}
```

## Rust Policy Code Responsibilities

The Rust policy code should own:

- canonical `NetworkPolicy` model types;
- builder API;
- canonical JSON loading;
- direct HCL loading through `NetworkPolicy::from_hcl_str` and `NetworkPolicy::from_hcl_file`;
- normalization;
- validation;
- required and optional network secret slot derivation;
- HCL parser frontend;
- HCL-to-canonical lowering.

`libvm` uses or re-exports the canonical Rust API.

Host-side networking components read canonical JSON directly and do not depend on Rust parser handles or HCL snapshots.

## Consequences

- HCL remains pleasant to write.
- Runtime components stay frontend-agnostic.
- Canonical JSON files, SDK builders, and HCL all converge on one policy contract.
- Source-specific diagnostics and metadata stay in the frontend layer.
- Policies can be reused across multiple VMs without copying launch code.

## What This Does Not Decide

This ADR does not define:

- named policy lookup or CLI search paths;
- where policy files live on disk;
- secret store or keychain resolution;
- refresh hook execution;
- runtime enforcement;
- HCL includes/imports;
- hot policy update.
