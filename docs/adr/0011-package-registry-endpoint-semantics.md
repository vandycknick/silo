# 11. Package Registry Endpoint Semantics

Date: 2026-07-16

## Status

Draft

## The Problem

Package managers do not fetch a package in one request. They first fetch registry metadata, choose a version and artifact, and then download package bytes. npm, pip, uv, Poetry, and related clients use different metadata representations, cache behavior, and artifact URL formats.

Silo's firewall is endpoint based. A rule attached to an endpoint is expected to decide whether a concrete request to that endpoint is allowed. Applying the same rule while rewriting every version listed inside a metadata response introduces another, implicit rule-evaluation stage. That stage does not describe an artifact the workload has selected or requested.

This distinction matters for policy and audit correctness. A metadata request such as `GET /jquery-real` identifies a package name but not a selected version. Malware and release-age facts are version specific. If Silo evaluates every listed version, removes denied versions, and then audits the outer metadata request, the audit combines facts from two different layers:

- the request-level package has no version;
- candidate decisions have exact versions;
- the HTTP request can return `200` after candidates were removed;
- the rule and facts that removed candidates can be lost;
- the audit can therefore say `allow` with unknown identity even though package policy caused the installation to fail.

SafeChain demonstrates useful package-manager behavior, particularly suppressing newly released versions from registry metadata. Its interception model is not Silo's endpoint model, however, and cannot be ported one-to-one as firewall rule semantics.

Silo needs a registry endpoint contract that preserves the useful resolver behavior without evaluating firewall rules at metadata and artifact stages.

## Determination

The `registries` endpoint is a protocol-aware endpoint with two distinct request surfaces:

1. Metadata requests are allowed registry protocol operations. They never invoke registry CEL rules or `settings.default_action`. The endpoint may rewrite metadata using its configured package-age invariant.
2. Artifact requests are the only registry requests that invoke firewall rules. They must have an exact package identity before rule evaluation.

Minimum package age is an endpoint invariant rather than a CEL rule. One endpoint setting controls both resolver assistance and direct artifact enforcement:

- metadata omits artifacts known to be younger than the configured threshold;
- exact artifact requests known to be younger than the threshold are denied;
- unknown age is allowed;
- metadata with no eligible artifacts remains a successful, possibly empty response;
- CEL allow rules cannot override the age invariant.

Malware is evaluated only for exact artifact requests. Metadata is never filtered using malware facts.

Malformed or unsupported metadata, registry administrative requests, and requests that cannot be classified as metadata or an exact artifact pass through unchanged. An identifiable artifact remains subject to rules and the age invariant regardless of whether the client first fetched metadata.

## Endpoint Contract

The human-facing HCL endpoint is:

```hcl
endpoint "registries" "public" {
  registries         = ["npm", "pypi"]
  malware_feed       = "https://malware-list.aikido.dev"
  filter_package_age = 24
}
```

Fields:

| Field | Required | Meaning |
| ----- | -------- | ------- |
| `registries` | yes | Non-empty unique list containing `npm`, `pypi`, or both. |
| `malware_feed` | yes | HTTPS base URL for ecosystem malware and release documents. |
| `filter_package_age` | no | Positive integer minimum package age in hours. Omission disables age filtering. |

`filter_package_age` rejects zero, negative values, fractions, strings, and values that cannot be represented by the canonical integer type. An artifact is too young when its known age is strictly less than the configured number of hours. An artifact at exactly the threshold is eligible.

The field is named `malware_feed` for the endpoint's primary intelligence source. It identifies a feed base URL, not one JSON document. Silo derives these paths beneath the configured base:

```text
malware_predictions.json
malware_pypi.json
releases/npm.json
releases/pypi.json
```

For example, the base URL `https://feeds.example.test/silo` produces `https://feeds.example.test/silo/malware_predictions.json`.

The feed URL:

- must use HTTPS;
- must have a valid host and optional non-zero port;
- must not contain credentials, a query, or a fragment;
- may contain a base path;
- derives one TLS egress authority from its host and port;
- may redirect only within the same approved origin.

## Canonical Contract

The endpoint lowers to canonical policy JSON:

```json
{
  "kind": "registries",
  "name": "public",
  "family": "package",
  "transport": "tls-terminate",
  "tls": "terminate",
  "config": {
    "registries": ["npm", "pypi"],
    "malware_feed": "https://malware-list.aikido.dev",
    "filter_package_age": 24
  },
  "egress": [
    {
      "host": "malware-list.aikido.dev",
      "port": 443,
      "tls": true
    }
  ],
  "hosts": [
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "registry.npmjs.com",
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "pythonhosted.org"
  ]
}
```

When `filter_package_age` is omitted, canonical config omits the key. `malware_feed` replaces `intelligence_base_url`; the old field is not an alias and is rejected by the strict schema.

Registry hosts and intelligence egress are derived canonical data. A canonical document is invalid when either differs from the selected registries or feed base URL.

## Request Surfaces

"Artifact" includes npm tarballs, Python wheels, Python source distributions, and artifact metadata sidecars. It is broader than "tarball."

| Surface | npm examples | PyPI examples |
| ------- | ------------ | ------------- |
| Full metadata | `GET /lodash` | `GET /simple/requests/`, `GET /pypi/requests/json` |
| Exact metadata | `GET /lodash/4.17.21`, `GET /lodash/latest` | `GET /pypi/requests/2.31.0/json` |
| Artifact | `GET /lodash/-/lodash-4.17.21.tgz` | `GET /packages/.../requests-2.31.0.whl` |
| Artifact metadata | not normally separate | `GET /packages/.../requests-2.31.0.whl.metadata` |
| Administrative | `/-/ping`, `/-/v1/search`, publish APIs | non-package API paths |

Request behavior:

| Surface | CEL rules | Package-age metadata filtering | Artifact age invariant |
| ------- | --------- | ------------------------------ | ---------------------- |
| Full metadata | never | yes | no |
| Exact metadata | never | only when usable release data is present | no |
| Exact artifact | always | no | yes |
| Administrative or unknown | never | no | no |

Methods do not turn metadata into an artifact. Administrative, publish, `HEAD`, and unrecognized operations do not run package rules unless the URL itself identifies an exact artifact.

## Package Facts And Rule Scope

Registry rules run only after Silo identifies an exact artifact. Their package activation includes:

```text
package.ecosystem
package.operation = "download"
package.name
package.version
package.identity_known = true
package.age_known
package.age_hours
package.age_source
package.malware_data_available
package.malware
package.malware_reason
```

Rules attached to `registries.public` therefore never run with `operation = "resolve"` or `identity_known = false`.

Rule priority and declaration order remain the policy ordering defined by ADR 0006. If a CEL rule denies an artifact, that denial supplies the audit rule and reason. If policy otherwise allows the artifact but the endpoint age invariant denies it, the invariant supplies the denial reason. The invariant is non-bypassable by CEL allow rules.

The endpoint's default action applies to exact artifacts because they are the registry rule-evaluation surface. It does not apply to metadata or administrative registry operations.

## npm Request Flow

```text
GET /jquery-real
        |
        v
Fetch full npm packument
        |
        v
Apply filter_package_age
        |
        +-- remove young entries from time
        +-- remove young entries from versions
        +-- remove dist-tags that reference removed versions
        +-- recalculate latest when required
        |
        v
Return HTTP 200 metadata
        |
        v
npm selects an artifact
        |
        v
GET /jquery-real/-/jquery-real-X.Y.Z.tgz
        |
        v
Resolve exact package facts
        |
        v
Evaluate registry CEL rules
        |
        +-- policy deny --> HTTP 403
        |
        v
Apply endpoint age invariant
        |
        +-- known and too young --> HTTP 403
        +-- unknown age --> forward
        +-- old enough --> forward
```

### npm Full Metadata

The full npm packument normally contains `time`, `versions`, and `dist-tags`. When filtering is enabled, Silo:

1. requests full JSON when the client requested abbreviated install metadata;
2. calculates age from each version's `time` entry;
3. removes only versions known to be too young;
4. removes corresponding `time` entries;
5. removes every dist-tag that references a removed version;
6. restores `latest` to the most recently published eligible stable version, or the most recent eligible prerelease when no stable version remains;
7. removes response validators that no longer describe the transformed body.

`created` and `modified` timestamps are not package versions and are retained.

When no version is removed, Silo forwards the original body and validators unchanged. When all versions are removed, Silo returns `200` with empty eligible version data. The package manager is responsible for reporting that no version satisfies resolution.

For SafeChain parity, npm conditional request validators are forwarded upstream. An upstream `304 Not Modified` is passed through because it has no metadata body to transform. A client may therefore reuse metadata cached before the current endpoint configuration took effect. This is an accepted resolver-assistance limitation, not an enforcement bypass: every exact artifact request remains subject to CEL rules and the endpoint age invariant.

### npm Exact Metadata

`GET /package/version` and `GET /package/tag` return a single manifest rather than the full `time`, `versions`, and `dist-tags` envelope. Silo does not run CEL rules for that request. When the manifest does not provide sufficient release information for safe rewriting, it is forwarded unchanged. The later tarball request is still enforced using its exact package identity.

### npm Artifacts

An npm artifact is recognized from the registry host and `/<package>/-/<filename>.tgz` path. Scoped package names and prerelease versions are normalized without changing the version string.

The artifact request is the authoritative enforcement point. Direct downloads, frozen lockfiles, client caches, and exact manifests cannot bypass rules or the age invariant.

## PyPI Request Flow

```text
GET /simple/jquery-real/
        |
        v
Parse HTML or JSON project metadata
        |
        v
Apply filter_package_age
        |
        +-- remove links for known young releases
        |
        v
Return HTTP 200 metadata
        |
        v
pip selects a wheel or source distribution
        |
        v
GET /packages/.../jquery_real-X.Y.Z.whl
        |
        v
Resolve exact package facts
        |
        v
Evaluate registry CEL rules
        |
        +-- policy deny --> HTTP 403
        |
        v
Apply endpoint age invariant
        |
        +-- known and too young --> HTTP 403
        +-- unknown age --> forward
        +-- old enough --> forward
```

### PyPI Simple Metadata

Silo supports HTML and PEP 691 JSON simple-index responses. It extracts package versions from wheel and source-distribution filenames. Links with unknown identity or unknown age remain in the response. Links known to be too young are removed.

PyPI conditional request headers are removed when filtering is active so the upstream returns a body that can be rewritten. Response validators are removed only when the body changes.

### PyPI Project JSON

Project and release JSON may contain `releases`, `urls`, `versions`, `info`, and `vulnerabilities`. Filtering removes known young release entries and artifact URLs. If fields describe a removed latest release, Silo must not relabel release-specific data as another version. It either reconstructs internally consistent data or removes stale release-specific fields.

Malformed JSON, unsupported media types, and unsupported shapes pass through unchanged.

### PyPI Artifacts

Wheels, source distributions, and PEP 658 metadata sidecars are artifact requests when their filenames provide an exact package name and version. Artifact URLs observed in metadata are indexed so later requests retain the normalized package identity and observed release time.

Direct artifact requests that were not previously observed use filename parsing and release-feed data. Unknown release age is allowed, but exact malware and policy facts remain enforceable when available.

## Intelligence And Age Sources

Feed state is cached per endpoint and ecosystem. Refreshes use the configured `malware_feed` base and retain the last successful snapshot when a later refresh fails.

Age source precedence is:

1. release time observed in registry metadata for the exact artifact;
2. ecosystem release-feed timestamp for the exact package and version;
3. unknown.

Future release timestamps produce age zero. Age uses complete elapsed hours so the integer fact and endpoint threshold agree.

`malware_data_available` is true only when a malware snapshot for the artifact ecosystem has loaded. Malware entries may identify one version or use `*` for every version of a package.

An unavailable feed does not turn unknown age or malware into a denial. Policy authors can still deny unavailable malware intelligence on exact artifact requests if they explicitly write such a rule.

## Audit Contract

There is one audit event per HTTP request. No `package_resolution` or candidate-outcome field is introduced.

Metadata audit records the registry operation, not a package-rule decision:

```json
{
  "package": {
    "ecosystem": "npm",
    "operation": "resolve",
    "name": "jquery-real",
    "identity_known": false
  },
  "verdict": "allow",
  "reason": "minimum_package_age_filtered"
}
```

The reason is omitted when metadata is unchanged. Candidate-only age and malware fields are omitted when no exact package identity exists.

Artifact audit is authoritative for package policy:

```json
{
  "policy": {
    "endpoint_kind": "registries",
    "endpoint_name": "public",
    "rule_name": "block-known-malware"
  },
  "package": {
    "ecosystem": "npm",
    "operation": "download",
    "name": "jquery-real",
    "version": "0.0.1-security",
    "identity_known": true,
    "age_known": true,
    "age_hours": 100,
    "malware_data_available": true,
    "malware": true
  },
  "verdict": "deny",
  "reason": "package identified as malware"
}
```

An endpoint age denial has an exact package and reason but no rule name because the invariant is endpoint configuration, not a hidden CEL rule.

## Failure Semantics

| Failure | Behavior |
| ------- | -------- |
| Metadata parse or unsupported shape | Forward original response. |
| Unsupported metadata content encoding | Forward original response. |
| npm metadata returns `304 Not Modified` | Forward the response unchanged; enforce the selected artifact later. |
| Feed refresh fails with cached state | Use last successful state. |
| Feed refresh fails without cached state | Facts remain unavailable; unknown age is allowed. |
| Artifact identity cannot be determined | Treat as unknown registry traffic and pass through. |
| Artifact policy condition fails | Deny exact artifact with `condition_error`. |
| Artifact is known too young | Deny exact artifact. |
| All metadata artifacts are filtered | Return successful empty metadata. |

## Security Properties

Metadata filtering is not the security boundary. Its purpose is to help package resolvers avoid selecting artifacts that the endpoint invariant will reject.

Artifact enforcement remains effective when:

- a client uses a lockfile;
- a client has cached metadata;
- a client requests exact version metadata;
- a client downloads an artifact URL directly;
- metadata parsing fails;
- metadata lacks release timestamps;
- metadata filtering is disabled.

Every allowed or denied artifact rule decision has an exact package identity. Audit records therefore describe the request that could introduce package bytes into the sandbox.

## Consequences

Positive consequences:

- registry rules have one evaluation stage;
- rule audits always describe exact artifacts;
- metadata filtering improves resolver behavior without becoming policy enforcement;
- minimum age has one endpoint-owned threshold;
- direct downloads cannot bypass minimum age;
- malformed metadata does not make registries unusable;
- npm and PyPI differences remain inside protocol adapters.

Tradeoffs:

- package-name rules deny the selected artifact rather than hiding the package from search or metadata;
- an all-young package can produce a package-manager "no matching version" error;
- unknown age is allowed;
- metadata allow events can precede an artifact deny event during one install;
- minimum-age denial is endpoint behavior and does not have a CEL rule name.

## Alternatives Considered

### Evaluate Every Rule For Metadata Candidates

Rejected because it creates a second policy stage, can prevent the authoritative artifact request from occurring, and cannot be represented truthfully in one request-level audit event.

### Add Candidate Outcomes To Audit

Rejected because a `package_resolution` structure would document the accidental second policy stage rather than remove it.

### Separate Metadata And Artifact Endpoints

Rejected for now because npm and PyPI use overlapping hosts. Splitting one registry declaration into multiple logical endpoints would require larger routing, configuration, and state-sharing changes without improving artifact enforcement.

### Keep Minimum Age As A CEL Rule

Rejected because the same numeric threshold would need to drive metadata rewriting before the artifact request. Annotating or introspecting rules for metadata use would reintroduce stage-specific rule semantics.

### External Filtering Proxy

Rejected because it adds another deployed component while Silo already terminates registry TLS and has the metadata needed to perform the resolver optimization.

## Relationship To Other ADRs

ADR 0006 remains authoritative for canonical network policy, rule ordering, default actions, CEL evaluation, and general audit behavior.

ADR 0007 remains authoritative for HCL as a frontend that lowers to canonical policy.

This ADR specializes both records for the `registries` endpoint kind.
