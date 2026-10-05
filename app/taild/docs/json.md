# Lobby JSON

`--json` produces exactly one UTF-8 JSON object on stdout. Progress, human
messages and errors use stderr. Shell, exec and logs are streaming byte commands
and reject lobby `--json`; exec arguments after `--` remain literal guest arguments.

Success: `{"ok":true,"data":...}`. Failure:
`{"ok":false,"error":{"code":"conflict","message":"...","operation":"op_..."}}`.
`operation` exists when an admitted operation fails. That response also includes
its operation record in `data`; validation/admission failures have no operation.
No host paths, native diagnostics, credential values, raw specs or environment
contents are projected into VM/operation queries.

## Data shapes

| Command | `data` |
| --- | --- |
| `ls` | Array of VM projections, empty array when no visible VMs |
| `show VM` | One VM projection |
| create/start/stop/restart/rm/set | One terminal operation record |
| `ops`, `ops show ID` | Array of own operation records (one for show) |
| `whoami` | `{peer, capability, explanation?}` |
| `version` | `{taild, sdk, runtime, tailscale}` strings |
| `help` | `{help}` string |
| `template` / `policy` commands | Array of document records (one for show/create/edit/rm/validate); ls includes both tiers |

VM projections have `id`, `name`, `owner`, `state`, `node`, `address`, `cpus`,
`memory`, `disk`, `created`, `image`, and `labels`. Operation history is queried
through `ops`. Labels contain caller labels only; reserved ownership labels are projected
as validated fields. Image is empty for local-disk or unvalidated legacy sources.
Optional `template`, `policy`, and `guest_tcp_ports` project immutable provenance
and guest TCP discovery hints, never host publication authority or inbound ACLs.
`default_user` is the default guest shell/exec account: `root` when no account was
provisioned, otherwise the recorded account name. Optional `guest_user` contains
that provisioned account's `name`, `uid`, `gid`, and guest `home` path. An absent
`guest_user` does not synthesize a root provisioning record. Explicit session
`-u` overrides `default_user`.

Document records contain `kind`, `name`, `tier` (`yours` or `operator`), and `owner`
only for principal-owned files. Show/create/edit/validate include canonical `content`;
template records include typed `template` fields; policies include `secrets`
(`slots` and `requirements`, names/projections/alternatives only). Lists omit content,
remove returns identity only, and validation has empty name/tier because nothing is
stored. Another principal's documents are invisible (3). Operator-only writes are
forbidden (4), duplicate creates conflict (5), invalid stdin/documents fail (2),
unsafe/unreadable stored documents fail (9).
Resource sizes are integer bytes. Times are UTC
RFC 3339 strings with optional fractional seconds. `node_state` is `none`,
`pending approval`, `enrolled`, `connecting`, `disconnected`, `stopped`, `expired`,
`enrollment failed`, `status unavailable`, or `state unreadable`. `node_id` is the stable
Tailscale node ID, not its numeric peer ID or admin endpoint device ID.
`addresses` and `key_expiry` come from netd observations. `key_expiry` is an RFC3339
timestamp, `never` for observed non-expiring keys, or `unknown` when unavailable.
`key_expiry_observed_at` records when expiry was observed, and
`key_expiry_last_known: true` marks historical values. These do not prove connectivity.
Stopped VMs retain their configured `node` name and report `node_state: stopped`.
`owner_login` is a display-only human login; `owner` remains the authoritative principal.
Authorized owners see the current `approval_url`, never tokens. `show` is read-only;
netd handles authentication without a VM restart. `tags` contains requested tags,
independently of the creating principal who owns the VM in taild.
Ownership is one verified `user:<numeric-id>` or
`tag:<name>`; other owners and instances are invisible (exit 3).

Machine and rootfs creation, modification, start and update times, and image
creation, update and last-use times are stored by libvm as Unix seconds. The
Go native bridge converts them to signed Unix milliseconds using checked
multiplication, then the Go SDK decodes them with `time.UnixMilli`. Out-of-range
stored seconds return a native error rather than a wrapped or saturated time.
Inventory isolates per-machine conversion failures: the entry retains its
indexed ID/name with absent data and a structured configuration issue; healthy
neighbors remain readable and corrupt names remain reserved. Global database
failures still fail inventory, and inspecting the affected machine still errors.
Absent optional start/last-use timestamps remain absent. Provisioning report
start/finish timestamps already contain milliseconds and retain their subsecond
precision. No stored timestamps are rewritten. Human views use relative creation
ages in lists and absolute UTC creation dates in show; JSON retains timestamps,
integer-byte sizes and address fields.

Operations contain `id`, `kind`, `vm`, `principal`, `state`, `started`, `progress`,
optional `finished`, optional `error` (`code`, `message`). `vm` is the requested
exact name during create, otherwise the stable VM ID. Kinds are create/start/
stop/restart/remove/set. States are queued/running/succeeded/failed. Progress
retains at most 128 lines of at most 1024 bytes. IDs use canonical uppercase
Crockford ULID encoding: a 48-bit millisecond timestamp plus 80 crypto-random bits.
Finished operations expire after 24 hours; all operations disappear on daemon
restart. Querying a failed operation still succeeds as a query (exit 0).
Optional `completion` captures immutable VM ID/name/image/default user, running
state, node state, verified DNS name and current approval URL at job completion.
Pre-creation consent links appear in pending `ops show ID` and its progress array.

`peer` has principals (array), node_id, node_name, login (optional display-only),
observed_at and permissions. Permissions has actions (array), limits
(`vms`, `cpus`, `memory`, `disk`, nonnegative integers), optional reason. Capability
limits are additive; enforcement additionally constrains them by operator ceilings.

## VM and operation JSON Schema (2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$defs": {
    "error": {
      "type": "object",
      "required": ["code", "message"],
      "properties": {
        "code": {"type": "string"},
        "message": {"type": "string"},
        "operation": {"type": "string", "pattern": "^op_[0-7][0-9A-HJKMNP-TV-Z]{25}$"}
      },
      "additionalProperties": false
    },
    "vm": {
      "type": "object",
      "required": ["id", "name", "owner", "state", "node", "address", "cpus", "memory", "disk", "created", "image", "labels"],
      "properties": {
        "id": {"type": "string"},
        "name": {"type": "string", "pattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"},
        "owner": {"type": "string"},
        "owner_login": {"type": "string"},
        "state": {"enum": ["stopped", "starting", "running", "stopping", "error", "unknown"]},
        "node": {"type": "string"},
        "node_state": {"enum": ["none", "pending approval", "enrolled", "state unreadable", "connecting", "disconnected", "stopped", "expired", "enrollment failed", "status unavailable"]},
        "tags": {"type": "array", "items": {"type": "string"}},
        "node_id": {"type": "string"},
        "node_diagnostics": {"type": "array", "items": {"type": "string"}},
        "addresses": {"type": "array", "items": {"type": "string"}},
        "key_expiry": {"type": "string"},
        "key_expiry_observed_at": {"type": "string", "format": "date-time"},
        "key_expiry_last_known": {"type": "boolean"},
        "approval_url": {"type": "string", "format": "uri"},
        "address": {"type": "string"},
        "cpus": {"type": "integer", "minimum": 0},
        "memory": {"type": "integer", "minimum": 0},
        "disk": {"type": "integer", "minimum": 0},
        "created": {"type": "string", "format": "date-time"},
        "image": {"type": "string"},
        "labels": {"type": "object", "additionalProperties": {"type": "string"}},
        "default_user": {"type": "string"},
        "guest_user": {
          "type": "object",
          "required": ["name", "uid", "gid", "home"],
          "properties": {
            "name": {"type": "string"},
            "uid": {"type": "integer", "minimum": 0, "maximum": 4294967295},
            "gid": {"type": "integer", "minimum": 0, "maximum": 4294967295},
            "home": {"type": "string"}
          },
          "additionalProperties": false
        },
        "template": {"type": "string"},
        "policy": {"type": "string"},
        "guest_tcp_ports": {"type": "array", "uniqueItems": true, "items": {"type": "integer", "minimum": 1, "maximum": 65535}}
      },
      "additionalProperties": false
    },
    "operation": {
      "type": "object",
      "required": ["id", "kind", "vm", "principal", "state", "started", "progress"],
      "properties": {
        "id": {"type": "string", "pattern": "^op_[0-7][0-9A-HJKMNP-TV-Z]{25}$"},
        "kind": {"enum": ["create", "start", "stop", "restart", "remove", "set"]},
        "completion": {
          "type": "object",
          "required": ["vm_id", "name", "image", "user", "running", "node_state"],
          "properties": {
            "vm_id": {"type": "string"}, "name": {"type": "string"},
            "image": {"type": "string"}, "user": {"type": "string"},
            "running": {"type": "boolean"}, "node_state": {"type": "string"},
            "node": {"type": "string"}, "approval_url": {"type": "string", "format": "uri"}
          },
          "additionalProperties": false
        },
        "vm": {"type": "string"},
        "principal": {"type": "string"},
        "state": {"enum": ["queued", "running", "succeeded", "failed"]},
        "started": {"type": "string", "format": "date-time"},
        "finished": {"type": "string", "format": "date-time"},
        "progress": {"type": "array", "maxItems": 128, "items": {"type": "string", "maxLength": 1024}},
        "error": {"$ref": "#/$defs/error"}
      },
      "additionalProperties": false
    }
  },
  "type": "object",
  "required": ["ok"],
  "properties": {
    "ok": {"type": "boolean"},
    "data": {},
    "error": {"$ref": "#/$defs/error"}
  },
  "additionalProperties": false
}
```

Exit codes: 0 success, 2 usage/validation, 3 invisible/missing VM or operation,
4 forbidden, 5 state/conflict, 6 limit, 7 failed VM/image operation, 8 enrollment
(pending/expired/failed approval), 9 unavailable, 255 lost transport/execution. Exec/shell pass guest
exit codes through; signal exits use `128 + signal` (capped at 255), missing guest
program uses 127, other guest launch failures use 126.
