# Lobby JSON, phase 11

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

VM projections have `id`, `name`, `owner`, `state`, `node`, `address`, `cpus`,
`memory`, `disk`, `created`, `image`, `labels`, and optional `last_operation` on
show. Labels contain caller labels only; reserved ownership labels are projected
as validated fields. Image is empty for local-disk or unvalidated legacy sources.
Resource sizes are integer bytes. Times are UTC
RFC 3339 strings with optional fractional seconds. Node/address are empty until
VM enrollment is implemented. Ownership is one verified `user:<numeric-id>` or
`tag:<name>`; other owners and instances are invisible (exit 3).

Operations contain `id`, `kind`, `vm`, `principal`, `state`, `started`, `progress`,
optional `finished`, optional `error` (`code`, `message`). `vm` is the requested
exact name during create, otherwise the stable VM ID. Kinds are create/start/
stop/restart/remove/set. States are queued/running/succeeded/failed. Progress
retains at most 128 lines of at most 1024 bytes. IDs use canonical uppercase
Crockford ULID encoding: a 48-bit millisecond timestamp plus 80 crypto-random bits.
Finished operations expire after 24 hours; all operations disappear on daemon
restart. Querying a failed operation still succeeds as a query (exit 0).

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
        "state": {"enum": ["stopped", "starting", "running", "stopping", "error", "unknown"]},
        "node": {"type": "string"},
        "address": {"type": "string"},
        "cpus": {"type": "integer", "minimum": 0},
        "memory": {"type": "integer", "minimum": 0},
        "disk": {"type": "integer", "minimum": 0},
        "created": {"type": "string", "format": "date-time"},
        "image": {"type": "string"},
        "labels": {"type": "object", "additionalProperties": {"type": "string"}},
        "last_operation": {"$ref": "#/$defs/operation"}
      },
      "additionalProperties": false
    },
    "operation": {
      "type": "object",
      "required": ["id", "kind", "vm", "principal", "state", "started", "progress"],
      "properties": {
        "id": {"type": "string", "pattern": "^op_[0-7][0-9A-HJKMNP-TV-Z]{25}$"},
        "kind": {"enum": ["create", "start", "stop", "restart", "remove", "set"]},
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
(future phase), 9 unavailable, 255 lost transport/execution. Exec/shell pass guest
exit codes through; signal exits use `128 + signal` (capped at 255), missing guest
program uses 127, other guest launch failures use 126.
