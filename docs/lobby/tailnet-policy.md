# Tailnet policy for the lobby

Network reachability and lobby authorization are separate. Grant TCP 22 for SSH
and TCP 443 for HTTPS on the lobby node, plus the application capability
`github.com/vandycknick/silo` for management commands. The lobby resolves fresh
WhoIs from the accepted connection. SSH usernames, display names and forwarded
HTTP headers have no authority.

The default lobby tag is `tag:silo`, configurable with
`daemon.tailscale.tag`. Reserve it for the service provisioning identity.
These examples are fragments to merge into an existing tailnet policy, not a
complete policy. Replace groups/tags and run the tailnet's policy tests before
applying them.

```json
{
  "tagOwners": {
    "tag:silo": ["autogroup:admin"]
  },
  "grants": [{
    "src": ["group:developers"],
    "dst": ["tag:silo"],
    "ip": ["tcp:22", "tcp:443"],
    "app": {
      "github.com/vandycknick/silo": [{
        "scope": "own",
        "actions": [
          "vm.create", "vm.read", "vm.start", "vm.stop", "vm.delete",
          "vm.shell", "vm.exec", "vm.logs", "vm.files", "vm.update"
        ],
        "limits": {"vms": 3, "cpus": 4, "memory": "8GiB", "disk": "40GiB"}
      }]
    }
  }]
}
```

The lobby runs its own SSH server on raw tailnet TCP 22. Tailscale SSH `ssh`
rules do not replace application grants for this listener. Direct SSH to a VM
has its own node/network and guest-authentication requirements. Verified peers
with network access but no app grant can use `whoami`, `help` and `version`,
not VM operations. HTTPS `/healthz` and `/metrics` require `vm.read`.
`/metrics` additionally requires the requesting peer to hold the configured
`daemon.tailscale.tag` (default `tag:silo`). `/healthz` has no tag requirement.
Do not give users the service tag merely to enable metrics; keep tag assignment
under operator control.

## Own-scope grants

Untagged callers own resources as `user:<numeric-id>`. Tagged callers carry
each verified `tag:<name>` principal and must select `--owner` when more than
one is present. Sharing a node tag does not grant control over human-owned VMs.
No admin, wildcard-owner or cross-owner scope is implemented.

Each capability value is an object with nonempty `actions`, optional `scope`
(default `own`) and optional `limits`. The capability's value is an array of
these objects. A schema for the applicable own-scope entries follows:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Silo own-scope capability values",
  "type": "array",
  "items": {
    "type": "object",
    "required": ["actions"],
    "properties": {
      "scope": {"const": "own", "default": "own"},
      "actions": {
        "type": "array",
        "minItems": 1,
        "items": {"type": "string"},
        "description": "Known primitive actions or *. Unknown action strings are ignored."
      },
      "limits": {
        "type": "object",
        "properties": {
          "vms": {"$ref": "#/$defs/count"},
          "cpus": {"$ref": "#/$defs/count"},
          "memory": {"$ref": "#/$defs/bytes"},
          "disk": {"$ref": "#/$defs/bytes"}
        }
      }
    }
  },
  "$defs": {
    "count": {
      "type": "integer",
      "minimum": 0,
      "maximum": 18446744073709551615
    },
    "bytes": {
      "type": "string",
      "pattern": "^[0-9]+(B|KB|KiB|MB|MiB|GB|GiB|TB|TiB)?$",
      "description": "Integer byte size; scaled result must fit an unsigned 64-bit integer."
    }
  }
}
```

Unknown object fields are ignored. Scope is inspected before actions/limits:
unknown string scopes are ignored without decoding their body. A malformed
applicable entry denies the entire capability, even if another entry is valid.
Explicit nulls, nonstring actions and wrong limit types are malformed. Only
omission selects defaults. Numeric memory/disk values are invalid; use strings.
Size parsing is case-sensitive, without whitespace or fractions: `GB` is decimal,
`GiB` binary. Explicit zero limits remain zero unless another grant raises them.

Applicable grants add actions and take the maximum of each limit. Omitted
limits default to operator ceilings, so a second grant with omitted limits can
raise a tighter first grant back to those ceilings. Enforcement still intersects
the combined result with `daemon.tailscale.vm.ceilings`. `vms` limits VM count
per principal; `cpus`, `memory` and `disk` limit each VM, not aggregate usage.

| Action | Commands |
| --- | --- |
| `vm.create` | `create` |
| `vm.read` | `ls`, `show`, `ops`, document list/show/validate, HTTPS health; metrics also requires the configured lobby tag |
| `vm.start` | `start` |
| `vm.stop` | `stop` |
| `vm.delete` | `rm` |
| `vm.update` | `set` |
| `vm.shell` | `shell` |
| `vm.exec` | `exec` |
| `vm.files` | `cp` reads and writes |
| `vm.logs` | `logs` |
| `template.manage` | Create/edit/remove both templates and policies |
| `*` | All known primitive actions above |

`restart` requires both `vm.stop` and `vm.start`. `vm.restart` is not a standalone
grant action. Forced removal of a non-stopped VM additionally requires `vm.stop`.
`vm.exec` does not imply `vm.files`. To grant read-only inspection:

```json
{
  "src": ["group:reviewers"],
  "dst": ["tag:silo"],
  "ip": ["tcp:22", "tcp:443"],
  "app": {"github.com/vandycknick/silo": [{"scope": "own", "actions": ["vm.read"]}]}
}
```

## Tagged automation

Separate a management agent's tag from its VM-node tag. Giving a guest the
agent's lobby grant could let a process in that guest manage sibling VMs.
For example:

```json
{
  "tagOwners": {
    "tag:silo": ["autogroup:admin"],
    "tag:build-agent": ["autogroup:admin"],
    "tag:build-vm": ["tag:build-agent"]
  },
  "grants": [{
    "src": ["tag:build-agent"],
    "dst": ["tag:silo"],
    "ip": ["tcp:22"],
    "app": {
      "github.com/vandycknick/silo": [{
        "scope": "own",
        "actions": ["vm.create", "vm.read", "vm.start", "vm.stop", "vm.delete", "vm.exec", "vm.files"],
        "limits": {"vms": 2, "cpus": 2, "memory": "4GiB", "disk": "20GiB"}
      }]
    }
  }]
}
```

The OAuth client behind `tailscale.lobby.client_secret` needs auth-key creation
authority for the lobby tag and verified agent owner tag. Tagged VM bootstrap
keys are scoped to the owner tag; Tailscale evaluates advertised VM tags through
`tagOwners`. For example, the agent requests
`create ubuntu:24.04 --tailscale --tag tag:build-vm`. Do not grant `tag:build-vm`
the lobby capability. Requested node tags do not change management ownership.

Minted keys are not preauthorized. If device approval is enabled, approve nodes
in the admin console; `show` reports approval diagnostics. Verify that `show`
reaches `node_state: enrolled` with the exact requested tags before relying on
unattended provisioning. Policy examples alone do not establish actual
control-plane behavior.

## Guest service access

Lobby grants do not authorize browser or direct SSH traffic to VM nodes.
Separately grant intended peers access to the VM's listener ports:

```json
{
  "src": ["group:developers", "tag:build-agent"],
  "dst": ["tag:build-vm"],
  "ip": ["tcp:443"]
}
```

Template `network.publish` values and JSON `guest_tcp_ports` are discovery
hints, not inbound ACLs or host publications. Netd may relay other allowed
same-port TCP traffic, so grant only intended listener ports. Tailscale grants
are additive: broader existing rules may still allow access.

For HTTPS termination on the VM node, save this as an operator or principal
policy named `web-preview`:

```hcl
forward "tailscale" "web" {
  listen      = ":443"
  target      = "self"
  target_port = 8080
  protocol    = "https"
  tls {
    provider = "tailscale"
  }
}
```

```sh
ssh silo policy create web-preview < web-preview.hcl
ssh silo create ubuntu:24.04 --name preview --policy web-preview --tailscale --tag tag:build-vm
ssh silo show preview --json
```

The caller needs `template.manage` to upload the policy. The guest application
must serve plaintext HTTP on its guest interface (for example `0.0.0.0:8080`),
not loopback. Configure the application's external URL/proxy settings as needed.
Grant TCP 443 to the VM identity, not backend port 8080. Alternate listeners
need separate intended grants. There is no Funnel, host bind or backend HTTPS.

Enable MagicDNS and HTTPS certificates on the actual tailnet. Netd obtains and
renews certificates for the node's exact eligible DNS name and retains keys in
its persistent node state, never in the guest. Certificate names appear in
public certificate-transparency logs. Cold issuance can delay or fail the first
connection; do not delete certificate state to retry it. `show` forward URLs
report configuration, not certificate, listener or backend health.

Remote policies may use this `self` selector only with dedicated per-VM
attachments. They cannot declare nodes, explicit tunnels, host/cross-VM
forwards or reserved lobby identity metadata. The lobby owns node binding.
VMs created by the lobby resolve policy secrets only from Machine scope, never
the host Home store. Remote-policy checks do not read Home, reveal Home secret
names or distinguish their presence. An app grant cannot authorize Home-secret
access through a remote policy.
See [operator enrollment](operator.md#vm-node-enrollment) and the
[user command reference](user.md).
