# Tailnet policy for taild

The operator must separately grant network access, Tailscale SSH access where
appropriate, and the application capability `github.com/vandycknick/silo/cap/taild`.
Network reachability alone does not authorize lobby commands. Taild resolves
WhoIs for the connection and accepts only current approved capability scopes.
Only `own` is implemented; do not grant wildcard or cross-owner scopes.

Use the capability schema in `app/taild/internal/identity` for the pinned source
revision. Review policy with the tailnet's policy tests before applying it.
Grant the lobby tag `tag:silo` only to the service provisioning identity; grant
users access to lobby TCP 22 and 443. Grant direct VM access according to intended
owner/group network policy. VM publish hints do not restrict inbound ports.

Illustrative application grant (merge into your existing tailnet policy, replace
the group and review with policy tests):

```json
{
  "grants": [{
    "src": ["group:developers"],
    "dst": ["tag:silo"],
    "ip": ["tcp:22", "tcp:443"],
    "app": {
      "github.com/vandycknick/silo/cap/taild": [{
        "scope": "own",
        "actions": ["vm.create", "vm.read", "vm.start", "vm.stop", "vm.delete", "vm.shell", "vm.exec", "vm.logs", "vm.update"],
        "limits": {"vms": 3, "cpus": 4, "memory": "8GiB", "disk": "40GiB"}
      }]
    }
  }]
}
```

`vm.restart` and `vm.reauth` require both `vm.stop` and `vm.start`; they are not
standalone grant actions. `template.manage` is a separate optional action. Effective
limits remain bounded by the operator's configured ceilings.

User-owned enrollment must verify the consenting user's identity and exact assigned
DNS hostname. Tagged provisioning must be explicitly approved for that principal.
Global DNS collisions are rejected; owner prefixes are never silently added.
Use narrowly scoped device administration credentials if deletion or expiry changes
are enabled. Configure OAuth callbacks to the lobby's actual HTTPS name; never
replace consent with an ambient host identity or a broadly shared auth key.

Policy examples are not evidence of working control-plane behavior. Complete G2 in
the [operator guide](operator.md) with actual credentials and peer connections.
