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
Use narrowly scoped device administration credentials if expiry changes
are enabled. Configure OAuth callbacks to the lobby's actual HTTPS name; never
replace consent with an ambient host identity or a broadly shared auth key.

## HTTPS guest forwards

The [guest HTTPS example](user-quickstart.md#expose-a-guest-service-over-tailnet-https)
uses a separate network grant to the **VM identity** on TCP 443. Keep the lobby
application grant above; it does not authorize browser traffic to VMs. Policy
uploads additionally require `template.manage`. Browser peers need no lobby
management capability merely to use an already exposed frontend.

Grant the frontend's listener port, not its backend guest port (for example
8080). Alternate HTTPS or raw TCP listeners need their own intended port grants.
Do not add Funnel, a host port bind, or a backend-port grant for this workflow.
Grants are additive: a broader existing rule can still allow direct guest access.

Enable MagicDNS and HTTPS certificates in the designated tailnet. Netd obtains
certificates only for the listening node's exact eligible DNS name and persists
certificate state with that node. Hostnames appear in public certificate
transparency logs. The guest's `self` selector does not choose the certificate
identity and is valid only for a dedicated 1:1 attachment.

Live regression fixtures use disposable `tag:silo-test` lobby and
`tag:silo-test-vm` VM identities, plus an independently denied peer configured
through `SILO_E2E_TS_DENIED_CLIENT_SECRET` and `SILO_E2E_TS_DENIED_TAG`. The
denied identity must have no effective TCP 443 grant to the VM. The suite also
needs the existing live tailnet/client/peer/API-token variables, explicit
runtime/bridge/rootfs fixtures, `SILO_TEST_BIN_DIR` selecting the matching
daemon binaries, and the compiled `SILO_TAILD_FORWARD_PROBE`. Its rootfs must
boot systemd as PID 1 and provide `systemctl`: once-only userdata installs and
enables the probe service so it also starts after reboot. The shutdown proof
requires a clean exact-generation exit and terminal forward audits before the
netd stop boundary, not merely a successful forced kill.
It does not alter tailnet grants, DNS settings, or certificate settings.

Policy examples are not evidence of working control-plane behavior. Complete G2 in
the [operator guide](operator.md) with actual credentials and peer connections.
