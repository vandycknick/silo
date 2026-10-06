# Operating taild

Taild is an optional same-user helper supervised by silod. It exposes a tailnet
SSH lobby and authenticated HTTPS health/metrics endpoints. It uses Silo's normal
Home/configuration and the manager-selected native SDK assets, not a separate
service account or runtime installation. Native Linux and macOS execution must
be qualified on their respective hosts; Linux results do not qualify HVF.

## Enable

Install matching Silo binaries, runtime assets and native Go bridge together.
Silod requires `taild` and the native bridge beside its canonical executable:
`libsilo_go_ffi.so` on Linux or `libsilo_go_ffi.dylib` on macOS. Do not override the
helper's SDK loader or install a second SDK runtime. Product/protocol/ABI mismatch
is a component failure, never a fallback to another installed binary.

```sh
silo daemon up --tailscale --system=false
silo daemon status
```

The normal strict version-1 configuration accepts:

```yaml
daemon:
  version: "1"
  system:
    enabled: false
  tailscale:
    enabled: true
    hostname: silo
    tag: tag:silo
    enrollment:
      mode: oauth-app
```

`up` persists explicitly selected features and leaves other settings intact.
Core Ready, Tailscale Starting and Tailscale NeedsAuth are distinct states. Pending
network/login does not take away the core API. Read the approval URL through
local daemon status; URLs are not logged. Deterministic helper setup failures
remain visible until configuration/restart, while unexpected exits get bounded
restart backoff. Linux boot-before-login additionally depends on account linger;
see [daemon bootstrap](../system-daemon.md).

Operator templates and policies live in `<config_dir>/templates` and
`<config_dir>/policies`. Missing directories are valid. Principal documents,
audit, pins and the stable instance remain in `<Home>/taild`. Symlinks within
selected roots and unsafe document/secret leaves are rejected.

Do not install the old standalone service/sysusers configuration. Existing
service accounts and `/var/lib/silo-taild` state are neither migrated nor deleted.
`taild help` and `taild version` work offline; only a manager-provided bootstrap
can start the helper. Offline version does not load a bridge or claim a verified
ABI. Remote version reports the actual connected manager and native ABI.

## Credentials and authorization

Use existing plain Home-scope secrets:

| Name | Purpose |
|---|---|
| `tailscale.lobby.client_secret` | Tagged lobby provisioning and tagged VM bootstrap |
| `tailscale.lobby.oauth_app_secret` | User-consent OAuth app setup |
| `tailscale.lobby.api_token` | Optional key-expiry administration |

For example:

```sh
silo secret set tailscale.lobby.client_secret --value-stdin < /private/client-secret
```

Each optional value is limited to 16KiB. Missing values are allowed; corrupt,
unavailable or wrong-kind values fail helper setup. Credentials travel only in
the one-use bootstrap frame, never YAML, argv, environment, status or logs.
Configure the [tailnet policy](tailnet-policy.md) before admitting users.

## Optional VM enrollment

VMs join only when creation explicitly supplies `--tailscale`. The lobby's own
node is independent of this option. `enrollment.mode: none` rejects that explicit
request; ordinary creation still works. Templates cannot opt VMs into enrollment.

OAuth-app consent completes before image pull or VM creation. Its one-use result
is stored at `tailscale.vm.auth_key` in the new stopped VM's secret scope before
startup. Denied/expired consent creates no VM. Tagged workflows use the initial
`tailscale.vm.client_secret`; optional expiry administration uses
`tailscale.vm.api_token`. These are delivered through the existing secret transport,
not through the status file. Existing node state takes precedence over bootstrap keys.

All VM-node enrollment runs inside netd alongside guest boot. Taild waits at most
three seconds after guest readiness for a login URL. The guest is accessible through
`ssh -t silo shell NAME`. Netd initiates required browser reauthentication without a
VM restart; `show` displays the login URL. Active lobbies surface deduplicated notices.
`daemon.tailscale.enrollment.disable-key-expiry` runs in netd and failures appear in status while being retried.

Humans may request `--tag tag:NAME` repeatedly. Tailscale's tag-owner permissions
authorize assignment through the caller's user-authorized credential or browser
identity. The VM's taild management owner remains its creator. Human requests never
use a shared OAuth client to bypass tag permissions. Tagged callers select a
verified management-owner tag; the initial key is scoped to that tag, and Tailscale
authorizes advertised tags through its tag-owner relationships.

Netd verifies the owner, exact hostname and tailnet against taild-injected reserved
policy metadata before allowing tailnet guest traffic. User policies cannot supply
that metadata. Use a matching updated netd/runtime with this taild build.

### Live status file (version 1)

Netd atomically replaces `<machine>/tailscale.status.json` with mode 0600. It is a
one-way observation file alongside the private `tailscale/` directory, not a request
queue. Fields are `version`, `vm_id`, `run_id`, `observed_at`, `state` and optional
`approval_url`, `node_id`, `dns_name`, `tags`, `error_code`, `addresses`, `key_expiry`,
`key_expiry_known`, and `last_known`. States are `connecting`,
`approval_required`, `ready`, `disconnected`, `failed` and `stopped`. URLs are
cleared when no longer applicable; the file contains no credentials or private keys.

Taild accepts it only for the current running VM/run, with an observation no more
than 60 seconds old (and at most five seconds in the future). Missing, malformed,
stale or mismatched files mean status is unavailable. Stopped VMs and previous
runs cannot reuse an old snapshot. After an unclean netd exit within the same VM
run, its last observation can remain visible until the 60-second freshness bound;
the snapshot is not an instantaneous health probe. Netd refreshes status
periodically and on Tailscale notifications; the VM remains usable if the snapshot
cannot be written. `show` and `ls` expose current approval URLs without requiring
the original creation session. The status protocol is independent of the SDK.

`last_known` retains the last verified node identity and expiry with its original
observation timestamp. Stopped VMs display their configured hostname and historical
expiry; these values do not establish connectivity or authorize access. A known
absent expiry means `Never`, while an absent observation means `Unavailable`.

### Upgrade notes

Remove `enrollment.timeout` from configuration. The `reauth` command is removed;
authentication is handled by netd and observed with `show`. Use the matching updated
netd/runtime and **ABI 1** Go bridge, including generic machine-scoped secret writes.
Start/update retain enrollment recovery checks. Explicit VM removal discards local
node state, including abandoned transactions, once no process or lease is using it.

VM removal is local only. It neither logs out nor deletes a remote Tailscale device.
Persistent registrations may remain in the admin console and affect exact hostname
reuse; ephemeral registrations follow Tailscale's own cleanup behavior. Successful
`rm` output contains only the normal removal summary.

Set per-principal VM ceilings, per-VM CPU/memory/disk ceilings, session concurrency,
image registry allowlist and `disk-reserve` under `daemon.tailscale`. The remote
surface accepts operator-approved templates and policies, never arbitrary host
paths or host file mounts. Only `own` scope is accepted in v1. SIGHUP reloads
operator documents; inspect logs for rejection and retained prior documents.

## Restart and shutdown

`KillMode=process` is essential: the user service terminates silod, which drains
and reaps taild explicitly. Independent VM workers and guest SSH sessions survive.
Helper-owned lobby sessions drain within the bounded shutdown window; unexpected
parent-pipe EOF cancels them immediately. Neither event is a host-shutdown request.
Never use a whole-cgroup kill to repair the service. On Linux, the existing logind
delay inhibitor permits a bounded stop of managed VMs only for authenticated host
shutdown. Configure its budget/margin within the host's inhibitor delay and test it.

Audit records live below the private home and rotate; treat them as access records.
`/healthz` and `/metrics` use the same capability authorization as the lobby.
Unlabelled machines are reported unmanaged, never adopted or stopped by taild.

## Failure drills and release gates

These are manual, unchecked until a dated result with artifact SHA-256 and host
details is recorded. Automated offline tests do not establish real tailnet behavior.

- [ ] OPS-01: keep a VM SSH session and lobby shell open; restart the real unit,
  then SIGKILL taild, then stop the unit. VM/session survive; lobby drops and
  inventory reconciles on restart. Finally shut down the test host and verify
  managed VMs stop gracefully within the logind budget.
- [ ] OPS-02: block control-plane access during interactive `create --tailscale`;
  verify guest readiness and lobby shell access without approval. Restore access,
  approve the URL and verify direct SSH without a reboot. For OAuth-app creation,
  verify no image pull or VM record before consent, and replay/late exchange rejection.
  Expire an enrolled node and complete its new browser login while the guest stays up.
- [ ] OPS-03: run packaged acceptance with an isolated Home and no installed SDK
  runtime; verify the adjacent bridge is mapped and exact product assets are reused.
  Reject component and bridge version/ABI/path mismatches.
- [ ] Crash the native bridge deliberately on a disposable host. It is in-process:
  a fatal crash means transport loss, **not a guaranteed SSH exit 9**. Silod restarts
  taild and inventory reconciles. Recoverable unavailability can return 9.
- [ ] Exhaust scratch disk during create and verify bounded error without corrupt
  inventory; inspect an unmanaged machine without mutating it.
- [ ] Delete a VM node in the admin console; observe expired/unreadable state and
  inspect `show` and recover through the reported login action; verify exact name
  and ownership before guest access resumes.
- [ ] G1: guest SSH certificate/user isolation, native fallback and OpenSSH matrix.
- [ ] G2: actual user-owned enrollment, OAuth consent, tag provisioning, exact DNS,
  peer SSH, node replacement and reauthentication on the configured tailnet.
- [ ] G3: one week unattended on a real systemd test host, no manual repair.

Record skips honestly when KVM, logind, credentials or another architecture are
unavailable. Release memory acceptance must use the shipped artifact: the historical
unstripped debug agent OOMs at 256 MiB. Retained debug builds require at least 1 GiB;
the current Linux amd64 release archive passed real guest execution at 256 MiB on
2026-10-01. This does not qualify other guest workloads or architectures.
Offline `taild version` reports the required ABI (currently 1), not an invented
verified value. The remote version reports the actually verified ABI and connected
silod/protocol. Integrated startup loads the manager-selected adjacent bridge;
it does not extract an embedded SDK bridge.
