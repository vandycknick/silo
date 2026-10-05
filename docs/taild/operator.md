# Operating taild

taild is an optional Linux service. It exposes a tailnet SSH lobby and authenticated
HTTPS health/metrics endpoints, using the public Go SDK to manage one host's VMs.
Native Linux amd64 and arm64 packaging must be qualified separately. macOS service
operation is unsupported; Linux results do not qualify Virtualization.framework.

## Install

Use the portable archive and matching runtime-only archive from the same release
and target. See [PACKAGING](../../PACKAGING.md) for provenance and build order.
Install `bin/taild` at `/usr/bin/taild`. Copy the shipped service and sysusers
fragment into `/etc/systemd/system/silo-taild.service` and
`/etc/sysusers.d/silo-taild.conf`, then run `systemd-sysusers`.
The unit maintains `/var/lib/silo-taild` with mode 0700 and grants the service user
membership in `kvm`. Create that directory before the initial offline installation,
which runs before the unit starts. Check that `/dev/kvm` is group-accessible on this host.

Create `/etc/silo-taild` and its `secrets`, `templates`, and `policies` directories.
Secrets directory: owner `silo-taild:silo-taild`, mode 0700. Secret files: same owner,
mode 0600, regular files, no symlinks. Config and operator documents must be readable
by the service user and writable only by the operator. Start from the shipped
`config.yaml`, `examples/devbox.yaml` and `examples/dev-egress.hcl`.
Put the YAML template in `templates/devbox.yaml` and HCL in `policies/dev-egress.hcl`.
Set `runtime_archive` to the absolute path of the matching runtime-only archive.

```sh
sudo install -d -o silo-taild -g silo-taild -m 0700 /var/lib/silo-taild
sudo -u silo-taild /usr/bin/taild install-runtime --config /etc/silo-taild/config.yaml
sudo -u silo-taild /usr/bin/taild --check --config /etc/silo-taild/config.yaml
sudo -u silo-taild /usr/bin/taild version --config /etc/silo-taild/config.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now silo-taild
```

Offline installation uses the archive checksum embedded in the qualified SDK,
not a downloaded checksum or an operator-supplied digest. An explicit `runtime_root`
must include root `runtime-manifest.json` with exact SDK version, native SDK target
identifier and the complete bin/assets inventory with lowercase SHA-256 digests.
Wrong versions, altered components, extra paths and traversal paths must fail
before VM use. Do not set `SILO_GO_FFI_PATH` for installed binaries: the bridge is
embedded, digest-checked and ABI/product-version checked by the SDK loader.

## Credentials and authorization

The local files are `oauth-client-secret`, `oauth-app-secret`, and `api-token`. Supply only those
required by the configured enrollment mode. `oauth-client-secret` provisions the tagged
lobby. Interactive enrollment requires user consent, OAuth-app enrollment also
requires `oauth-app-secret`. Optional key-expiry administration uses `api-token`.
Never put credentials in YAML, service environment, command arguments or reports.
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
`disable_key_expiry` runs in netd and failures appear in status while being retried.

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
image registry allowlist and `disk_reserve` in the operator config. The remote
surface accepts operator-approved templates and policies, never arbitrary host
paths or host file mounts. Only `own` scope is accepted in v1. SIGHUP reloads
operator documents; inspect logs for rejection and retained prior documents.

## Restart and shutdown

`KillMode=process` is essential: ordinary stop/restart terminates taild only.
Lobby sessions drop; running VM workers and independent guest SSH sessions
(`ssh root@dev` by default, or the explicitly provisioned guest username) survive.
Never add `Delegate=` or use a whole-cgroup kill to repair the service.
At host shutdown, the logind delay inhibitor permits a bounded SDK stop of managed
VMs. The ExecStop fallback stops VMs only when system state is `stopping`.
Configure shutdown budget/margin within the host's inhibitor delay and test them.

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
- [ ] OPS-03: run the packaged acceptance script with isolated HOME and offline
  runtime installation; reject runtime version/hash/path and bridge version mismatch.
- [ ] Crash native bridge deliberately on a disposable host. It is in-process:
  a fatal crash means transport loss, **not a guaranteed SSH exit 9**. systemd
  restarts taild; VM state is reconciled. Recoverable unavailability can return 9.
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
`taild version` reports numeric required and actual verified native ABI (currently
1); mismatched bridges are rejected before native API symbols are resolved. The
matching bridge is embedded in the portable taild binary.
