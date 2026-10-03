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
requires `oauth-app-secret`. Device deletion/expiry administration uses `api-token`.
Never put credentials in YAML, service environment, command arguments or reports.
Configure the [tailnet policy](tailnet-policy.md) before admitting users.

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
- [ ] OPS-02: block control-plane access during create, observe bounded failure
  and resumable state; expire consent and verify replay/late exchange rejection.
- [ ] OPS-03: run the packaged acceptance script with isolated HOME and offline
  runtime installation; reject runtime version/hash/path and bridge version mismatch.
- [ ] Crash native bridge deliberately on a disposable host. It is in-process:
  a fatal crash means transport loss, **not a guaranteed SSH exit 9**. systemd
  restarts taild; VM state is reconciled. Recoverable unavailability can return 9.
- [ ] Exhaust scratch disk during create and verify bounded error without corrupt
  inventory; inspect an unmanaged machine without mutating it.
- [ ] Delete a VM node in the admin console; observe expired/unreadable state and
  prove `reauth` recovers exact name and ownership without duplicate identity.
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
4); older bridges are rejected before newer native symbols are resolved. The
matching bridge is embedded in the portable taild binary.
