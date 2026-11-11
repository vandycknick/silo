# Operating the lobby

The lobby runs inside silod and calls VM management and libvm in process.
Silod owns a same-user `tsgate` child for Tailscale transport. Tsgate handles
lobby-node enrollment, tailnet TCP 22, TLS on TCP 443 and stream forwarding;
it does not manage VMs. See [ADR 0022](../adr/0022-lobby-in-silod-and-tsgate.md).

## Enable

Install matching Silo runtime assets and the adjacent `tsgate` executable from
the same product build. The macOS app supplies it in `Contents/Helpers`.
Silod revalidates tsgate before every spawn: it must be a regular, non-symlink
executable owned by the daemon user or root, without group/other write access.
The package directory and every ancestor must be owned by the daemon user or
root. Group/other writes are refused except in root-owned sticky directories
(such as `/tmp`), or root-owned directories writable only by a root-equivalent
group (gid 0, plus macOS `admin`, gid 80). Root-owned Linux `staff` directories
are not exempt. Linux executes the validated open file through `/proc/self/fd`;
macOS executes its revalidated package path. Validation failure marks only the
lobby failed, with a diagnostic; the daemon's core API and VMs remain available.
There is no separate service account, gateway configuration file or SDK runtime.

```sh
silo daemon up --tailscale
silo daemon status
```

Use `silo daemon up --tailscale --system=false` for the lobby without the
system appliance. Explicit feature flags persist; omitted flags preserve the
selected features. Configure [tailnet policy](tailnet-policy.md) before granting
users access. Users connect with ordinary [SSH clients](user.md).

The strict version-1 `daemon` section in Silo's `config.yaml` accepts these
settings. This example spells out the defaults; `enabled` is selected by `up`.

```yaml
daemon:
  version: "1"
  tailscale:
    enabled: true
    hostname: silo
    tag: tag:silo
    control-url: ""
    enrollment:
      mode: oauth-app
      disable-key-expiry: false
    vm:
      defaults:
        cpus: 2
        memory: 4GiB
        disk: 20GiB
      ceilings:
        vms-per-principal: 5
        cpus: 8
        memory: 32GiB
        disk: 200GiB
    sessions:
      global: 64
      per-peer: 8
    disk-reserve: 1GiB
    file-transfer-limit: 256MiB
```

All keys above are under `daemon.tailscale`, not `daemon.lobby`.

| Setting | Meaning |
| --- | --- |
| `hostname` | Lobby node name, lowercase letters, digits and internal hyphens, 1..63 bytes |
| `tag` | Required lobby tag, default `tag:silo`; listeners require its live verification |
| `control-url` | Alternate control server; empty uses Tailscale's default |
| `enrollment.mode` | VM enrollment: `oauth-app`, `interactive` or `none` |
| `enrollment.disable-key-expiry` | Ask netd to disable VM-node key expiry using the optional API credential |
| `vm.defaults.*` | Values used when neither explicit create options nor a template supplies them |
| `vm.ceilings.vms-per-principal` | Maximum VM count for each management principal, including stopped VMs |
| `vm.ceilings.cpus`, `.memory`, `.disk` | Per-VM operator ceilings, intersected with application grants |
| `sessions.global`, `.per-peer` | Concurrent SSH session limits; peer accounting uses the verified node ID |
| `disk-reserve` | Host free-space reserve enforced during disk admission |
| `file-transfer-limit` | Maximum bytes per `cp` upload; downloads have no corresponding upload ceiling |

Configuration byte sizes accept nonnegative integer bytes or integer strings
with `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`, `TB` or `TiB`. Suffixes are
case-sensitive; `GB` is decimal and `GiB` binary. Create/set/template resource
options instead follow the CLI's binary-unit rules. Defaults must fit ceilings;
CPU ceilings are 1..255 and session limits must be positive, with per-peer no
larger than global. Unknown configuration keys are rejected. There is no global
VM image default: supply an OCI reference or a template containing one.

Registry restrictions use the shared top-level `images` policy, not a
`daemon.tailscale.vm.allowed-registries` key, for example:

```yaml
images:
  default: deny
  rules:
    - {prefix: ghcr.io/example, action: allow}
```

## Secrets and lobby enrollment

Use plain Home-scope secrets, not YAML credentials, command arguments or service
environment variables:

| Secret | Purpose |
| --- | --- |
| `tailscale.lobby.client_secret` | Literal `tskey-client-...` OAuth client secret for tagged lobby enrollment and tagged VM bootstrap |
| `tailscale.lobby.oauth_app_secret` | Literal `tskey-app-...` secret for human VM-enrollment consent |
| `tailscale.lobby.api_token` | Optional VM-node key-expiry administration |

```sh
silo secret set tailscale.lobby.client_secret --value-stdin < /private/client-secret
```

Provide the literal secret bytes without a trailing newline. Each optional value
is limited to 16 KiB and must be plain UTF-8. Missing credentials are allowed;
corrupt, unreadable or wrong-kind values fail lobby setup. Only the client secret
is sent to tsgate, through the private bootstrap socket, never argv or environment.
Restart the daemon after changing startup credentials or configuration.

These are enrollment credentials, not a policy-secret fallback. Every VM created
by the lobby resolves policy secrets from its own Machine scope only, never the
host Home store. This restriction persists across policy/label updates,
snapshots, forks and handoff. Prospective remote-policy checks also skip Home:
they report requirements from the submitted policy without revealing Home
secret names or whether those secrets exist. The lobby refuses to start, change
or open guest sessions on a lobby-labelled VM whose persisted scope is not
Machine-only (exit 5); reads, listing and logs still work. The control API
rejects requests that leave the secret scope unspecified.

The lobby node is independent of VM enrollment mode. Tsgate reuses valid persisted
node state without minting another key. If enrollment is needed and a client
secret exists, it mints a short-lived auth key for the configured lobby tag.
Without that secret, follow the approval URL in local daemon status and assign
the configured tag. The OAuth client needs auth-key creation authority for that
tag. MagicDNS and HTTPS certificates must be enabled for the lobby's TLS listener.
Tsgate pins the verified control server, tailnet and DNS suffix in its state.
Tsgate disables tsnet log upload, including `log.tailscale.com`, regardless of
ambient environment variables. Redacted local stderr logging remains enabled.

## Status and restart behavior

```sh
silo daemon status
silo daemon status --format json
silo daemon logs --follow
```

Core readiness is independent of lobby readiness. The schema-2 status record's
`lobby` object contains `phase`, `dns_name`, `approval_url`, `diagnostic`,
`restart_count` and `updated_at`. Phases are `starting`, `needs_login`,
`needs_tag`, `ready`, `degraded` and `failed`; current gateway supervision emits
all except `degraded`. Use the local status approval URL while login is pending.
`needs_tag` means the configured tag or pinned control identity is not yet
verified. Approval URLs are not written to gateway logs.

Unexpected tsgate exits or spawn failures restart only the gateway, with delays
of 1, 2, 4 seconds up to 60 seconds. A gateway lifetime of at least 60 seconds
resets the backoff. Lobby jobs and operation records belong to silod, not the
gateway: admitted work can continue, but gateway streams and SSH sessions drop.
Fresh authorization still gates work that has not yet executed. Reconnect and
inspect `ops` and `show` rather than blindly repeating a mutation.

Ordinary daemon stop/restart closes lobby sessions and bounds lobby cleanup to
85 seconds. It is not a VM-stop operation. Tsgate owner-socket loss interrupts
streams and exits within five seconds; explicit gateway shutdown allows up to
four seconds for stream draining. Jobs are in memory and do not survive a daemon
restart. There is no host-shutdown inhibitor or guaranteed guest shutdown window.
Keep the native service's process-only termination policy; do not repair the
service by killing its whole cgroup. See [daemon operation](../system-daemon.md).

On tailnet HTTPS, `GET /healthz` requires fresh WhoIs and own-scope `vm.read`.
`GET /metrics` additionally requires the peer to carry the lobby's configured
`daemon.tailscale.tag` (default `tag:silo`). Ordinary users with `vm.read` do
not gain metrics access. These are not public host listeners and do not use
forwarded identity headers. `/oauth/callback` instead requires a valid one-use
consent nonce. There is no Funnel listener.

## State and documents

`<Home>` is the normal [Silo state root](../adr/0017-single-host-state-root.md).
Keep these directories owned by the daemon user and private:

| Path | Contents |
| --- | --- |
| `<Home>/lobby/` | Stable `instance`, SSH host key, audit and principal documents |
| `<Home>/lobby/ssh_host_ed25519_key` | Persistent Ed25519 host key, mode 0600 |
| `<Home>/lobby/principals/<encoded-principal>/templates/` | Principal YAML templates |
| `<Home>/lobby/principals/<encoded-principal>/policies/` | Principal HCL policies |
| `<Home>/tsgate/` | Lobby tsnet state and `control-pin.json` |

Principal directory names use URL-safe unpadded base64. State directories are
mode 0700. Retain state across stop/start to preserve identity and SSH host pins.
Deleting `lobby/instance` does not adopt existing VMs into a new instance.
This release requires reinstall/reset, with no import of prior lobby state.

Authorization audit records go to `<Home>/lobby/audit.log` through a background
writer with a 1024-record queue. Group commits run about every 100 ms, or after
64 records, draining the whole queued backlog before syncing. Audited denials
(including identity-validation failures), plus successful `identity`/`whoami`
checks from peers with no granted actions, share a per-node token bucket
(20 per second, burst 40). Excess requests return exit 6 (`limit`) without
consuming another node's budget. Allowed decisions for granted callers never
consume this budget.
A full queue or writer failure denies new requests with exit 9 (`unavailable`).
Writer failures are logged and reported as degraded lobby status with a diagnostic;
the writer retries with backoff and clears the diagnostic on recovery. Admission
does not wait for durable commit: a crash or writer failure can lose records for
already-allowed actions. Ordinary shutdown drains and commits queued records
before joining the writer, or reports a write failure.
Rotation retries resume at the failed step. If a partial record cannot be
truncated, the writer preserves that log under a unique `audit.log.damaged.N`
name using no-replace semantics, then opens a fresh log before writing another
record. Later quarantines never replace earlier evidence.

Operator documents live in `<config_dir>/templates/NAME.yaml` and
`<config_dir>/policies/NAME.hcl`, next to Silo's `config.yaml`. Missing directories
are valid. Operator documents are read-only remotely; same-named principal
documents take precedence. Files are validated at startup and read uncached,
so invalid replacements fail reads rather than retaining an earlier cached copy.
Symlink traversal is rejected. Documents must be nonempty UTF-8, at most 64 KiB.
Use the [document commands and examples](user.md#templates-and-policies) to
validate content before installing it.

Ownership labels use `io.silo.lobby.*`, including `owner`, `owner-login`, `name`,
`instance`, `node.mode`, `node.tags`, `template`, `policy` and `guest-tcp-ports`.
Only valid labels for this lobby instance select managed VMs. Other instances,
unlabelled VMs and other principals are not adopted. Do not edit reserved labels.

## VM node enrollment

Only `create --tailscale` requests a VM tailnet node. Templates cannot opt in.
`--tag tag:NAME` is repeatable and requires `--tailscale`.

- `oauth-app` (default): human callers use pre-creation consent when an OAuth app
  secret is configured, otherwise browser enrollment runs beside guest boot.
  Configure the app's callback as `https://<lobby-hostname>.<tailnet-suffix>/oauth/callback`.
  Consent is principal/attempt-bound, single-use and expires after 15 minutes.
  Denial, expiry or failed exchange creates no VM and starts no image pull.
- `interactive`: human callers enroll through the VM's browser approval URL
  after boot; they never borrow shared tagged-provisioning credentials.
- `none`: rejects explicit VM enrollment while ordinary creation still works.
- Tagged callers use a verified management-owner tag and tagged bootstrap in
  either enabled mode. Multiple verified tags require explicit `--owner`.
  Tailscale's `tagOwners` controls the requested node tags, not lobby ownership.

The lobby creates the VM stopped and writes any one-use auth key as the
machine-scoped `tailscale.vm.auth_key` before starting it. Tagged provisioning
uses `tailscale.vm.client_secret`; optional expiry administration uses
`tailscale.vm.api_token`. A failed secret write prevents startup. Netd owns VM
registration and persistent node state, and verifies owner, exact hostname,
tags and tailnet before tailnet guest access. Keep management-agent tags separate
from VM-node tags, as shown in the [policy guide](tailnet-policy.md#tagged-automation).

Guest boot does not wait for browser login. Creation waits at most three seconds
after guest readiness for an onboarding URL; use `show VM` or `ls` later if it
is not available yet. Lobby shell/exec access does not require a VM tailnet node.
Netd can reauthenticate without restarting the guest. `--no-start` defers
node enrollment until start. There is no `reauth` command or enrollment timeout
configuration. Stop/start preserves node state. VM removal deletes local state
only; remote registrations may remain in the Tailscale admin console.

## Limits of the remote surface

Only own-scope grants are implemented. CPU, memory and disk limits are per VM;
VM-count quotas are per management principal. Names are exact and reserved
across the Home, with no owner prefix or automatic suffix. The surface accepts
OCI images, restricted templates and named policies, never host paths, host
mounts, arbitrary node declarations or cross-VM forwards. User labels cannot
use the reserved `io.silo.` prefix.

Tsgate shares a fixed cap of 256 concurrent tailnet connections across SSH and
HTTPS, with at most 32 per remote IP. Excess connections close before stream
forwarding. Silod independently caps these connections at four times
`sessions.global` overall and four times `sessions.per-peer` per verified WhoIs
node ID (256 and 32 with defaults), counting IPv4 and IPv6 together. Before
identity resolves, the same per-peer cap applies by remote IP. SSH session caps
still apply by verified node ID; each SSH connection also allows at most
`sessions.per-peer` open channels. Initial WhoIs resolution and SSH authentication
each have a 15-second deadline. SSH closes idle connections after 10 minutes
without client channel data or channel requests, even if clients answer
keepalives or receive server output. This deadline pauses while an admitted
command is running, including exec, shell, followed logs and file transfers;
it resumes when the command finishes. Idle REPLs remain subject to the deadline.
Connections without an open channel close after 60 seconds.
At most 16 queued plus active operations are admitted per principal; excess
operation submissions return exit 6 (`limit`).

Commands and interactive lines are bounded to 16 KiB. Userdata is an inline
shebang script up to 16 KiB. Stdin document/userdata reads have a 30-second
deadline. Log snapshots retain at most a 4 MiB tail before following. Guest
streams refresh identity, ownership and permissions every 30 seconds. Session
caps do not replace tailnet ACLs or application grants.
