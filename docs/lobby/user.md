# Using the lobby

The lobby is a VM-management SSH service inside silod. Connect to the lobby's
Tailscale DNS name with ordinary OpenSSH; examples below assume it is `silo`.
Your verified tailnet identity and [application grants](tailnet-policy.md), not
the SSH username or an SSH key, determine access. The lobby accepts SSH `none`
authentication only on its tailnet transport. Keep normal host-key verification.

```sh
ssh -t silo                         # interactive silo> prompt
ssh silo whoami
ssh silo help create
ssh silo create ubuntu:24.04 --name devbox
ssh -t silo shell devbox
ssh silo exec devbox -- uname -a
ssh silo ls --json
```

An empty command with a PTY opens the lobby prompt; without a PTY it prints
help and exits 2. At the prompt, Ctrl-C cancels the current input line and
Ctrl-D leaves an empty prompt. History and Unicode editing are supported.
Bracketed paste cannot submit a command by itself. Each command refreshes
WhoIs; idle PTY sessions also refresh identity every 30 seconds. The service
does not provide a host shell, SFTP/SCP subsystems, port, X11 or agent forwarding.

SSH authentication must complete within 15 seconds after initial identity
resolution. SSH closes idle connections after 10 minutes without client channel
data or channel requests; keepalive replies and server output do not extend that
deadline. It pauses while an admitted command is running (including exec, shell,
followed logs and copies), but not while a REPL waits for input. Connections
without an open channel close after 60 seconds. Tsgate admits at most 256
concurrent connections, 32 per remote IP, across SSH and HTTPS.
Silod additionally counts both address families together by verified node ID
after WhoIs resolution. Each SSH connection's open channels are bounded by
`daemon.tailscale.sessions.per-peer` (default 8). Excess connections or channels
can be refused before a command runs.

## Command language

Commands are one line, with single/double quotes and backslash escapes. Empty
quoted arguments are retained. There is no shell expansion, pipeline, command
substitution or redirection. Unquoted shell syntax is rejected before the exec
`--` delimiter; after it, arguments are literal, not evaluated by a shell.
When calling through a local shell, quote the whole command to preserve quotes
for the lobby parser:

```sh
ssh silo "exec devbox -- python3 -c 'print(1, 2)'"
ssh silo "exec devbox -- printf '%s\\n' '$'"
```

For shell syntax inside the guest, explicitly run a guest shell, for example
`ssh silo "exec devbox -- sh -c 'printf hello'"`. Never put host file paths in
lobby commands; redirect SSH stdin/stdout locally instead.

Every command and nested verb accepts `-h` and `--help`; equivalent topics use
`help COMMAND [SUBCOMMAND]`. Help does not consume stdin or execute the command.
Nonstreaming commands also accept `--json`. `shell`, `exec`, `cp` and `logs`
reject lobby `--json`; after exec's `--`, `--help` and `--json` are guest arguments.

## Commands

`VM` means an exact name or VM ID owned by one of your verified principals and
managed by this lobby instance. Other owners' VMs are invisible. Untagged peers
own VMs as `user:<numeric-id>`; tagged peers use verified `tag:<name>` principals.
Multiple verified tags require `--owner tag:NAME` when selecting a namespace for
creation or a document. That option does not grant access to another owner.

### Identity and inspection

| Command | Meaning |
| --- | --- |
| `whoami` | Verified login and node; JSON also includes permissions and capability explanation |
| `version` | Lobby, silod and Tailscale versions |
| `help [COMMAND [SUBCOMMAND]]` | Command reference |
| `ls` (alias `list`) | List your managed VMs |
| `show VM` (alias `status`) | Inspect one VM, including current enrollment URL when present |
| `ops` | List your operation records |
| `ops show OPERATION_ID` | Inspect one `op_ULID` record |

These commands have no command-specific flags. All support `--json` and help.
`whoami`, `version` and `help` need verified identity but no management grant.
Inventory, operations and document reads require `vm.read`.

### Create

```text
create [IMAGE] [-n NAME | --name NAME] [--image OCI] [--template NAME]
       [--policy NAME] [--cpus N] [--memory SIZE] [--disk SIZE | --disk-size SIZE]
       [--provision-user NAME:UID:GID:HOME] [--userdata INLINE|-]
       [--label K=V]... [--owner tag:NAME]
       [--tailscale] [--tag tag:NAME]... [--no-start]
```

Alias: `new`. Requires `vm.create`.

| Option | Meaning |
| --- | --- |
| `-n`, `--name NAME` | Exact name; omitted names are generated |
| `--image OCI` | Alternative to positional IMAGE; supplying both is invalid |
| `--template NAME` | Apply a YAML template; explicit options override it |
| `--policy NAME` | Named HCL network policy, overriding a template's policy reference |
| `--cpus N` | Positive CPU count, 1..255, bounded by grants and operator ceilings |
| `--memory SIZE` | Binary memory size |
| `--disk`, `--disk-size SIZE` | Binary root-disk size |
| `--provision-user NAME:UID:GID:HOME` | Provision and record the default guest account |
| `--userdata INLINE` | Inline shebang script, at most 16 KiB; `-` reads stdin after authorization |
| `--label K=V` | Repeatable caller label; `io.silo.*` keys are reserved |
| `--owner tag:NAME` | Select one of your verified management-owner tags |
| `--tailscale` | Request a separate VM tailnet node |
| `--tag tag:NAME` | Repeatable requested node tag; requires `--tailscale` |
| `--no-start` | Create stopped instead of booting immediately |

IMAGE is always an OCI reference, never a VM name. Supply it explicitly or use
a template containing an image; there is no default image. Names contain
lowercase letters, digits and hyphens, start with a letter or digit and are at
most 63 bytes. An explicit collision fails rather than silently renaming.

Memory/disk values use CLI binary parsing: `8gb`, `8GB`, `8g` and `8GiB` all
mean 8589934592 bytes. Case and surrounding whitespace are ignored. Grants and
configuration byte counts have different decimal/binary suffix rules.

Without `--provision-user`, shell/exec default to root. `--tailscale` is opt-in
and independent of lobby access to the guest. Human OAuth consent, if configured,
finishes before image pull and VM creation. Interactive node login instead runs
alongside guest boot. Follow creation's approval URL or inspect `show VM` later.
Tailscale authorizes requested tags separately from management ownership.
See [enrollment modes](operator.md#vm-node-enrollment).

### Lifecycle and configuration

| Command | Options and semantics | Required action |
| --- | --- | --- |
| `start VM` | Start a stopped VM | `vm.start` |
| `stop VM [--force] [--timeout DURATION]` | Graceful stop, or force shutdown; timeout 0..1m, such as `30s` | `vm.stop` |
| `restart VM` | Stop and start the VM | Both `vm.stop` and `vm.start` |
| `rm VM [--force] [--yes]` | Remove; `--force` first stops a running VM, `--yes` bypasses `[y/N]` | `vm.delete`, plus `vm.stop` when not stopped |
| `set VM KEY=VALUE...` | Update a stopped VM | `vm.update` |

`set` keys are `name`, `cpus`, `memory`, `disk` and `policy`. `policy=NAME`
resolves the current named policy; `policy=` clears it while retaining an
existing VM-node declaration. Resource limits still apply; disk may only grow.
Names remain exact, and VMs with a Tailscale declaration cannot be renamed.
There are no other command-specific flags for these commands. All support
`--json` and help.

```sh
ssh silo stop devbox --timeout 30s
ssh silo set devbox memory=8gb disk=40GiB
ssh silo set devbox policy=web-preview
ssh silo start devbox
ssh silo rm devbox --force --yes --json
```

Non-PTY removal requires `--yes`; `--json` does not confirm it. Declining or
failing to confirm exits 2. Removing a VM deletes local node state, not its
remote Tailscale registration.

Mutations return an operation after waiting for completion. Closing the observing
SSH session does not roll back or cancel an admitted job. Reconnect and inspect
`ops`/`show` rather than retrying an uncertain mutation. Jobs serialize changes
to one VM, refresh authorization before execution and retain completed records
for 24 hours. All operation records disappear on daemon restart, but not on a
tsgate-only restart. A successful query of a failed operation exits 0.
Each principal can have at most 16 queued plus active operations; further
submissions fail with exit 6 (`limit`) until capacity is released.

### Shell and exec

```text
shell VM [-u USER]                         # alias: ssh
exec VM [-u USER] [-w DIR] [-e K=V]... [-t] -- CMD [ARG]...
```

`shell` requires `vm.shell` and an outer SSH PTY (`ssh -t`). It opens the guest
account's login shell over libvm's certificate SSH attachment, not a process
RPC or a host terminal. The selected account determines shell, home and startup
environment. A running VM with an established guest host-key pin and working
guest SSH listener can remain accessible when guest-agent health is stale;
first-pin establishment cannot bypass an agent outage.

`exec` requires `vm.exec` and runs a guest program directly, without an implicit
shell. `-u` overrides the recorded default guest user; `-w` selects the guest
working directory, defaulting to that account's home. Repeat `-e K=V` for guest
environment overrides. Account identity enriches HOME, USER, LOGNAME and SHELL
before explicit overrides. `-t` requests a guest PTY and also requires `ssh -t`.
Initial TERM/size, resize and supported SSH signals reach the guest.

Without `-t`, exec streams SSH stdin to the guest process and closes guest stdin
on EOF. This supports scripts and binary input:

```sh
ssh silo exec devbox -- python3 - < edit.py
ssh -t silo exec devbox -u root -w /root -e EDITOR=vi -t -- sh
```

PTY input EOF sends two best-effort EOT bytes; shell attachment also closes its
SSH input channel. EOT is terminal input, not a guaranteed logout. Use `exit`
for graceful completion, or disconnect to cancel the attachment/execution.
Disconnect never stops the VM. Output drains before exit status is sent.
Identity, ownership and action grants are rechecked every 30 seconds on streams.

### File copy

```text
cp [--mode OCTAL] [--owner UID[:GID]] [-p | --parents]
   [-n | --no-clobber] SRC DST
```

Requires `vm.files`, independently of `vm.exec`. One endpoint must be `-` and
the other `VM:/absolute/path`. Only regular files are supported, with no local
path, directory, VM-to-VM or SCP/SFTP mode. Use non-PTY SSH for byte-safe copies:

```sh
ssh silo cp - devbox:/root/patch.diff < patch.diff
ssh silo cp devbox:/root/result.bin - > result.bin
ssh silo cp -p --mode 0755 --owner 1000:1000 - devbox:/opt/bin/tool < tool
```

All options are upload-only. New files default to 0644; replacement preserves
mode unless specified. `--owner` uses numeric IDs, `--parents` creates missing
parents and `--no-clobber` fails if the destination exists on a best-effort,
non-atomic basis. Uploads are limited by
`daemon.tailscale.file-transfer-limit` (default 256 MiB). Downloads are not
subject to that upload ceiling. Transfer summaries and SHA-256 digests use
stderr; download stdout contains only file bytes. No lobby `--json` is supported.

### Logs

```text
logs VM [--follow] [--stream monitor|serial|exec|network|network-audit]
        [--output stdout|stderr]
```

Requires `vm.logs`. Default stream is `serial`; omitted output includes both
stdout and stderr. A snapshot reads at most a 4 MiB tail, aligned to complete
lines and redacted. `--follow` continues streaming. There is no lobby `--json`.

## Templates and policies

Both command groups have the same verbs and optional `--owner tag:NAME`:

```text
template ls                         policy ls
template show NAME                  policy show NAME
template create NAME                policy create NAME
template edit NAME                  policy edit NAME
template rm NAME                    policy rm NAME
template validate                   policy validate
```

Every verb accepts help and `--json`. `create`, `edit` and `validate` read one
nonempty UTF-8 document from stdin, at most 64 KiB, within 30 seconds. `edit`
replaces the whole document; it does not launch an editor. Read/validate requires
`vm.read`; create/edit/rm requires `template.manage` for both groups. Lists show
principal and operator tiers. Principal documents shadow same-named operator
documents; operator documents cannot be changed remotely. Document names follow
the same lowercase 1..63-byte naming rule as VM names.

```sh
ssh silo template validate < dev.yaml
ssh silo template create dev < dev.yaml
ssh silo policy create web-preview < web-preview.hcl
ssh silo create --template dev --name devbox
```

A restricted lobby template can contain:

```yaml
version: "1"
image: ubuntu:24.04
resources: {cpus: 2, memory: 4GiB}
disk_size: 20GiB
vsock: true
network: {kind: private, publish: [8080]}
labels: {team: development}
```

Optional fields also include `description`, inline shebang `userdata` and
`network.policy_ref`. Unknown fields, nulls, YAML aliases/merges, host paths,
host mounts, non-private networking and `vsock: false` are rejected. Publish
ports are discovery hints, not ACLs. Templates do not request VM enrollment.

Policies are HCL network documents. Remote policies cannot declare Tailscale
nodes, reserved lobby metadata, explicit tunnels, host or cross-VM forwards.
For an enrolled VM, forwards must use `forward "tailscale"` with `target = "self"`
and no `tunnel`. See the [HTTPS example](tailnet-policy.md#guest-service-access).
Editing/removing a policy reports visible `bound_vms` but never changes those
VMs. Apply a replacement explicitly with `stop`, `set VM policy=NAME`, `start`.

VMs created by the lobby resolve policy secrets only from their own Machine
scope, never the host Home store. Remote-policy checks do not read Home or
reveal Home secret names/presence; missing-policy-secret diagnostics describe
the submitted policy's requirements, not the host's secret inventory.

## JSON and exit codes

For supported commands, `--json` writes one UTF-8 object and newline to stdout;
progress, human summaries and errors use stderr. Use non-PTY SSH to keep stdout
separate. There is no JSON-lines event stream.

```json
{"ok":true,"data":[]}
```

```json
{"ok":false,"error":{"code":"conflict","message":"exact VM name is already taken"}}
```

An admitted operation failure also includes its operation record in `data` and
its ID in `error.operation`. Validation/admission failures have no operation.
Identity or tokenizer failures before the JSON flag can be parsed are plain
SSH/stderr failures, not a guaranteed JSON envelope.

| Command | `data` |
| --- | --- |
| `ls` | Array of VM records; empty when no VMs are visible |
| `show` | One VM record |
| `create`, `start`, `stop`, `restart`, `rm`, `set` | One terminal operation record |
| `ops`, `ops show` | Array of operation records, one for show |
| `whoami` | `{peer, capability, explanation?}` |
| `version` | `{lobby, silod, tailscale}` version strings |
| `help` | `{help}` string |
| `template`, `policy` | Array of document records, one for non-list verbs |

VM records include `id`, `name`, `owner`, `state`, `node`, `node_state`,
`address`, `cpus`, `memory`, `disk`, `created`, `image`, `labels`, `default_user`
and `key_expiry`. Optional fields include `owner_login`, provisioned `guest_user`,
`template`, `policy`, `guest_tcp_ports`, `forwards`, `tags`, `node_id`,
`node_diagnostics`, `addresses`, `approval_url`, `key_expiry_observed_at` and
`key_expiry_last_known`. Resources are integer bytes and timestamps are UTC
RFC 3339. Labels omit reserved authority labels. Owner login is display-only;
`owner` is authoritative. No host paths, credentials or raw native diagnostics
are projected.

Node states include `none`, `pending approval`, `enrolled`, `connecting`,
`disconnected`, `stopped`, `expired`, `enrollment failed`, `status unavailable`
and `state unreadable`. `key_expiry` is a timestamp, `never` or `unknown`;
last-known values do not establish connectivity. `forwards` records contain
`name`, `protocol`, `listen_port`, `target_port` and optional `url`. These report
configuration, not listener/backend health.

Operations contain `id`, `kind`, `vm`, `principal`, `state`, `started`, `progress`,
optional `finished`, `error` and `completion`. States are `queued`, `running`,
`succeeded`, `failed`. Kinds are create/start/stop/restart/remove/set. Progress
retains at most 128 lines of at most 1024 bytes. Completion captures immutable
VM ID/name/image/default user, running state, node state and any known DNS/URL.

Document records contain `kind`, `name`, `tier` (`yours` or `operator`) and
optional `owner`, `content`, typed `template`, policy `secrets` metadata and
`bound_vms`. Lists omit content. Validation stores nothing and uses empty name
and tier. Secret metadata contains names/requirements, never secret values.

| Exit | Meaning / JSON error codes |
| --- | --- |
| 0 | Success |
| 2 | Usage, validation or cancellation: `usage`, `cancelled` |
| 3 | Missing/invisible VM, document or operation: `not_found` |
| 4 | Capability/identity denial: `forbidden` |
| 5 | State or naming conflict: `conflict` |
| 6 | Resource/session/admission limit, including 16 queued/active operations per principal: `limit` |
| 7 | VM/image operation failure: `operation_failed`, `image` |
| 8 | Enrollment approval pending, failed or expired: `pending_approval`, `expired` |
| 9 | Unavailable runtime, state or audit writer/queue: `unavailable` |
| 255 | Lost SSH/execution transport: `disconnected`, or SSH's own failure |

Authorization audit records use a background writer with group commits about
every 100 ms. A full audit queue or writer failure denies new requests with exit 9.
Admission does not wait for durable commit: a crash or writer failure can lose
audit records for already-allowed actions. Transient writer failures are retried
with backoff. Audited denials (including identity-validation failures), plus
successful `identity`/`whoami` checks from peers with no granted actions, share a
per-node limit of 20 per second with a burst of 40. Excess requests return exit 6
without throttling other nodes. Allowed decisions for granted callers never
consume this budget.

Shell/exec pass guest exit status through, so it can overlap lobby categories.
Signal exits use `128 + signal`, capped at 255. Missing guest programs use 127;
other guest launch failures use 126. A lost connection does not prove that an
admitted mutation failed or was undone.
