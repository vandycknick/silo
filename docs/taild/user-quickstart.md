# Taild user quick start

Your operator grants the lobby capability and supplies approved templates and
policies. Connect using your tailnet identity, not a host account or an SSH key.

```sh
ssh silo
ssh silo help
ssh silo template ls
ssh silo policy ls
ssh silo create --name dev --template devbox
ssh silo show dev
ssh -t silo shell dev
```

Tailscale enrollment is opt-in. Add `--tailscale` to give the VM its own node:

```sh
ssh silo create --name tailbox --template devbox --tailscale
ssh -t silo shell tailbox
ssh silo show tailbox
# After enrollment completes:
ssh root@tailbox
```

For interactive enrollment, the guest boots while approval is pending. Creation
waits for guest readiness, then at most three more seconds for the onboarding URL,
never for you to approve it. Follow the returned URL, or retrieve it with `show`.
Closing the lobby or restarting taild does not cancel netd's interactive login.
If OAuth-app consent is configured, that initial consent happens before the VM is
created. Taild saves the returned bootstrap key for netd; registration then proceeds
alongside guest boot. Denied or expired consent creates no VM. Consent links are
short-lived and one-use.

You may request tags you are permitted to assign through Tailscale:

```sh
ssh silo create --name tagged-dev --template devbox --tailscale --tag tag:dev --tag tag:testing
```

Tailscale evaluates tag-owner permissions using the authenticating identity. The
VM remains yours to manage in taild, while its Tailscale identity becomes tag-based.
Guest SSH still requires the VM's management owner and permitted network access.

Netd handles expired authentication in the background. `show VM` displays any
required login URL; the guest remains running and accessible through the lobby.
Active lobby prompts show one notice per new login URL. Notices wait until you
return from a guest session. There is no separate `reauth` command.

`dev` is the exact requested name, never an owner-prefixed alias.
If anyone already owns that name locally or on the tailnet, create fails; choose
another name. Only your own VMs are visible and manageable under v1 `own` scope.

The interactive lobby opens with only `silo> `. Run `whoami` for your verified
login and node, or `whoami --json` for detailed identity/access diagnostics.
Tagged devices are identified as tagged devices, not as their creating human.
Every command accepts `-h`/`--help`; nested help works as
`ssh silo help template create` or `ssh silo policy validate --help`.

`create [IMAGE] [-n/--name NAME] [OPTIONS]` always treats its positional argument
as an image. With no name, Silo generates one and reports it in progress and the
JSON operation's `vm` field. There are at most three collision proposals before
publication. Explicit names stay exact, and a later conflict fails rather than
renaming the VM. Options may appear before or after IMAGE. `--image` is a
compatibility alias, but cannot be combined with positional IMAGE. An image must
be supplied explicitly or by the selected template; there is no global default
image. An explicit image overrides the template image. If neither provides one,
creation fails with a usage error before reserving a name or starting work.
Create starts the VM by default; `--no-start` leaves it stopped and defers enrollment until startup.
The former `--no-tailnet` flag has been removed; omitting `--tailscale` is the default.

Interactive terminals show an updating Silo-style spinner followed by a concise
completion summary and the usable lobby shell command. A direct VM SSH command
appears only when its running node is verified. Non-PTY output is static; JSON
includes the operation's structured `completion` details without animation.

Create options, `set` and template resource sizes use binary CLI units,
case-insensitively with surrounding whitespace ignored: `8gb` is 8 GiB
(8589934592 bytes), and `512mb` is 512 MiB. Configuration defaults, quotas and
disk-reserve settings retain their existing byte parsing, where `GB` is decimal
and `GiB` is binary. For example:

```sh
ssh silo create --template devbox --memory 4GiB
ssh silo create ghcr.io/example/dev:latest --name dev --memory 8gb --disk-size 16GiB
ssh silo set dev memory=8gb
```
Connection attempts determine guest readiness; an agent RPC alone does not prove
SSH is reachable. Inspect `show` before retrying a failed or pending operation.

```sh
ssh silo ls
ssh silo stop dev
ssh silo show dev
ssh silo rm dev
```

Removal asks `Remove VM 'dev'? [y/N] ` on stderr, including without `ssh -t`.
Enter `y` or `yes` (case-insensitive, surrounding whitespace ignored) to confirm.
Enter, `n`, `no`, Ctrl-C, EOF or disconnect cancels without changing the VM;
other answers repeat the prompt. Running VMs require `--force` and ask
`Stop and remove VM 'dev'? [y/N] `. For automation use `ssh silo rm dev --yes`.
`--json` selects a single stdout result envelope, not consent; cancellation has
error code `cancelled` and exit 2. `--force` does not skip confirmation.

Removal deletes local VM files and credentials only. Persistent Tailscale device
entries may remain in the admin console, where you can remove them before reusing
an exact node name. Stop/start retains the VM's local Tailscale identity.

`ls` and `show` keep the configured node name visible when stopped. `show` separates
the owner's Tailscale login from the guest username and omits empty labels. Key
expiry displays a date, `Never`, or `Unavailable`; stopped-node expiry is last known.
Use `ops` for operation history.

New VMs provision no account and lobby `shell`/`exec` sessions default to root.
Opt into a nonroot account when creating the VM:

```sh
ssh silo create --name dev --template devbox --tailscale --provision-user nickvd:1000:1000:/home/nickvd
ssh -t silo shell dev
ssh silo exec dev -- id -u
ssh -t silo shell dev -u root
ssh nickvd@dev
```

The home is inside the VM. All four fields are required; a bare flag never infers
your account from the daemon host. Existing VMs keep their recorded default user.
Lobby `-u` selects an existing guest account without provisioning it. Direct SSH
uses the username you request, so specify `root@dev` for a root-default VM.
Operators migrating old configs must remove `vm.guest_user` and opt in per create.

Account environment lookup uses shell builtins and does not require `cat`.
Binary execution also works without `/bin/sh`: root or the stored provisioned
account supplies its default HOME/cwd, while the guest agent validates the
requested execution identity. Other accounts need a working POSIX shell reader
to supply their account environment.

Direct VM sessions use a short-lived per-machine certificate.
Tailnet ACLs still control network access. Published guest-port
hints create no host listener and are not an inbound firewall.

## Expose a guest service over tailnet HTTPS

Network-policy forwards are separate from machine/vsock forwards and guest-port
publish hints. On a dedicated 1:1 netd attachment, `target = "self"` selects that
netd's attached VM. Shared/multi-VM and unknown attachment scopes reject it,
even with only one VM currently attached. Bridge is a topology, not an attachment
scope; named-network launches remain unsupported.

Save this policy as `web-forward.hcl`:

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

Use a template that starts an HTTP service on guest `0.0.0.0:8080` or its
interface IP, not just loopback. The forward does not start the application.
Uploading a policy requires `template.manage`; creation needs `vm.create`
and inspection needs `vm.read`.

```sh
ssh silo policy create web-forward < web-forward.hcl
ssh silo create --name web --template web --policy web-forward --tailscale
ssh silo show web
```

Use fresh names if these resources already exist. Open `https://<full-VM-DNS>/`
using the verified DNS name from `show`. The node's readiness is not a
per-forward health check. A forward-bearing policy requires `--tailscale`,
including when inherited from a template. Remote documents omit `tunnel`:
taild supplies and binds the managed node. User-authored Tailscale declarations,
explicit tunnel references, host forwards, and cross-VM selectors remain
forbidden through the lobby.

Netd terminates TLS and proxies plain HTTP to guest 8080, preserving streaming
and WebSocket upgrades. Enable MagicDNS and HTTPS certificates in the tailnet,
and grant the intended browser peers access to the VM on TCP 443. Certificate
acquisition/renewal uses the embedded node's persisted Tailscale state; no
Tailscale daemon, certificate, or private key is installed in the VM. Public
certificate-transparency logs disclose the node's certificate hostname.

No deny-by-default egress policy is required. HTTPS requires the explicit
`tls.provider = "tailscale"` block; port 443 alone does not enable TLS.
Certificates use the exact node DNS name, not a custom domain or short alias.
Configure the application's public URL and trusted-proxy settings as needed.

For raw TCP, including guest-owned TLS passthrough, use `protocol = "tcp"`
(also the default) and omit `tls`:

```hcl
forward "tailscale" "database" {
  listen      = ":15432"
  target      = "self"
  target_port = 5432
}
```

This maps tailnet 15432 to guest 5432 without interpreting traffic. A TCP
forward on 443 to guest 8443 instead passes TLS through unchanged, leaving
certificates to the guest. Managed HTTPS also works on alternate ports such as
`:9443`, with clients using `https://<full-VM-DNS>:9443/`.

Listeners must be `:<decimal port>` in 1–65535, excluding reserved SSH port 22.
Duplicate listener ports are rejected, regardless of protocol. Configured ports
stay reserved when TLS, enrollment, listener startup, or the backend fails;
they never downgrade to the generic same-port guest relay. Other ports retain
that relay behavior, subject to tailnet grants. Broad existing grants can still
permit direct access to other guest services. No host 443 listener, public
Funnel, UDP forward, arbitrary target, or guest HTTPS upstream is enabled.

The native guest SSH fallback does not implement SFTP or SSH port forwarding.
Use a guest image with OpenSSH for those workflows, and qualify the exact client
and forwarding requests against that image. Images with OpenSSH use that server
when available. Remote commands cannot name host paths, upload arbitrary host
configs, or bypass operator-approved templates/policies.
