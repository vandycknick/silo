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
ssh silo start dev
ssh root@dev
```

Follow the returned consent link when enrollment is pending. It is short-lived and
one-use. `dev` is the exact requested DNS/name, never an owner-prefixed alias.
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
compatibility alias, but cannot be combined with positional IMAGE. Without an
image, the template then configured image applies. Create starts the VM by
default; `--no-start` leaves it stopped.

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
ssh silo reauth dev
ssh silo rm dev
```

Removal asks `Remove VM 'dev'? [y/N] ` on stderr, including without `ssh -t`.
Enter `y` or `yes` (case-insensitive, surrounding whitespace ignored) to confirm.
Enter, `n`, `no`, Ctrl-C, EOF or disconnect cancels without changing the VM;
other answers repeat the prompt. Running VMs require `--force` and ask
`Stop and remove VM 'dev'? [y/N] `. For automation use `ssh silo rm dev --yes`.
`--json` selects a single stdout result envelope, not consent; cancellation has
error code `cancelled` and exit 2. `--force` does not skip confirmation.

New VMs provision no account and lobby `shell`/`exec` sessions default to root.
Opt into a nonroot account when creating the VM:

```sh
ssh silo create --name dev --template devbox --provision-user nickvd:1000:1000:/home/nickvd
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

The native guest SSH fallback does not implement SFTP or SSH port forwarding.
Use a guest image with OpenSSH for those workflows, and qualify the exact client
and forwarding requests against that image. Images with OpenSSH use that server
when available. Remote commands cannot name host paths, upload arbitrary host
configs, or bypass operator-approved templates/policies.
