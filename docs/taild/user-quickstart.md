# Taild user quick start

Your operator grants the lobby capability and supplies approved templates and
policies. Connect using your tailnet identity, not a host account or an SSH key.

```sh
ssh silo
ssh silo help
ssh silo template ls
ssh silo policy ls
ssh silo create dev --template devbox
ssh silo show dev
ssh silo start dev
ssh root@dev
```

Follow the returned consent link when enrollment is pending. It is short-lived and
one-use. `dev` is the exact requested DNS/name, never an owner-prefixed alias.
If anyone already owns that name locally or on the tailnet, create fails; choose
another name. Only your own VMs are visible and manageable under v1 `own` scope.
Connection attempts determine guest readiness; an agent RPC alone does not prove
SSH is reachable. Inspect `show` before retrying a failed or pending operation.

```sh
ssh silo ls
ssh silo stop dev
ssh silo reauth dev
ssh silo rm dev
```

New VMs provision no account and lobby `shell`/`exec` sessions default to root.
Opt into a nonroot account when creating the VM:

```sh
ssh silo create dev --template devbox --provision-user nickvd:1000:1000:/home/nickvd
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
