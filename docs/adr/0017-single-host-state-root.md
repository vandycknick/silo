# 17. Single Host State Root

Date: 2026-09-24

## Status

Accepted

Supersedes the "On-disk Layout" section of
[ADR 0004](0004-daemonless-architecture.md) and the XDG ownership table and
run-root order of [ADR 0012](0012-cross-platform-runtime-and-sdk-packaging.md).

## The Problem

Silo spread its host state across four XDG bases: machine data under
`$XDG_DATA_HOME/silo`, logs under `$XDG_STATE_HOME/silo`, sockets under
`$XDG_RUNTIME_DIR/silo`, SDK caches under `$XDG_CACHE_HOME/silo`, plus the
Docker socket under `~/.docker/run`. Each frontend resolved some of these on
its own: the CLI had separate resolvers for config, secrets, daemon records and
the service definition, the Go SDK resolved its runtime and cache directories
independently, and the state database pinned the data, state and image roots it
was created with.

The result was hard to explain, easy to get subtly wrong (a service started
without the shell's XDG environment looked for a different database), and made
a future sandbox for the VM monitor harder, because its allowed paths depended
on four environment variables.

## Decision

All persistent Silo state lives under one directory, the **Silo home**:

- `SILO_HOME` when set. It must be absolute; a relative value is rejected.
- Otherwise `$HOME/.silo`. `HOME` must be absolute.

Generated runtime state (per-machine and per-network sockets, pidfiles, locks)
lives under a fixed **run root**, `/tmp/silo-<euid>`, created with mode 0700 and
checked for ownership and against symlinks, exactly as before.

Configuration is the one exception to the single root. The config directory is
`$XDG_CONFIG_HOME/silo` (default `~/.config/silo`) and holds `config.yaml`,
`templates/` and network policy files. `~/.silo/config.yaml` is a fallback read
only when `<config dir>/config.yaml` does not exist; new configuration is
written to the config directory.

No other XDG variable is consulted. `$XDG_CONFIG_HOME` is read only by the
config resolver and to place the systemd user unit
(`${XDG_CONFIG_HOME:-~/.config}/systemd/user/`).

## Layout

```text
$XDG_CONFIG_HOME/silo/     config.yaml, templates/, network policies
~/.silo/                   (SILO_HOME)
  config.yaml              fallback config file
  state.db
  machines/<id>/           config.json, rootfs.img, initramfs, metadata.json, apple-machine-id
  logs/machines/<id>/      vm.trace.log, serial.log, exec.log[.1-3], vm.exit.json, network/
  logs/daemon/             daemon.log, native.log
  images/                  unpacked OCI rootfs artifacts
  keys/                    SSH keys
  secrets.json
  daemon/                  system daemon record, locks, status, data image
  runtimes/                runtimes installed by the Go SDK
  cache/                   SDK caches (cache/go-ffi)
  run/                     fixed-name control sockets only (0700)
    docker.sock            system daemon Docker endpoint
/tmp/silo-<euid>/          run root (0700, owner-checked, no symlinks)
  machines/<id>/           vm.pid, vm.sock, vm.lock, vsock.sock, vsock.sock_<port>
  networks/<nid>/          netd.sock, netd.pid, network-policy.json, capture.pcap, <id12>-krun.sock
  locks/
```

## Why Generated Sockets Stay In `/tmp`

Unix socket paths are limited by `sun_path`: 104 bytes on macOS and 108 on
Linux. The run root holds sockets whose names Silo generates from machine and
network identifiers. Under `/tmp/silo-<euid>` their length is bounded by
construction, and the existing unit test proves it. Under `~/.silo/run` the
length would grow with the user's account name or with `SILO_HOME`, and a long
enough home would make machines fail to start in ways a user cannot fix.

`~/.silo/run/` therefore holds only sockets with a fixed, short name whose
parent path Silo controls. Today that is `docker.sock`, which replaces
`~/.docker/run/silo.sock`.

## Ownership

| Component | Responsibility |
| --- | --- |
| libvm `paths` | Resolves the home (`SILO_HOME`, else `~/.silo`) and the run root; creates and validates the run root; derives every machine, network, log and image path. |
| libvm `HostPaths` | The single public resolver for frontends: home, config directory, config file, control socket directory, run root. |
| libvm store | Opens `<home>/state.db`. The `db_config` row records only the host OS that created the database; no paths are stored. |
| CLI | Resolves config, templates, secrets, daemon records, logs and the service definition through `HostPaths`. The native service records the resolved config directory and home because it runs without the shell's environment. |
| silo-vmm | Receives every path it uses as an argument or descriptor from libvm; it resolves nothing itself. |
| Go SDK | Installs runtimes under `<home>/runtimes` and caches its bridge under `<home>/cache/go-ffi`, honoring `SILO_HOME`. |

Programmatic callers pick a different home with `RuntimeConfig::local(home)`,
`RuntimeBuilder::home`, the Node `home` option or Go `WithHome`. The run root
has no override.

## Hard Break

This is a hard break, consistent with ADR 0012's existing stance that old
layouts are unsupported. Silo does not read, migrate, or detect an existing XDG
data or state layout, and the state database schema was reset rather than
migrated. A host that used the old layout starts with an empty `~/.silo`.

## Consequences

- One variable, `SILO_HOME`, isolates a complete Silo installation, which is
  what tests, SDK embedders and a second user profile need.
- A future sandbox for the VM monitor can be expressed as a small, stable set of
  directories under the home and the run root.
- The state database no longer rejects being opened at a different path, since
  it no longer pins roots; the home is the identity.
- Configuration still follows the XDG convention users expect for dotfiles
  management, at the cost of one documented exception to "everything under the
  home".

## Alternatives Considered

### Keep the XDG split

Standard on Linux and familiar, but it scatters one installation across four
bases, multiplies resolvers, and is unusual on macOS. The benefit did not
justify the cost for a tool whose state is one database plus machine
directories.

### Put everything, including sockets, under `~/.silo`

Simplest to describe, but it ties socket path length to the home path. That
turns long account names and deep `SILO_HOME` values into start failures.

### Move configuration into `~/.silo` as well

Rejected for the primary location because users keep configuration in managed
dotfiles under `~/.config`. The fallback keeps a single-directory setup possible
for people who want it.
