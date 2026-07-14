# 10. Static Guest Network Configuration

Date: 2026-07-11

## Status

Accepted

## The Problem

A VM needs an IP address before it can communicate. That address can be
configured statically or obtained dynamically through DHCP.

DHCP requires a server in the network backend and a client in the guest.
Starting the guest client depends on tools provided by its init system, which
adds boot latency and does not work for minimal OCI images where the agent runs
as PID 1.

Silo already knows enough about an attachment before boot to configure it
statically. We need one resolved MAC/IP pair that `netd` reserves, `vmmon` uses
to create the virtual NIC, and `AgentConfig` carries into the guest. This
removes DHCP from the managed guest boot path and makes the expected address
known to the host before the guest starts. That address could later improve
visibility and troubleshooting, but exposing it through `libvm` is outside this
ADR.

## A Networked Boot

The intended launch flow is:

```text
MachineNetworkConfig
  -> libvm prepares an attachment with netd
  -> libvm passes the data socket and MAC to vmmon through --network
  -> libvm adds the static guest settings to AgentConfig.provision.network
  -> ADR 0009 injects AgentConfig into the per-launch initramfs
  -> vmmon attaches the virtual NIC
  -> the agent performs any PID 1 handoff and starts its gRPC service
  -> vmmon connects over host-initiated vsock
  -> loopback and optional static networking run as the first provisioner
```

There is no post-boot configuration exchange in this path. Network settings are
part of the same immutable `AgentConfig` as the other launch-specific guest
inputs.

## Draft Determination

`netd` is the host-side authority for Silo userspace networking. `libvm`
orchestrates attachment setup and receives one resolved attachment containing
the data-plane connection, MAC address, static IPv4 configuration, and DNS
configuration.

For a private network, `libvm` starts a dedicated `netd` process and supplies
the VM attachment through a startup argument. For a named network, `libvm`
registers the attachment through a local attachment-oriented control API owned
by the long-running `netd` process. `netd` allocates named-network addresses and
returns the resolved attachment.

`libvm` sends only the data socket and MAC address to `vmmon` through the
existing `--network` argument. `VmSpec` remains unchanged. Replacing
`--network` with another launch contract is outside this ADR.

`libvm` places the guest-visible address, prefix, gateway, MAC address, and DNS
settings in the optional `AgentConfig.provision.network` section. ADR 0009
carries that configuration into the guest before boot. Host paths and `netd`
control details never enter `AgentConfig`.

The agent brings up loopback and applies any static configuration directly
through Linux networking interfaces as its first provisioner. It does not invoke `systemctl`,
`networkctl`, `ip`, a DHCP client, or distribution-specific scripts. It also
replaces `/etc/resolv.conf` with the configured resolver settings.

Network setup is a boot provisioning operation, not continuous reconciliation.
It runs after any target-init handoff, so target software may already be running
and may later change the interface. Silo does not attempt to continuously
compete with a network manager started by the image.

The first implementation supports one IPv4 attachment. IPv6 and multiple guest
NICs remain future work.

`vznat` cannot provide the resolved attachment needed by this model and does not
support Silo network policy. It is removed, leaving `netd` as the managed
network implementation.

## Responsibilities

| Component | Responsibility |
| --- | --- |
| `libvm` | Resolve durable network selection, orchestrate `netd`, pass the existing `--network` argument, and build `AgentConfig`. |
| `netd` | Validate attachments, allocate named-network addresses, reserve address-to-MAC mappings, and provide VM data sockets. |
| `vmmon` | Attach the virtual NIC using the data socket and MAC supplied through `--network`. |
| Guest agent | Bring up loopback and apply the optional injected static address, route, and DNS configuration as the first provisioner. |

The resolved attachment is an internal `libvm` value. It is broader than the
current `vmmon` network argument because it also carries guest configuration.
`libvm` projects the host connection into `--network` and the guest settings
into `AgentConfig`; neither consumer receives fields it does not need.

## Private Networks

A private network has one VM, one `netd` process, and one attachment. `libvm`
derives the deterministic VM MAC and private IPv4 settings from the machine and
runtime network configuration, then supplies that attachment when starting
`netd`. `netd` validates and reserves the address before reporting readiness.

Private mode does not need a control API because its attachment is fixed for
the process lifetime.

## Named Networks

Named attachment support is a later phase. Until the control API below exists,
`libvm` rejects named-network launches rather than reusing one data socket across
VMs. Named-network definitions remain available for management.

A named network has one `netd` process and may have multiple VM attachments.
Its local control API creates, inspects, and removes attachments. Creating an
attachment allocates or validates an address, reserves the MAC mapping, creates
a VM data socket, and returns the resolved attachment to `libvm`.

Each vfkit-style Unix datagram connection has its own data endpoint. The named
network therefore creates one data socket per VM attachment while sharing the
same internal virtual switch and network services.

The control API is a host-local implementation interface for `libvm`. It is not
part of the `vmmon` API or the guest agent API.

### Possible Named Network API

The named-network control surface will likely use attachment resources similar
to:

```http
POST   /v1/attachments
GET    /v1/attachments
GET    /v1/attachments/{attachment_id}
DELETE /v1/attachments/{attachment_id}
```

A possible create request is:

```json
{
  "attachment_id": "297e4167-primary",
  "vm_id": "297e4167c53b40b99b5b60e5c3f7da95",
  "mac": "02:29:7e:41:67:c5",
  "ipv4": null
}
```

When `ipv4` is absent, `netd` allocates an address. A possible response is:

```json
{
  "attachment_id": "297e4167-primary",
  "data_socket": "/run/silo/net/devnet/attachments/297e4167-primary.sock",
  "network": {
    "mac_address": "02:29:7e:41:67:c5",
    "ipv4": {
      "address": "192.168.105.42",
      "prefix_length": 24,
      "gateway": "192.168.105.1"
    },
    "dns": {
      "servers": ["192.168.105.1"],
      "search": []
    }
  }
}
```

This is a non-normative sketch. The API is host-local, `libvm` is its intended
client, and each attachment receives its own data socket. Exact idempotency,
limits, errors, persistence, and restart behavior remain open.

## Agent Network Configuration

The network provisioner is always part of enabled guest provisioning and runs
before hostname, user, mount, and userdata provisioning. It brings up loopback
whether or not static networking is configured. Disabling provisioning skips
both loopback and static network setup.

The initial shape is:

```json
{
  "provision": {
    "enabled": true,
    "network": {
      "interfaces": [
        {
          "mac_address": "02:29:7e:41:67:c5",
          "ipv4": {
            "address": "192.168.105.2",
            "prefix_length": 24,
            "gateway": "192.168.105.1"
          },
          "dns": {
            "servers": ["192.168.105.1"],
            "search": []
          }
        }
      ]
    }
  }
}
```

If `provision.network` is absent, the network provisioner only brings up
loopback and leaves non-loopback links, routes, and `/etc/resolv.conf`
untouched. This is the normal shape for a machine started without a network
attachment. The first implementation accepts exactly one static interface,
identifies it by MAC address, and configures IPv4. Host socket paths, attachment
identifiers, network drivers, image-dependent interface names, and DHCP flags
are not guest configuration and do not appear here.

The exact validation bounds, schema evolution rules, and error vocabulary are
not settled by this draft.

## Guest Setup

When provisioning is enabled, the agent performs the following network work as
its first provisioner:

1. Bring the loopback link up. Linux installs its loopback addresses as part of
   the link transition.
2. If static network configuration is absent, finish the provisioner.
3. Find the interface with the configured MAC address.
4. Bring the static interface link up.
5. Apply the IPv4 address and prefix.
6. Install the default route through the configured gateway.
7. Replace `/etc/resolv.conf` with the configured DNS values.

The agent uses `rtnetlink` to talk to the Linux kernel directly for link,
address, and route configuration. This keeps the boot contract independent from
the tools and init system available in the image.

Resolver configuration is written to a temporary file and atomically renamed
over `/etc/resolv.conf`. This replaces an existing symlink rather than changing
its target. A read-only or otherwise non-replaceable resolver path fails the
network provisioner.

The provisioner does not attempt to roll back partial kernel changes. Any link,
address, route, or resolver error uses the `FailBoot` policy, reports the failed
step to vmmon, and prevents the managed boot from reporting ready.

## netd Cleanup

The existing upstream defaults are not part of the new attachment model. `netd`
removes its implicit SSH forwarding, the associated `--ssh-port` option, and the
static lease for the upstream default guest MAC. Managed address-to-MAC
reservations come only from explicit attachments.

Persisted named-network `vznat` preferences are migrated to `netd`. Obsolete
`vznat` runtime records are removed with their attachment rows through the
existing foreign-key cascade.

## Consequences

### Benefits

- Guests receive a deterministic address during managed provisioning.
- Boot does not depend on DHCP clients or distribution-specific network tools.
- The host knows the expected guest address before boot.
- Private networks produce a resolved attachment shape that named networks can
  adopt when their control API is implemented.
- `vmmon` keeps its existing narrow network boundary.
- Guest configuration remains an immutable launch input under ADR 0009.
- Plain OCI images can have networking without distribution-specific tools.

### Tradeoffs

- The guest agent takes responsibility for low-level Linux network setup.
- Replacing `/etc/resolv.conf` may override conventions expected by an image.
- Target init and its network manager may start before static provisioning runs.
- Disabling provisioning also disables managed loopback and static networking.
- A network manager started later by the image may replace the injected state.
- Named networks require a new local control surface and attachment lifecycle.
- Removing `vznat` removes a backend that is convenient but too opaque for this
  contract.

## Alternatives Considered

### Continue Using DHCP

DHCP keeps address configuration out of the agent, but requires a working
client and init integration in every image. It does not serve agent-as-PID-1
images and makes early networking depend on guest user space we do not control.

### Generate Init-System Configuration

Writing systemd-networkd, NetworkManager, or sysvinit configuration can work for
known distributions, but creates one backend per guest environment and still
does not cover minimal images. Direct kernel configuration gives the boot path
one Linux interface.

### Fetch Configuration After Boot

A runtime configuration service introduces startup ordering and availability
dependencies for information already known before launch. ADR 0009 provides the
immutable delivery path we need.

### Put Attachments In VmSpec

`vmmon` only needs the data socket and MAC address already carried by
`--network`. Adding guest address and DNS settings to `VmSpec` would widen that
contract without a current consumer.

## Open Questions

The following extensions remain unresolved:

- Named-network API idempotency, limits, errors, persistence, and recovery.
- Named-network address allocation and per-attachment data sockets.
- Restart recovery for persisted private attachments.
- IPv6 and multiple guest interfaces.

## References

- [ADR 0006: Sandbox Network Policy and Firewall Semantics](0006-sandbox-network-policy-and-firewall-semantics.md)
- [ADR 0008: Vmmon Host and Guest Agent gRPC APIs](0008-vmmon-host-and-guest-grpc-api.md)
- [ADR 0009: Per-Launch Guest Agent Initramfs Overlay](0009-per-launch-guest-agent-initramfs-overlay.md)
- [Linux rtnetlink](https://man7.org/linux/man-pages/man7/rtnetlink.7.html)
- [Linux resolver configuration](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)
