# 10. Static Guest Network Configuration

Date: 2026-07-11

## Status

Draft

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
  -> libvm adds the static guest settings to AgentConfig
  -> ADR 0009 injects AgentConfig into the per-launch initramfs
  -> vmmon attaches the virtual NIC
  -> the agent configures the interface before init handoff
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
settings in a dedicated network section of `AgentConfig`. ADR 0009 carries that
configuration into the guest before boot. Host paths and `netd` control details
never enter `AgentConfig`.

The agent applies the static configuration directly through Linux networking
interfaces before target-init handoff. It does not invoke `systemctl`,
`networkctl`, `ip`, a DHCP client, or distribution-specific scripts. It also
replaces `/etc/resolv.conf` with the configured resolver settings.

Network setup is an early-boot operation, not continuous reconciliation. Once
the agent hands off to the target init system, later guest software may change
the interface. Silo does not attempt to compete with a network manager started
by the image.

The first implementation supports one IPv4 attachment. IPv6 and multiple guest
NICs remain future work.

`vznat` cannot provide the resolved attachment needed by this model and does not
support Silo network policy. It will be removed, leaving `netd` as the managed
network implementation.

## Responsibilities

| Component | Responsibility |
| --- | --- |
| `libvm` | Resolve durable network selection, orchestrate `netd`, pass the existing `--network` argument, and build `AgentConfig`. |
| `netd` | Validate attachments, allocate named-network addresses, reserve address-to-MAC mappings, and provide VM data sockets. |
| `vmmon` | Attach the virtual NIC using the data socket and MAC supplied through `--network`. |
| Guest agent | Apply the injected static address, route, and DNS configuration before init handoff. |

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

The network section of `AgentConfig` is independent from general guest
provisioning. Disabling hostname, user, mount, or userdata provisioning must not
disable required early network setup.

The initial shape is:

```json
{
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
```

`network` is a top-level section. If it is absent, the agent leaves guest
networking untouched. The first implementation accepts exactly one interface,
identifies it by MAC address, and configures static IPv4. Host socket paths,
attachment identifiers, network drivers, image-dependent interface names, and
DHCP flags are not guest configuration and do not appear here.

The exact validation bounds, schema evolution rules, and error vocabulary are
not settled by this draft.

## Guest Setup

When static network configuration is present, the agent performs the following
work before target-init handoff:

1. Find the interface with the configured MAC address.
2. Bring the link up.
3. Apply the IPv4 address and prefix.
4. Install the default route through the configured gateway.
5. Replace `/etc/resolv.conf` with the configured DNS values.

The agent talks to the Linux kernel directly for link, address, and route
configuration. This keeps the boot contract independent from the tools and init
system available in the image.

The detailed replacement and rollback behavior remains open. At minimum, a
managed boot must not report ready when required static network setup failed.

## netd Cleanup

The existing upstream defaults are not part of the new attachment model. `netd`
will remove its implicit SSH forwarding, the associated `--ssh-port` option,
and the static lease for the upstream default guest MAC. Managed address-to-MAC
reservations will come only from explicit attachments.

The exact persistence migration and removal sequence for existing `vznat`
definitions and runtime records remains implementation work.

## Consequences

### Benefits

- Guests have an address before their target init system starts.
- Boot does not depend on DHCP clients or distribution-specific network tools.
- The host knows the expected guest address before boot.
- Private and named networks produce one conceptual attachment shape.
- `vmmon` keeps its existing narrow network boundary.
- Guest configuration remains an immutable launch input under ADR 0009.
- Plain OCI images can have networking while the agent remains PID 1.

### Tradeoffs

- The guest agent takes responsibility for low-level Linux network setup.
- Replacing `/etc/resolv.conf` may override conventions expected by an image.
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

This draft intentionally leaves these details unresolved:

- `AgentConfig` validation bounds, schema evolution, and error reporting.
- Named-network API idempotency, limits, errors, persistence, and recovery.
- Private and named address allocation details.
- Attachment persistence, restart recovery, and rollback behavior.
- The Linux rtnetlink implementation and supporting Rust API.
- Resolver replacement behavior for symlinks and read-only roots.
- Migration behavior for existing `vznat` configuration.
- IPv6 and multiple guest interfaces.

## References

- [ADR 0006: Sandbox Network Policy and Firewall Semantics](0006-sandbox-network-policy-and-firewall-semantics.md)
- [ADR 0008: Vmmon Host and Guest Agent HTTP APIs](0008-vmmon-host-and-guest-http-api.md)
- [ADR 0009: Per-Launch Guest Agent Initramfs Overlay](0009-per-launch-guest-agent-initramfs-overlay.md)
- [Linux rtnetlink](https://man7.org/linux/man-pages/man7/rtnetlink.7.html)
- [Linux resolver configuration](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)
