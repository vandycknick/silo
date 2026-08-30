# libkrun Implicit Behaviors

Silo treats the `krun` helper as an explicit VM launcher. Libkrun v2 contexts start without implicit console or vsock devices and no longer inject a default init binary. Silo adds only the devices required by its configuration.

## Runtime Defaults

Every helper-created context does the following:

1. Set the VM CPU and memory configuration.
2. Set the explicit kernel, optional initramfs, and kernel command line.
3. Add disks, mounts, networking, and console only when configured, plus vmmon's unconditional vhost-user-vsock device.

The v1 `krun_disable_implicit_console()` and `krun_disable_implicit_vsock()` APIs do not exist in v2 because those devices are explicit. `krun_disable_implicit_init()` remains only as an `-ENOTSUP` compatibility stub and must not be called. If a console is needed, the helper adds one explicitly with `krun_add_virtio_console_default()` and selects `hvc0` with `krun_set_kernel_console()`. Vmmon passes one vhost-user socket to the helper, which attaches device type 19 with three queues. The helper never calls `krun_add_vsock` or configures per-port mappings; vmmon's embedded backend handles arbitrary host and guest ports dynamically.

`krun_set_port_map()` is intentionally not part of Silo's startup path. It controls TSI stream remapping, not explicit virtio-net backends or Silo's vhost-user-vsock device.

## Inventory

| Behavior | Trigger | Default libkrun behavior | Silo behavior | Platform notes |
| --- | --- | --- | --- | --- |
| Console device | Call `krun_add_virtio_console_default()` | No console device | Added only for `--stdio-console`, then selected as `hvc0` | Applies on Linux and macOS |
| Init binary | Load and apply `libkrun_init` configuration | No injected init binary | Not used; Silo supplies an explicit kernel and optional initramfs | `krun_disable_implicit_init()` returns `-ENOTSUP` in v2 |
| Vsock device | Attach a vhost-user device | No vsock device | Device type 19, three queues, terminated by vmmon's embedded backend | Unconditional for internal ports; public enablement controls only the host surface |
| TSI networking | Enable TSI flags on libkrun's built-in vsock device | No TSI fallback | Not used; Silo attaches vhost-user-vsock and explicit virtio-net | Applies on Linux and macOS |
| TSI port remapping | Use TSI stream listens through libkrun's vsock path | May rewrite guest listen ports according to a libkrun port map | Not used; TSI is disabled and explicit virtio-net backends do not consume this map | Applies only to libkrun's vsock/TSI stream path |
| Environment inheritance | Call `krun_set_exec()` or `krun_set_env()` with `NULL` | Inherits host process environment | Current helper does not use exec-mode APIs; future exec-mode code must pass an explicit env array | Applies on Linux and macOS |
| Unixgram networking | Call `krun_add_net_unixgram()` | Adds explicit virtio-net and prevents TSI fallback | Available via `--network unixgram` with `--net-peer` and `--net-mac` | Current Silo gvproxy path |
| Unixstream networking | Call `krun_add_net_unixstream()` | Adds explicit virtio-net and prevents TSI fallback | Available via `--network unixstream` with `--net-peer` and `--net-mac` | Suitable for passt/socket_vmnet-style peers |
| TAP networking | Call `krun_add_net_tap()` | Adds explicit virtio-net and prevents TSI fallback | Available via `--network tap` with `--net-tap-name` and `--net-mac` | Linux only |

## Networking Modes

`--network none` means no guest network device. It is the default and must not fall back to TSI.

`--network unixgram` connects a virtio-net device to a datagram Unix socket peer. The helper creates its local datagram socket next to the peer and passes the connected fd to libkrun.

`--network unixstream` connects a virtio-net device to a stream Unix socket path. The helper passes the path directly to libkrun.

`--network tap` connects a virtio-net device to an existing TAP interface by name. Validation rejects this mode on non-Linux hosts.

## Historical Port Map Evidence

The `krun_set_port_map()` API accepts `host_port:guest_port` strings, stores them as `guest_port -> host_port`, and fails with `EINVAL` if any explicit virtio-net device has already been configured. In libkrun 1.18.1 this is enforced by `ContextConfig::set_port_map()` checking `net_index != 0`; `create_virtio_net()` increments that index for `krun_add_net_unixgram()`, `krun_add_net_unixstream()`, and `krun_add_net_tap()`.

The stored map is copied into `VsockDeviceConfig.host_port_map`, then into the vsock muxer, and is read by `TsiStreamProxy::try_listen()` when handling TSI stream listen requests. It is not read by the explicit virtio-net unixgram, unixstream, or tap backends. This means an empty port map is not a useful explicit-net hardening step for Silo; it is a TSI/vsock knob, and Silo already disables that path.

Source references for the historical v1 behavior:

1. [`krun_set_port_map()`](https://github.com/containers/libkrun/blob/v1.18.1/src/libkrun/src/lib.rs#L1202-L1245), [`ContextConfig::set_port_map()`](https://github.com/containers/libkrun/blob/v1.18.1/src/libkrun/src/lib.rs#L290-L296), and [`create_virtio_net()`](https://github.com/containers/libkrun/blob/v1.18.1/src/libkrun/src/lib.rs#L2000-L2016).
2. [`VsockDeviceConfig.host_port_map`](https://github.com/containers/libkrun/blob/v1.18.1/src/vmm/src/vmm_config/vsock.rs#L34-L45) and its config conversion path.
3. [`VsockMuxer::process_listen_request()`](https://github.com/containers/libkrun/blob/v1.18.1/src/devices/src/virtio/vsock/muxer.rs#L424-L437), which passes the map to the TSI stream proxy.
4. [`TsiStreamProxy::try_listen()`](https://github.com/containers/libkrun/blob/v1.18.1/src/devices/src/virtio/vsock/tsi_stream.rs#L197-L220) and the port rewrite lookup in [`process_listen_request()`](https://github.com/containers/libkrun/blob/v1.18.1/src/devices/src/virtio/vsock/tsi_stream.rs#L641-L659).

## Parent Liveness

The parent process passes the helper a watchdog pipe read fd in `SILO_KRUN_WATCHDOG_FD` and holds the write fd for the VM lifetime. If the parent dies, the write fd closes, the helper observes `POLLHUP`, and exits. This avoids orphaned helper processes without relying on Linux-only `PR_SET_PDEATHSIG`.
