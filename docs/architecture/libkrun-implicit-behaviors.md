# libkrun Implicit Behaviors

BentoBox treats the `krun` helper as an explicit VM launcher. A missing libkrun API call must not silently create host integration, guest devices, inherited environment, or host port exposure.

## Runtime Defaults

Every helper-created context must do the following before adding optional devices:

1. Call `krun_disable_implicit_console()`.
2. Call `krun_disable_implicit_vsock()`.
3. Add networking only when `--network` is not `none`.

If a console is needed, the helper adds one explicitly with `krun_add_virtio_console_default()` and sets `console=hvc0`. If vsock ports are configured, the helper adds one explicit vsock device with `krun_add_vsock(ctx, 0)`, keeping TSI hijacking disabled.

`krun_set_port_map()` is intentionally not part of BentoBox's startup path. In libkrun 1.18.1 the port map is stored on the vsock configuration and consumed by the TSI stream listen path, not by explicit virtio-net backends. The implementation also rejects `krun_set_port_map()` after an explicit net device has been added because `create_virtio_net()` increments `net_index` and `ContextConfig::set_port_map()` returns `EINVAL` when `net_index != 0`. BentoBox disables implicit vsock and uses explicit virtio-net, so the port-map API is both unnecessary and invalid for the normal gVisor/unixgram path.

## Inventory

| Behavior | Trigger | Default libkrun behavior | BentoBox behavior | Platform notes |
| --- | --- | --- | --- | --- |
| Console device | Omit `krun_disable_implicit_console()` | Creates a console automatically | Always disabled, then explicitly added only for `--stdio-console` | Applies on Linux and macOS |
| Vsock device | Omit `krun_disable_implicit_vsock()` | Creates a vsock device automatically, with TSI selected heuristically | Always disabled, then explicitly added with TSI features `0` when vsock ports exist | Applies on Linux and macOS |
| TSI networking | Add no virtio-net device and leave implicit vsock enabled | Falls back to Transparent Socket Impersonation | Disabled by disabling implicit vsock and never enabling TSI features | Applies on Linux and macOS |
| TSI port remapping | Use TSI stream listens through libkrun's vsock path | May rewrite guest listen ports according to a libkrun port map | Not used; TSI is disabled and explicit virtio-net backends do not consume this map | Applies only to libkrun's vsock/TSI stream path |
| Environment inheritance | Call `krun_set_exec()` or `krun_set_env()` with `NULL` | Inherits host process environment | Current helper does not use exec-mode APIs; future exec-mode code must pass an explicit env array | Applies on Linux and macOS |
| Unixgram networking | Call `krun_add_net_unixgram()` | Adds explicit virtio-net and prevents TSI fallback | Available via `--network unixgram` with `--net-peer` and `--net-mac` | Current BentoBox gvproxy path |
| Unixstream networking | Call `krun_add_net_unixstream()` | Adds explicit virtio-net and prevents TSI fallback | Available via `--network unixstream` with `--net-peer` and `--net-mac` | Suitable for passt/socket_vmnet-style peers |
| TAP networking | Call `krun_add_net_tap()` | Adds explicit virtio-net and prevents TSI fallback | Available via `--network tap` with `--net-tap-name` and `--net-mac` | Linux only |

## Networking Modes

`--network none` means no guest network device. It is the default and must not fall back to TSI.

`--network unixgram` connects a virtio-net device to a datagram Unix socket peer. The helper creates its local datagram socket next to the peer and passes the connected fd to libkrun.

`--network unixstream` connects a virtio-net device to a stream Unix socket path. The helper passes the path directly to libkrun.

`--network tap` connects a virtio-net device to an existing TAP interface by name. Validation rejects this mode on non-Linux hosts.

## libkrun 1.18.1 Port Map Evidence

The `krun_set_port_map()` API accepts `host_port:guest_port` strings, stores them as `guest_port -> host_port`, and fails with `EINVAL` if any explicit virtio-net device has already been configured. In libkrun 1.18.1 this is enforced by `ContextConfig::set_port_map()` checking `net_index != 0`; `create_virtio_net()` increments that index for `krun_add_net_unixgram()`, `krun_add_net_unixstream()`, and `krun_add_net_tap()`.

The stored map is copied into `VsockDeviceConfig.host_port_map`, then into the vsock muxer, and is read by `TsiStreamProxy::try_listen()` when handling TSI stream listen requests. It is not read by the explicit virtio-net unixgram, unixstream, or tap backends. This means an empty port map is not a useful explicit-net hardening step for BentoBox; it is a TSI/vsock knob, and BentoBox already disables that path.

Source references for the pinned version:

1. [`krun_set_port_map()`](https://github.com/containers/libkrun/blob/v1.18.1/src/libkrun/src/lib.rs#L1202-L1245), [`ContextConfig::set_port_map()`](https://github.com/containers/libkrun/blob/v1.18.1/src/libkrun/src/lib.rs#L290-L296), and [`create_virtio_net()`](https://github.com/containers/libkrun/blob/v1.18.1/src/libkrun/src/lib.rs#L2000-L2016).
2. [`VsockDeviceConfig.host_port_map`](https://github.com/containers/libkrun/blob/v1.18.1/src/vmm/src/vmm_config/vsock.rs#L34-L45) and its config conversion path.
3. [`VsockMuxer::process_listen_request()`](https://github.com/containers/libkrun/blob/v1.18.1/src/devices/src/virtio/vsock/muxer.rs#L424-L437), which passes the map to the TSI stream proxy.
4. [`TsiStreamProxy::try_listen()`](https://github.com/containers/libkrun/blob/v1.18.1/src/devices/src/virtio/vsock/tsi_stream.rs#L197-L220) and the port rewrite lookup in [`process_listen_request()`](https://github.com/containers/libkrun/blob/v1.18.1/src/devices/src/virtio/vsock/tsi_stream.rs#L641-L659).

## Parent Liveness

The parent process passes the helper a watchdog pipe read fd in `BENTO_KRUN_WATCHDOG_FD` and holds the write fd for the VM lifetime. If the parent dies, the write fd closes, the helper observes `POLLHUP`, and exits. This avoids orphaned helper processes without relying on Linux-only `PR_SET_PDEATHSIG`.
