# libkrun Implicit Behaviors

Silo treats the `krun` helper as an explicit VM launcher. At the pinned native Rust API revision, `VmmBuilder` starts without implicit console, vsock, balloon, or RNG devices and does not inject a default init binary. Silo adds every required device explicitly.

## Runtime Defaults

Every helper-created VMM does the following:

1. Set the VM CPU and memory configuration.
2. Set the explicit kernel, optional initramfs, and kernel command line.
3. Add console, disks, mounts, the native vsock control-channel device, and networking when configured, in that deterministic order.
4. Add explicit RNG and balloon devices. Host memory release remains disabled unless the separate reclaim policy and startup qualification enable it.

The helper does not use the compatibility C API. If a console is needed, it builds `ConsoleDevice::builder().add_default_console(...)` with borrowed stdio descriptors and selects `hvc0` on `VmmBuilder`. On Linux and macOS, vmmon passes one inherited Unix stream descriptor to the helper, which constructs a native `VsockDevice` with CID 3 and empty TSI flags, then gives the descriptor to libkrun's control-channel mux. Per-connection descriptors cross that private channel with `SCM_RIGHTS`; stream payloads do not. The helper configures no per-port mappings and the transport binds no filesystem path.

The historical `krun_set_port_map()` API is intentionally not part of Silo's startup path. It controls TSI stream remapping, not explicit virtio-net backends or Silo's native control-channel vsock device.

## Inventory

| Behavior | Trigger | Default libkrun behavior | Silo behavior | Platform notes |
| --- | --- | --- | --- | --- |
| Console device | Add `ConsoleDevice` | No console device | Added only for `--stdio-console`, then selected as `hvc0` | Applies on Linux and macOS |
| Init binary | Select a payload | No injected init binary | Silo loads an external kernel and optional initramfs | Applies on Linux and macOS |
| Vsock device | Add `VsockDevice` | No vsock device | Native CID 3 device with TSI disabled and an inherited control-channel fd | Same default krun implementation on Linux and macOS; VZ is an explicit macOS override |
| RNG device | Add `RngDevice` | No RNG device | Always added explicitly | Applies on Linux and macOS |
| Balloon device | Add `BalloonDevice` | No balloon device | Added explicitly; host reclaim is configured independently and remains qualification-gated | Applies on Linux and macOS |
| TSI networking | Enable TSI flags on libkrun's built-in vsock device | No TSI fallback | Not used; the native vsock device has empty TSI flags and configured hosts may add explicit virtio-net | Applies on Linux and macOS |
| TSI port remapping | Use TSI stream listens through libkrun's vsock path | May rewrite guest listen ports according to a libkrun port map | Not used; TSI is disabled and explicit virtio-net backends do not consume this map | Applies only to libkrun's vsock/TSI stream path |
| Exec-mode environment | Use the compatibility C exec APIs | Not exposed by the native `VmmBuilder` API | Not used; Silo direct-boots its kernel and initramfs | Applies on Linux and macOS |
| Unixgram networking | Add `NetDevice::new_unixgram_fd()` | No network device | Available via `--network unixgram` with `--net-peer` and `--net-mac` | Current Silo gvproxy path; the fd is owned by libkrun |
| Unixstream networking | Add `NetDevice::new_unixstream_path()` | No network device | Available via `--network unixstream` with `--net-peer` and `--net-mac` | Suitable for passt/socket_vmnet-style peers |
| TAP networking | Add `NetDevice::new_tap()` | No network device | Available via `--network tap` with `--net-tap-name` and `--net-mac` | Linux only |

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
