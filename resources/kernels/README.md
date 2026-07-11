# Kernel Resources

This directory owns the guest kernel build inputs for Silo.

## Supported tracks

- `stable`: `6.19.7`
- `longterm`: `6.18.17`
- `longterm5`: `5.15.202`

Build with:

```bash
silo exec arch -- make kernel TRACK=stable ARCH=arm64
silo exec arch -- make kernel TRACK=longterm ARCH=arm64
silo exec arch -- make kernel TRACK=longterm5 ARCH=arm64
```

Kernel source, build, and cache state live inside the guest under `$HOME/.cache/silo/kernels/`.

Final exported artifacts land in the mounted repo under `target/kernels/<track>-<arch>-<version>/`.

The canonical arm64 config baseline lives at `resources/kernels/configs/arm64-base.config`. Track-specific config drift lives in `resources/kernels/configs/overlays/<track>.config`, which gets appended before `olddefconfig` runs. The `manifest.toml` file records the current manually pinned track versions.

# Kernel config changes from the VM bring-up session

This file tracks kernel-side config changes identified while debugging package updates, DNS/TLS time issues, and VM boot behavior.

## 1) Core VM runtime filesystem and device node support

### Required config changes

- `CONFIG_MEMFD_CREATE=y`
- `CONFIG_DEVTMPFS=y`
- `CONFIG_DEVTMPFS_MOUNT=y`
- `CONFIG_STANDALONE=y`
- `CONFIG_PREVENT_FIRMWARE_BUILD=y`
- `CONFIG_TMPFS=y`
- `CONFIG_TMPFS_POSIX_ACL=y`
- `CONFIG_TMPFS_XATTR=y`
- `CONFIG_TMPFS_QUOTA=y`

### What this enables

- Anonymous in-memory file descriptors via `memfd`.
- Automatic population of `/dev` via devtmpfs.
- Tmpfs-backed runtime filesystems with ACL/xattr/quota support.

### Why this is needed

- Supports modern userspace and service manager expectations during VM boot.
- Avoids missing device-node and runtime-filesystem issues in minimal images.

## 2) PCI host controller support for virtualized device enumeration

### Required config changes

- `CONFIG_PCI_ECAM=y`
- `CONFIG_PCI_HOST_COMMON=y`
- `CONFIG_PCI_HOST_GENERIC=y`

### What this enables

- Generic ECAM-based PCI configuration space access.
- Generic PCI host bridge initialization on arm64 virtual platforms.
- PCI bus discovery and enumeration for virtual devices presented by the hypervisor.

### Why this is needed

- In Linux guests on Apple `Virtualization.framework`, many paravirtualized devices are exposed through a PCI topology.
- The guest kernel must initialize the virtual PCI host bridge and scan buses, otherwise devices can fail to appear even when their functional drivers are enabled.
- Enabling the ECAM and generic host-controller path provides a portable baseline for VM device discovery across common `Virtualization.framework` Linux guest configurations.

## 3) Cgroup v2 and file event support for modern userspace

### Required config changes

- `CONFIG_CGROUPS=y`
- `CONFIG_INOTIFY_USER=y`

### What this enables

- Unified cgroup v2 hierarchy mounting and management.
- Inotify-based user-space file event watching.

### Why this is needed

- Required by modern init and runtime tooling that expects cgroup support and filesystem notifications.
- `inotify` is the standard Linux userspace API for file and directory change events, many daemons and developer tools rely on it instead of polling.
- Without `CONFIG_INOTIFY_USER`, programs using `inotify_init(2)` and `inotify_init1(2)` fail, which causes silent feature loss or hard failures in minimal VM images.

## 4) ISO cloud-init media and character set support

### Required config changes

- `CONFIG_ISO9660_FS=y`
- `CONFIG_JOLIET=y`
- `CONFIG_ZISOFS=y`
- `CONFIG_NLS=y`
- `CONFIG_NLS_DEFAULT="y"`

### What this enables

- Mounting ISO9660 cloud-init seed media.
- Joliet filename extensions and zisofs compressed ISO support.
- Kernel NLS framework for filesystems and features requiring charset handling.

### Why this is needed

- Enables reading `cidata` ISO images used for cloud-init provisioning in VM workflows.

## 5) Disable IPv6 SIT tunneling

### Required config changes

- `# CONFIG_IPV6_SIT is not set`

### What this enables

- Removes SIT tunnel support from the kernel.

### Why this is needed

- Eliminates unused tunnel capability and resolves the prior SIT-related issue in this VM kernel profile.

## 6) Pacman sandbox support (Landlock)

### Required config changes

- `CONFIG_SECURITYFS=y`
- `CONFIG_SECURITY_LANDLOCK=y`
- Keep `CONFIG_SECURITY=y`
- Ensure `landlock` is present in `CONFIG_LSM`

### What this enables

- Landlock-based filesystem sandboxing used by pacman/libalpm.
- General LSM support for userspace sandboxing workflows.

### Why this is needed

- Landlock can be used to create a sandbox around agent processes.
- Without Landlock support, pacman fails with errors such as:
    - `restricting filesystem access failed because Landlock is not supported by the kernel`

## 7) Seccomp support for sandbox compatibility

### Required config changes

- `CONFIG_SECCOMP=y`

### What this enables

- Syscall filtering used by modern sandboxed user-space.

### Why this is needed

- Improves compatibility with hardened and sandboxed execution paths, including package management and service sandboxes.

## 8) Lockdown LSM defaults (optional hardening baseline)

### Required config changes

- `CONFIG_SECURITY_LOCKDOWN_LSM=y`
- `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=n`
- Default lockdown mode: `LOCK_DOWN_KERNEL_FORCE_NONE`

### What this enables

- Lockdown framework is available without forcing restrictive behavior at boot.

### Why this is needed

- Keeps hardening hooks available while avoiding breakage in development VM workflows.

## 9) Nested virtualization support for arm64 guest kernels

### Required config changes

- `CONFIG_KVM=y`
- `CONFIG_VHOST_MENU=y`
- `CONFIG_VHOST_VSOCK=y`
- `CONFIG_TUN=y`
- `CONFIG_VHOST_NET=y`

### What this enables

- In-guest KVM host support on arm64 so the guest can act as an L1 hypervisor.
- Vhost-backed vsock and virtio-net acceleration paths used by nested virtualization stacks.
- TUN support for common nested guest networking setups.

### Why this is needed

- Nested virtualization needs the guest kernel to expose `/dev/kvm` and the supporting virtualization datapath, not just guest virtio drivers.
- `VHOST_VSOCK` matches Silo's current vsock-heavy transport model.
- `TUN` and `VHOST_NET` make nested guest networking usable instead of deeply annoying.

## 10) Kernel config introspection (observability)

### Required config changes

- `CONFIG_IKCONFIG=y`
- `CONFIG_IKCONFIG_PROC=y`

### What this enables

- Embedding the kernel config into the built kernel.
- Reading the running kernel config from `/proc/config.gz`.

### Why this is needed

- Not required for virtualization itself.
- Makes it easy to verify a booted kernel really contains the expected KVM and vhost flags without playing guess-the-image.

## 11) RTC framework for direct-kernel, non-EFI boots

### Required config changes

- `CONFIG_RTC_CLASS=y`
- `CONFIG_RTC_HCTOSYS=y`
- `CONFIG_RTC_HCTOSYS_DEVICE="rtc0"`
- `# CONFIG_RTC_SYSTOHC is not set`
- `# CONFIG_RTC_NVMEM is not set`
- `CONFIG_RTC_DRV_PL031=y`

### What this enables

- Linux RTC subsystem support, the ARM PL031 virtual RTC driver, and RTC-to-system-clock integration during boot.
- The guest reads the host-backed virtual RTC without writing guest time back or enabling unused RTC NVMEM support.

### Why this is needed

- Current kernel has RTC core disabled, causing `RTC time: n/a`.
- This does not guarantee RTC in direct kernel boot mode if the hypervisor path does not expose a compatible RTC device.

## 12) AUTOFS support for no-modules kernels (optional cleanup)

### Required config changes

- `CONFIG_AUTOFS_FS=y`

### What this enables

- Built-in autofs support.

### Why this is needed

- Removes `Failed to find module 'autofs4'` warnings when using a kernel with `CONFIG_MODULES=n`.

## 13) Rootful Docker guest support

### Required config changes

- Core container isolation and policy:
    - `CONFIG_NAMESPACES=y`
    - `CONFIG_UTS_NS=y`
    - `CONFIG_IPC_NS=y`
    - `CONFIG_PID_NS=y`
    - `CONFIG_NET_NS=y`
    - `CONFIG_USER_NS=y`
    - `CONFIG_CGROUPS=y`
    - `CONFIG_MEMCG=y`
    - `CONFIG_BLK_CGROUP=y`
    - `CONFIG_CGROUP_PIDS=y`
    - `CONFIG_CGROUP_DEVICE=y`
    - `CONFIG_CPUSETS=y`
    - `CONFIG_CGROUP_CPUACCT=y`
    - `CONFIG_SECCOMP=y`
    - `CONFIG_SECCOMP_FILTER=y`
- Docker bridge networking and packet path:
    - `CONFIG_BRIDGE=y`
    - `CONFIG_BRIDGE_NETFILTER=y`
    - `CONFIG_VETH=y`
    - `CONFIG_INET=y`
    - `CONFIG_IPV6=y`
    - `CONFIG_NETFILTER=y`
    - `CONFIG_NF_CONNTRACK=y`
    - `CONFIG_NETFILTER_XTABLES=y`
    - `CONFIG_NETFILTER_XTABLES_LEGACY=y`
    - `CONFIG_NETFILTER_XTABLES_COMPAT=y`
    - `CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y`
    - `CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y`
    - `CONFIG_NETFILTER_XT_NAT=y`
    - `CONFIG_NETFILTER_XT_TARGET_MASQUERADE=y`
- Legacy `iptables` and `ip6tables` tables used by current rootful Docker userspace:
    - `CONFIG_IP_NF_IPTABLES=y`
    - `CONFIG_IP_NF_FILTER=y`
    - `CONFIG_IP_NF_MANGLE=y`
    - `CONFIG_IP_NF_NAT=y`
    - `CONFIG_IP_NF_RAW=y`
    - `CONFIG_IP_NF_TARGET_MASQUERADE=y`
    - `CONFIG_IP6_NF_IPTABLES=y`
    - `CONFIG_IP6_NF_FILTER=y`
    - `CONFIG_IP6_NF_MANGLE=y`
    - `CONFIG_IP6_NF_NAT=y`
    - `CONFIG_IP6_NF_RAW=y`
    - `CONFIG_IP6_NF_TARGET_MASQUERADE=y`
- nftables NAT and iptables-nft compatibility used by newer Docker and distro `iptables` userspace paths:
    - `CONFIG_NF_TABLES=y`
    - `CONFIG_NF_TABLES_IPV4=y`
    - `CONFIG_NF_TABLES_IPV6=y`
    - `CONFIG_NFT_COMPAT=y`
    - `CONFIG_NFT_NAT=y`
    - `CONFIG_NFT_CHAIN_NAT=y`
    - `CONFIG_NFT_MASQ=y`
    - `CONFIG_NFT_REDIR=y`
- Storage and runtime basics:
    - `CONFIG_OVERLAY_FS=y`
    - `CONFIG_UNIX=y`
    - `CONFIG_PACKET=y`
    - `CONFIG_POSIX_MQUEUE=y`

### What this enables

- Namespace isolation, cgroup accounting, and seccomp filtering for ordinary container startup.
- Legacy IPv4 and IPv6 `iptables` table support used by current rootful Docker startup paths, including the `raw` table.
- The legacy xtables kernel path required by current `iptables-legacy` and `ip6tables-legacy` userspace on newer kernels.
- nftables-backed NAT, redirect, and masquerade support used when Docker goes through the `iptables-nft` userspace path instead of the older legacy xtables path.
- Connection-tracking matches used by Docker bridge firewall rules such as `-m conntrack --ctstate RELATED,ESTABLISHED`.
- Compatibility support for `iptables-legacy` and `ip6tables-legacy` userspace against the kernel xtables path.
- Compatibility between `iptables` userspace and nftables kernel plumbing via `CONFIG_NFT_COMPAT`.
- Docker bridge networking, including `docker0` and veth peer creation for containers.
- Overlay filesystem support for the `overlay2` storage driver.

### Why this is needed

- Fixes Docker daemon startup failures such as:
    - `iptables ... can't initialize iptables table 'nat': Table does not exist`
    - `iptables ... can't initialize iptables table 'raw': Table does not exist`
    - `iptables ... TABLE_ADD failed (Operation not supported): table nat`
    - `failed to create NAT chain DOCKER`
    - `ip6tables ... can't initialize ip6tables table 'nat'` or `filter`
    - `Extension conntrack revision 0 not supported, missing kernel module?`
- Prevents `olddefconfig` on newer kernels from silently dropping legacy `IP*_NF_*` and `IP6*_NF_*` table support when `CONFIG_NETFILTER_XTABLES_LEGACY=y` is missing.
- Lets Docker create the `DOCKER` NAT chain and MASQUERADE rules when using `iptables-legacy`.
- Lets Docker create the `DOCKER` NAT chain and MASQUERADE or REDIRECT rules when userspace goes through the nftables-backed `iptables` path.
- Lets Docker install direct access filtering rules in `raw/PREROUTING`, which it uses to drop non-bridge traffic headed at container addresses.
- Lets Docker install IPv6 chains when ip6tables support is enabled in userspace.
- Provides the baseline guest kernel networking and storage features needed for Silo's current rootful Docker extension model.

### Notes

- This repo's arm guest kernel profile currently disables modules, so these options must be built in, not left as modules.
- `CONFIG_NF_TABLES=y` alone is not enough for the current Docker setup, because the guest userspace may use either `iptables-legacy` or the nftables-backed `iptables` path.
- On newer kernels, `CONFIG_NETFILTER_XTABLES_LEGACY=y` is required alongside the legacy `IP*_NF_*` and `IP6*_NF_*` symbols or Docker can still fail with missing `nat`/`raw` tables.
- `CONFIG_IP_NF_RAW=y` and `CONFIG_IP6_NF_RAW=y` are easy to miss because Docker often fails later on the first visible `raw` table access rather than during its initial capability checks.
- `CONFIG_NETFILTER_XTABLES_COMPAT=y` is part of that legacy userspace path, and missing it can surface as conntrack match failures or legacy table initialization failures even when the newer `IP*_NF_*` options are enabled.
- Silo currently needs both sides of the firewall stack available for reliable Docker behavior in guests:
    - legacy xtables support for `iptables-legacy`
    - nftables NAT support for nft-backed `iptables`
- If Docker reports `TABLE_ADD failed (Operation not supported): table nat`, the guest kernel is usually missing nft NAT support even if the older `IP_NF_*` options are enabled.
- `CONFIG_NETFILTER_XTABLES_LEGACY` depends on `!PREEMPT_RT` on newer kernels, so a PREEMPT_RT kernel and the current Docker `iptables-legacy` path are not friends.

## 14) VZ requestSTop

### Required config changes

- `CONFIG_GPIO_PL061=y`
- `CONFIG_INPUT_EVDEV=y`
- `CONFIG_KEYBOARD_GPIO=y`

### What this enables

These are the guest-kernel pieces needed for Apple Silicon `requestStop()` support.

Kernel support only gets you the event. You still need userspace to react to the virtual power button and actually shut the machine down. The VZ Linux wiki suggests `acpid` with a simple handler like this:

- acpid
  with a handler like:
  mkdir -p /etc/acpi/PWRF
  echo '#!/bin/sh' > /etc/acpi/PWRF/00000080
  echo 'poweroff' >> /etc/acpi/PWRF/00000080
  chmod +x /etc/acpi/PWRF/00000080
  acpid

## 15) Idle guest CPU behavior and host CPU usage

### Required config changes

- `CONFIG_TICK_ONESHOT=y`
- `CONFIG_NO_HZ_COMMON=y`
- `CONFIG_NO_HZ_FULL=y`
- `CONFIG_NO_HZ=y`
- `CONFIG_HIGH_RES_TIMERS=y`
- `CONFIG_CPU_IDLE=y`
- At least one CPU idle governor enabled:
    - `CONFIG_CPU_IDLE_GOV_LADDER=y`
    - or `CONFIG_CPU_IDLE_GOV_MENU=y`
    - or `CONFIG_CPU_IDLE_GOV_TEO=y`

### Optional but worth testing on arm64 VZ guests

- `CONFIG_ARM_PSCI_CPUIDLE=y`

### What this enables

- Suppression of periodic scheduler ticks while guest CPUs are idle.
- Better odds that the guest can stay asleep long enough for the host `Virtualization.framework` process to stop getting poked for pointless timer housekeeping.
- A path to stricter adaptive-ticks CPU isolation later if a workload actually benefits from it.

### Why this is needed

- In practice, a Linux guest that keeps taking periodic scheduler ticks while otherwise idle can still make the host VM process burn a surprising amount of CPU.
- Tickless idle is the first obvious lever for reducing host-side CPU use when the guest is doing nothing useful.
- The upstream kernel docs explicitly call out tickless idle as important for highly virtualized systems because otherwise guest timer interrupts keep firing when the guest should be asleep.

### `NO_HZ_FULL` versus idle-only tickless

- `CONFIG_NO_HZ_IDLE` is the usual "stop scheduler ticks on idle CPUs" mode.
- `CONFIG_NO_HZ_FULL` is the stricter adaptive-ticks configuration intended for CPUs that should avoid scheduler ticks even while running a single task.
- For Silo's arm64 baseline, keeping `CONFIG_NO_HZ_FULL=y` is a reasonable choice because it still gives the ordinary idle tick suppression behavior, while leaving the door open for stricter tuning later.
- In other words, without a `nohz_full=` CPU list on the kernel command line, `CONFIG_NO_HZ_FULL=y` mostly behaves like ordinary idle tickless operation for this VM use case.
- Once `nohz_full=` is provided, the selected CPUs become adaptive-ticks CPUs and the extra housekeeping and RCU constraints start to matter.
- That makes `NO_HZ_FULL` a decent baseline if you want room to experiment later, not because every dev VM wants full adaptive-ticks isolation on day one.

### Boot parameters for stricter isolation later

- `nohz_full=<cpu-list>` selects adaptive-ticks CPUs.
- `rcu_nocbs=<cpu-list>` offloads RCU callbacks away from those CPUs so RCU does not keep waking them.
- Leave at least one housekeeping CPU outside that set. In practice, keeping CPU 0 out of it is the usual move.
- Example:

```text
nohz_full=1-N rcu_nocbs=1-N
```

- That example means "leave CPU 0 for housekeeping, try to keep the rest quieter".
- This is useful for dedicated low-jitter or pinned workloads. It is not a great default for ordinary devbox-style guests.

## 16) k3s, kube-proxy, and Istio guest networking support

### Required config changes

- Container runtime and cgroup v2 support:
    - `CONFIG_BPF_JIT=y`
    - `CONFIG_CFS_BANDWIDTH=y`
    - `CONFIG_CGROUP_PERF=y`
    - `CONFIG_CGROUP_HUGETLB=y`
    - `CONFIG_CHECKPOINT_RESTORE=y`
    - `CONFIG_PERF_EVENTS=y`
    - `CONFIG_BLK_DEV_THROTTLING=y`
    - `CONFIG_HUGETLBFS=y`
    - `CONFIG_HUGETLB_PAGE=y`
- Flannel VXLAN and traffic-control support:
    - `CONFIG_VXLAN=y`
    - `CONFIG_NET_SCHED=y`
    - `CONFIG_NET_CLS=y`
    - `CONFIG_NET_CLS_CGROUP=y`
    - `CONFIG_CGROUP_NET_PRIO=y`
    - `CONFIG_CGROUP_NET_CLASSID=y`
- nftables and `iptables-nft` compatibility:
    - `CONFIG_NF_TABLES_INET=y`
    - `CONFIG_NFT_CT=y`
    - `CONFIG_NFT_COUNTER=y`
    - `CONFIG_NFT_LOG=y`
    - `CONFIG_NFT_LIMIT=y`
    - `CONFIG_NFT_REJECT=y`
    - `CONFIG_NFT_FIB=y`
    - `CONFIG_NFT_FIB_IPV4=y`
    - `CONFIG_NFT_FIB_IPV6=y`
    - `CONFIG_NFT_CHAIN_NAT=y`
    - `CONFIG_NFT_MASQ=y`
- xtables matches and targets used by kube-proxy, k3s network policy, and Istio init rules:
    - `CONFIG_NETFILTER_XT_TARGET_CHECKSUM=y`
    - `CONFIG_NETFILTER_XT_TARGET_CT=y`
    - `CONFIG_NETFILTER_XT_TARGET_LOG=y`
    - `CONFIG_NETFILTER_XT_TARGET_MARK=y`
    - `CONFIG_NETFILTER_XT_TARGET_REDIRECT=y`
    - `CONFIG_NETFILTER_XT_MATCH_COMMENT=y`
    - `CONFIG_NETFILTER_XT_MATCH_MARK=y`
    - `CONFIG_NETFILTER_XT_MATCH_MULTIPORT=y`
    - `CONFIG_NETFILTER_XT_MATCH_NFACCT=y`
    - `CONFIG_NETFILTER_XT_MATCH_OWNER=y`
    - `CONFIG_NETFILTER_XT_MATCH_PHYSDEV=y`
    - `CONFIG_NETFILTER_XT_MATCH_RECENT=y`
    - `CONFIG_NETFILTER_XT_MATCH_STATE=y`
    - `CONFIG_NETFILTER_XT_MATCH_STATISTIC=y`
    - `CONFIG_NETFILTER_XT_SET=y`
    - `CONFIG_IP_NF_TARGET_REDIRECT=y`
- ipset support for k3s network policy:
    - `CONFIG_IP_SET=y`
    - `CONFIG_IP_SET_BITMAP_IP=y`
    - `CONFIG_IP_SET_BITMAP_IPMAC=y`
    - `CONFIG_IP_SET_BITMAP_PORT=y`
    - `CONFIG_IP_SET_HASH_IP=y`
    - `CONFIG_IP_SET_HASH_IPMARK=y`
    - `CONFIG_IP_SET_HASH_IPPORT=y`
    - `CONFIG_IP_SET_HASH_IPPORTIP=y`
    - `CONFIG_IP_SET_HASH_IPPORTNET=y`
    - `CONFIG_IP_SET_HASH_IPMAC=y`
    - `CONFIG_IP_SET_HASH_MAC=y`
    - `CONFIG_IP_SET_HASH_NETPORTNET=y`
    - `CONFIG_IP_SET_HASH_NET=y`
    - `CONFIG_IP_SET_HASH_NETNET=y`
    - `CONFIG_IP_SET_HASH_NETPORT=y`
    - `CONFIG_IP_SET_HASH_NETIFACE=y`
    - `CONFIG_IP_SET_LIST_SET=y`

### What this enables

- `containerd` and `runc` running Kubernetes workloads against the unified cgroup v2 hierarchy.
- Flannel's default VXLAN backend and the pod network routes it needs to write `/run/flannel/subnet.env`.
- kube-proxy running through the distro `iptables` command when it is backed by nftables.
- k3s network policy rules that rely on ipset and xtables matches.
- Istio init-container and sidecar iptables rules that match by process owner before redirecting traffic to Envoy.

### Why this is needed

- Fixes container startup failures where `runc` cannot set cgroup v2 CPU quota because `/sys/fs/cgroup/.../cpu.max` is missing.
- Fixes flannel startup failures where the default VXLAN backend never creates the pod-network subnet state.
- Fixes kube-proxy `iptables-restore` failures caused by missing nftables and xtables compatibility expressions.
- Fixes k3s network policy startup failures where `ipset save` returns `Kernel error received: Invalid argument`.
- Fixes Istio iptables setup failures where the `owner` match is unavailable.

### Observed failure modes

- `runc create failed: error setting cgroup config for procHooks process: openat2 /sys/fs/cgroup/.../cpu.max: no such file or directory`
- `failed to set up sandbox container ... /run/flannel/subnet.env: no such file or directory`
- `Failed to load kernel module nft-expr-counter with modprobe`
- `Failed to load kernel module nft-chain-2-nat with modprobe`
- `Skipping network policy controller start, ipset save failed: ipset ... Kernel error received: Invalid argument`
- `Warning: Extension physdev revision 0 not supported, missing kernel module?`
- `Warning: Extension nfacct revision 0 not supported, missing kernel module?`
- `Warning: Extension owner revision 0 not supported, missing kernel module?`

### Notes

- Silo's current arm64 kernel profile builds these features in instead of relying on loadable modules.
- Some k3s startup logs still say `Failed to load kernel module ...` when a feature is built in. Treat those as actionable only when the matching kernel config is missing or userspace reports the extension is unsupported.
- The generated kernel config under `target/kernels/<track>-<arch>-<version>/.config` can stay stale until `make kernel TRACK=<track> ARCH=<arch>` rebuilds the kernel.
