# Shutdown and hardening contract

Ordinary SIGTERM, `systemctl stop`, restart and daemon crash never request VM
stops. Sessions and operations drain behind the existing 90-second cleanup
deadline. Signal notification is reset before cleanup so another termination
signal can end a blocked cleanup. `KillMode=process` belongs in the real unit.

## Host shutdown

The nonroot daemon authenticates to the real system bus, resolves login1's
unique owner, and subscribes to its exact object/interface/PrepareForShutdown
signal. Subscription precedes acquisition and the startup read of
`PreparingForShutdown`. The delay FD is close-on-exec and closed at the deadline
independently of any synchronous native call. Bus or login1 owner loss is logged
as loss of protection, not a successful shutdown.

Authenticated receipt starts during acquisition, before helper or marker
recovery. The ordered PreparingForShutdown property reply supplies godbus's
ResponseSequence boundary: historical signals at or before that reply are
superseded by the snapshot. A queued true followed by false before a false
snapshot cannot start VM stops. Later signals keep their original receipt
timestamps. FD deadline enforcement and process-local sealing run independently
of startup recovery and filesystem writes.

One owner mutex holds the current episode phase, revision, sequence, absolute
deadline and FD. Acquisition runs outside that mutex; completion installs an FD
against the state current at that moment. A returned FD inherits an intervening
true episode's deadline, closes immediately if that deadline expired, and is
discarded if its acquisition context is stale. A timer closes the currently
owned FD, rather than only the FD pointer present when receipt first occurred.

The shared budget is the smaller of `shutdown.stop_budget` (default 4s) and the
actual `InhibitDelayMaxUSec` minus `shutdown.margin` (default 250ms). It is not
the service's 90-second ordinary drain timeout. A host already preparing at
startup offers no guarantee of a fresh inhibitor window.

On true, a shared in-memory latch seals service authorization and job admission,
and existing jobs are directly cancelled before any disk I/O. Then
`<home>/taild/shutdown` is written and synced. If the write fails, the memory latch
still denies exec, shell, document mutations and final create/start authorization.
The error explicitly reports loss of cross-process durable protection rather
than pretending the marker exists. Recovery uses episode revisions, so an old
cancellation cannot clear a newer shutdown latch.
Every valid instance/owner/name-labelled VM receives a concurrent public SDK
stop before operations drain. Existing operations observe cancellation, releasing
enrollment leases; synchronous native calls may still run past cancellation.
After operation drain a second inventory stops late durable creations. Graceful
stop uses part of the remaining budget, followed by force only while the parent
budget remains. Native lifecycle/run identity locks remain authoritative.
Logs distinguish issued, returned and failed stops. A deadline cannot imply that
blocked native calls finished.

The fallback `taild stop-vms --only-when-shutting-down` reads **stdout** from the
real `systemctl is-system-running`, including its nonzero `stopping` result.
Unknown/failed observations diagnose and stop nothing. It does not acquire the
daemon-exclusive home lock: ExecStop runs before the main process gets SIGTERM.
It writes the same seal, uses native per-VM locks and re-inventories through its
bounded budget. The still-running main process observes the seal and interrupts
existing jobs. Only existing valid instance ownership is read, never invented.
An independent helper lease lives until helper process exit, including native
threads still in flight. Cancellation/restart recovery waits for that lease;
guarded helpers recheck systemctl after acquiring it so a delayed helper cannot
stop newly admitted VMs after a cancelled shutdown.

On authenticated false, FD reacquisition runs independently of old native drain.
One stop/drain worker remains tracked until its actual native calls, jobs and
helper processes finish. Retiring that worker does not recover its old revision:
recovery targets the latest cancelled episode, even if it never began a sweep.
PreparingForShutdown is checked again and the current episode is checked before
and after the durable latch compare-and-swap. Only then can admission resume.
Thus A draining after a received B true/false pair cannot leave B permanently
sealed, and no false can reopen a newer true. If recovery fails, admission
stays sealed. Restart clears a crash-retained seal only after a known safe host
observation. A manual unguarded stop-vms invocation intentionally leaves a seal;
restart on a verified non-shutdown host clears it.

## Disk admission and metrics

`disk_reserve` defaults to 1GiB. Admission uses statfs available blocks for the
service UID, excluding root filesystem reserves. Each concurrent create reserves
its full requested logical disk capacity before pull and rechecks before
materialization. Reservations release on every returned outcome. Disk growth
also holds a concurrent reservation through SDK Update. Existing disk
allocation is already accounted for by statfs. Sparse apparent size is not
allocated size; the logical reservations are deliberately conservative and do
not promise permanent capacity as guests or unrelated writers consume space.
Per-principal quotas and operator/capability ceilings remain independently applied.

Metrics share the health endpoint's fresh connection WhoIs and vm.read guard.
They contain bounded operation kind/outcome counts and duration sums/counts,
enrollment and WhoIs latency, active sessions/jobs, and actually held daemon-owned
runtime/machine/exec/log/node-lease handles. They do not claim to count all bridge
allocations or handles held by other processes. There are no peer, VM, path or
credential metric labels. Log handlers sanitize known secrets, credential fields,
HTTP errors and host paths. Intentional operator login URLs remain visible.

## Qualification and failure semantics

An ordinary returned SDK/native error can be categorized as exit 9. A fatal
native SIGSEGV inside this process cannot return a structured SSH exit 9. The
client sees transport loss (normally SSH 255), and systemd Restart=on-failure
restarts the daemon. Durable SDK records are recovery truth; supervisors are not
stopped by closing the broken lobby transport. Phase 14.6 must use this corrected
contract rather than assert that an in-process fatal crash returns exit 9.

The silod inhibitor is a nontrivial Rust lifecycle change and is an allowed
Phase 14 follow-up, with a separate real-unit qualification. No silod change is
made by this app subtask.

The real-unit restart/kill/stop/session-survival drill and any host shutdown
drill remain a user-run manual phase on a prepared test host after this work.
No synthetic login1 signal, injected fake bus or host power operation is an
acceptance substitute. `SILO_TAILD_REQUIRE_FIXTURES=1` keeps runtime/bridge
fixtures mandatory for CI. ENOSPC tests require an isolated <=64MiB filesystem
via `SILO_TAILD_ENOSPC_ROOT`; otherwise the genuine failure drill explicitly skips.
