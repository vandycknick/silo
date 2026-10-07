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
Every valid instance/owner/name-labelled VM is inspected and stopped through
silod's generated management API, with at most 16 concurrent workers. Graceful
and forced requests retain the same inspected run ID. The first stop pass is
followed by `DrainMutations` for actual accepted native work, a fresh inventory
and final stop pass, then another actual drain. Cancelled RPC waiters are not
native completion. Jobs and shutdown helpers must also settle before early
inhibitor release; the deadline still releases its FD on time and reports
incomplete work rather than inventing success.

Linux service `ExecStop` invokes the adjacent `silod --host-shutdown`.
It uses an authenticated existing manager, or, only after proven absence,
holds both Home and per-UID ownership before publishing a temporary restricted
control service. That service admits only status, mutation drain, machine
list/inventory/inspect and run-fenced stop, never creation or session access.
Both paths launch `taild --shutdown-only --bootstrap-fd 0` through the normal
framed owner pipe, without loading the SDK, native assets, documents or secrets,
creating an instance, replacing the normal helper generation or starting listeners.

The child reads **stdout** from the real `systemctl is-system-running`,
including its nonzero `stopping` result. Unknown observations fail closed;
ordinary non-stopping observations are a no-op. It reads only existing instance
ownership, acquires the independent shutdown-helper lease, rechecks host state,
then persists the marker and runs the same stop/drain/fresh-final-pass sequence.
The lease survives to helper exit. Its management connection is pinned to the
admitted daemon; replacement connections and automatic replay are forbidden.

On authenticated false, FD reacquisition runs independently of old native drain.
One stop/drain worker remains tracked until accepted native calls, jobs and
helper processes finish. A true/false pair that never began a sweep must still
persist the marker before native drain. Retiring an old worker does not recover
its old revision: recovery targets the latest cancelled episode.
PreparingForShutdown and actual host state are checked again, and the current
episode is checked before and after the durable latch compare-and-swap.
Only then can admission resume. A racing newer true remains sealed.
Startup recovery also drains the admitted manager before clearing a crash marker.
Failed persistence or settlement cannot claim recovery.

On macOS, shutdown protection is explicitly `Unsupported`. No logind,
systemctl, inhibitor or fabricated host-state recovery is attempted.

## Disk admission and metrics

`disk_reserve` defaults to 1GiB. Admission uses statfs available blocks for the
service UID, excluding root filesystem reserves. Each concurrent create reserves
its full requested logical disk capacity before pull and rechecks before
materialization. Reservations release on every returned outcome. Disk growth
also holds a concurrent reservation through management Update. Existing disk
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
native SIGSEGV inside the direct session bridge cannot return a structured SSH
exit 9. The client sees transport loss (normally SSH 255); silod supervises
replacement of its helper. Durable libvm records remain recovery truth.
Closing or replacing a broken lobby transport does not stop VM supervisors.

The real-unit restart/kill/stop/session-survival drill and any host shutdown
drill remain a user-run manual phase on a prepared test host after this work.
No synthetic login1 signal, injected fake bus or host power operation is an
acceptance substitute. `SILO_TAILD_REQUIRE_FIXTURES=1` keeps runtime/bridge
fixtures mandatory for CI. ENOSPC tests require an isolated <=64MiB filesystem
via `SILO_TAILD_ENOSPC_ROOT`; otherwise the genuine failure drill explicitly skips.
