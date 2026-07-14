# Testing the Host gRPC API

The host API is exposed by each running `vmmon` process on that machine's Unix
socket. Run these commands from `nix develop`, which provides `grpcurl` and
`jq`.

## Select a running machine

Set the machine name and derive its runtime directory from the CLI:

```bash
VM=dev
MACHINE_DIR="$(silo status "$VM" --format json | jq -r '.dir')"
SOCKET="$MACHINE_DIR/vm.sock"
GRPC_TARGET="unix://$SOCKET"

test -S "$SOCKET" && printf 'Using %s\n' "$SOCKET"
```

`silo status` already exercises `VmMonitorService.GetStatus`. If it fails
before printing the machine directory, inspect the default machine directory
directly:

```bash
ls "${XDG_DATA_HOME:-$HOME/.local/share}/silo/machines"/*/vm.sock
```

Machine directories use the full undashed machine UUID.

## Reflection

List the services admitted by the host endpoint:

```bash
grpcurl -plaintext "$GRPC_TARGET" list
```

The expected inventory is:

```text
grpc.health.v1.Health
grpc.reflection.v1.ServerReflection
silo.v1.GuestFilesystemService
silo.v1.VmAccessService
silo.v1.VmMonitorService
```

The host must not advertise `silo.v1.GuestAgentService`.

Inspect services, methods, and messages through reflection:

```bash
grpcurl -plaintext "$GRPC_TARGET" list silo.v1.VmMonitorService
grpcurl -plaintext "$GRPC_TARGET" describe silo.v1.VmMonitorService
grpcurl -plaintext "$GRPC_TARGET" describe silo.v1.HostStatus
grpcurl -plaintext "$GRPC_TARGET" describe silo.v1.GuestFilesystemService
```

## Health

Check overall server health:

```bash
grpcurl \
  -plaintext \
  -d '{"service":""}' \
  "$GRPC_TARGET" \
  grpc.health.v1.Health/Check
```

Check each application service:

```bash
for service in \
  silo.v1.VmMonitorService \
  silo.v1.VmAccessService \
  silo.v1.GuestFilesystemService; do
  grpcurl \
    -plaintext \
    -d "{\"service\":\"$service\"}" \
    "$GRPC_TARGET" \
    grpc.health.v1.Health/Check
done
```

A healthy service returns:

```json
{
  "status": "SERVING"
}
```

Watch the monitor health transition while stopping the VM in another terminal:

```bash
grpcurl \
  -plaintext \
  -d '{"service":"silo.v1.VmMonitorService"}' \
  "$GRPC_TARGET" \
  grpc.health.v1.Health/Watch
```

The watch remains open until interrupted or until the server closes it.

## Monitor status

Read the complete host status snapshot:

```bash
grpcurl \
  -plaintext \
  -d '{}' \
  "$GRPC_TARGET" \
  silo.v1.VmMonitorService/GetStatus
```

Show the most useful readiness and guest-agent fields:

```bash
grpcurl \
  -plaintext \
  -d '{}' \
  "$GRPC_TARGET" \
  silo.v1.VmMonitorService/GetStatus |
jq '{
  machineId,
  name,
  vmState: .vm.state,
  ready: .readiness.ready,
  readinessReason: .readiness.reason,
  connection: .agent.enabled.connection.state,
  freshness: .agent.enabled.status.freshness,
  guestState: .agent.enabled.status.report.state
}'
```

## Wait for readiness

Protobuf durations use their JSON string representation:

```bash
grpcurl \
  -plaintext \
  -d '{"maxWait":"10s"}' \
  "$GRPC_TARGET" \
  silo.v1.VmMonitorService/WaitReady
```

A healthy running VM returns `WAIT_READY_OUTCOME_READY`. Other valid outcomes
are `WAIT_READY_OUTCOME_TERMINAL` and `WAIT_READY_OUTCOME_TIMED_OUT`.

## Metrics

Read the latest host-retained guest metrics:

```bash
grpcurl \
  -plaintext \
  -d '{}' \
  "$GRPC_TARGET" \
  silo.v1.VmMonitorService/GetMetrics
```

The first observation may take about five seconds after the guest agent becomes
responsive. Missing metric sections are valid when an individual Linux
collector cannot produce a snapshot.

## Filesystem metadata

These calls traverse the complete host Unix socket to `vmmon` to guest-vsock
path.

Inspect a guest file without following a final symlink:

```bash
grpcurl \
  -plaintext \
  -d '{"path":"/etc/os-release"}' \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/GetEntry
```

List the first five entries in `/etc`:

```bash
grpcurl \
  -plaintext \
  -d '{"path":"/etc","limit":5}' \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/ListDirectory
```

Test cursor pagination:

```bash
FIRST_PAGE="$(grpcurl \
  -plaintext \
  -d '{"path":"/etc","limit":5}' \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/ListDirectory)"

CURSOR="$(printf '%s\n' "$FIRST_PAGE" | jq -r '.nextCursor // empty')"

jq -nc \
  --arg cursor "$CURSOR" \
  '{path:"/etc",limit:5,cursor:$cursor}' |
grpcurl \
  -plaintext \
  -d @ \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/ListDirectory
```

Cursor bytes are represented as base64 in JSON and must be passed back
unchanged.

## Filesystem mutations

Use a disposable path under `/tmp` for mutation tests.

Create a directory with mode `0700` (`448` in decimal JSON):

```bash
grpcurl \
  -plaintext \
  -d '{"path":"/tmp/silo-grpc-test","parents":true,"mode":448}' \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/CreateDirectory
```

Upload a file with mode `0644` (`420` in decimal JSON). Streaming request
messages are concatenated as separate JSON objects:

```bash
grpcurl \
  -plaintext \
  -d @ \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/UploadFile <<'EOF'
{"header":{"path":"/tmp/silo-grpc-test/hello.txt","mode":420}}
{"chunk":{"data":"aGVsbG8gZnJvbSBncnBjdXJsCg=="}}
EOF
```

The byte payload decodes to `hello from grpcurl` followed by a newline.

Download and decode the streamed file on macOS:

```bash
grpcurl \
  -plaintext \
  -d '{"path":"/tmp/silo-grpc-test/hello.txt"}' \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/DownloadFile |
jq -r '.data // empty' |
while IFS= read -r chunk; do
  printf '%s' "$chunk" | base64 -D
done
```

Remove the test directory recursively:

```bash
grpcurl \
  -plaintext \
  -d '{"path":"/tmp/silo-grpc-test","recursive":true}' \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/RemoveEntry
```

## Error handling

Send a relative path to verify request validation and the canonical gRPC error
code:

```bash
grpcurl \
  -v \
  -plaintext \
  -d '{"path":"relative"}' \
  "$GRPC_TARGET" \
  silo.v1.GuestFilesystemService/GetEntry
```

The call must fail with `InvalidArgument`. Application errors also carry a
stable `silo.v1.ErrorDetail` in the gRPC status details.

## SSH and serial streams

`VmAccessService.OpenSsh` and `OpenSerial` are bidirectional binary streams.
`grpcurl` can represent their `ByteChunk` messages as base64, but it is not an
SSH or terminal client. Exercise these host RPCs through the CLI instead:

```bash
silo shell "$VM"
```

```bash
silo shell "$VM" --attach serial
```

## Troubleshooting

`connection refused` or a missing socket means the VM is not running or the
wrong machine directory was selected.

`Unavailable` from metrics or filesystem calls usually means the host UDS API
is working but the guest agent is disabled, starting, stale, or unreachable
over vsock.

`ResourceExhausted` means the relevant monitor, access, or filesystem admission
limit is currently full.

Inspect the monitor trace and serial output when a guest does not become ready:

```bash
tail -f "$MACHINE_DIR/vm.trace.log"
```

```bash
tail -f "$MACHINE_DIR/serial.log"
```
