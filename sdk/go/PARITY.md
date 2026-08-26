# Node to Go SDK parity

This inventory is completed alongside implementation. A checked item has a public Go symbol, native bridge path, and test coverage. `libvm` APIs absent from the public Node facade are intentionally excluded.

| Node facade | Go facade | Native operation | Coverage | State |
|---|---|---|---|---|
| `Runtime.open` | `silo.Open` | `silo_runtime_open` | runtime tests | implemented |
| `Runtime.machine().create` | `Runtime.CreateMachine` | `silo_runtime_machine_create` | creation tests | implemented |
| `Runtime.getMachine` | `Runtime.Machine` | `silo_runtime_machine_get` | runtime tests | implemented |
| `Runtime.listMachines` | `Runtime.Machines` | `silo_runtime_machines` | runtime tests | implemented |
| `Runtime.images` | `Runtime.Images` | runtime-owned namespace | image tests | implemented |
| machine image/name/labels/metadata/CPU/memory | machine options | create request DTO | option + creation tests | implemented |
| machine kernel/initramfs/agent/disk size | machine options | create request DTO | option + creation tests | implemented |
| nested virtualization/Rosetta/userdata | machine options | create request DTO | option + creation tests | implemented |
| disks/mounts/network | machine options | create request DTO | option + creation tests | implemented |
| `Machine.id` | `Machine.ID` | local/native handle ID | runtime tests | implemented |
| `inspect` | `Machine.Inspect` | `silo_machine_inspect` | lifecycle tests | implemented |
| `start` | `Machine.Start` | `silo_machine_start` | lifecycle tests | implemented |
| `stop` | `Machine.Stop` | `silo_machine_stop` | lifecycle tests | implemented |
| `remove` | `Machine.Remove` | `silo_machine_remove` | lifecycle tests | implemented |
| `exec` | `Machine.Exec` | `silo_machine_exec` | execution tests | implemented |
| `shell` | `Machine.Shell` | `silo_machine_shell` | execution tests | implemented |
| `spawn` | `Machine.Spawn` | `silo_machine_spawn` | stream tests | implemented |
| session `recv` | `ExecutionSession.Recv` | `silo_execution_recv` | stream tests | implemented |
| session `stdin` | `ExecutionSession.Stdin` | `silo_execution_stdin` | stdin tests | implemented |
| session `wait` | `ExecutionSession.Wait` | `silo_execution_wait` | stream tests | implemented |
| session `collect` | `ExecutionSession.Collect` | `silo_execution_collect` | stream tests | implemented |
| session signal/resize | session control methods | execution control ABI | control tests | implemented |
| session close requests/cancel | session control methods | execution control ABI | cancellation tests | implemented |
| `attach` | `Machine.Attach` | `silo_machine_attach` | terminal tests | implemented |
| `attachShell` | `Machine.AttachShell` | `silo_machine_attach_shell` | terminal tests | implemented |
| `logs` | `Machine.Logs` | `silo_machine_logs` | log tests | implemented |
| log `recv` | `MachineLogStream.Recv` | `silo_log_recv` | log tests | implemented |
| image `pull` | `Images.Pull` | `silo_images_call` | image tests | implemented |
| image `get` | `Images.Lookup` | `silo_images_call` | image tests | implemented |
| image `list` | `Images.List` | `silo_images_call` | image tests | implemented |
| image `inspect` | `Images.Inspect` | `silo_images_call` | image tests | implemented |
| image `remove` | `Images.Remove` | `silo_images_call` | image tests | implemented |
| image `prune` | `Images.Prune` | `silo_images_call` | image tests | implemented |
| network policy builders | declarative policy structs | `silo_network_policy_build` | policy tests | implemented |
| `NetworkPolicy.fromJson` | `ParseNetworkPolicyJSON` | `silo_network_policy_parse` | policy tests | implemented |
| machine/image/process/status types | corresponding Go read models | response DTO conversion | conversion tests | implemented |
| `SiloError` | `silo.Error` | exhaustive native error DTO | error tests | implemented |

Go-only packaging APIs (`InstallRuntime`, `InstalledRuntime`, and `ByteSize`) have no Node equivalent and exist to satisfy the Go transport contract in ADR 0012.
