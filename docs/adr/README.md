# Architecture Decision Records (ADRs)

We use Michael Nygard-style ADRs to capture architectural decisions.

## ADR Lifecycle States

| State       | Meaning                                           |
| ----------- | ------------------------------------------------- |
| Proposed    | Drafted and under discussion.                     |
| Accepted    | Approved decision, implementation may be pending. |
| Implemented | Decision has been delivered in code.              |
| Rejected    | Considered and explicitly not adopted.            |
| Superseded  | Replaced by a newer ADR.                          |
| Abandoned   | Previously adopted but no longer maintained.      |

## ADR Index

| ADR  | Title                                                         | Status      | Date       | File                                             |
| ---- | ------------------------------------------------------------- | ----------- | ---------- | ------------------------------------------------ |
| 0001 | Record architecture decisions                                 | Accepted    | 2016-02-12 | `docs/adr/0001-record-architecture-decisions.md` |
| 0002 | Image management                                              | Abandoned   | 2026-02-20 | `docs/adr/0002-image-management.md`              |
| 0003 | Replace shell command with native SSH client (`ssh2`/libssh2) | Proposed    | 2026-02-23 | `docs/adr/0003-native-shell-client-ssh2.md`      |
| 0004 | Daemonless architecture                                       | Implemented | 2026-04-06 | `docs/adr/0004-daemonless-architecture.md`       |
| 0005 | Vmmon endpoint plugins for vsock streams                      | Implemented | 2026-04-12 | `docs/adr/0005-vmmon-vsock-endpoint-plugins.md`  |
| 0006 | Sandbox network policy and firewall semantics                 | Proposed    | 2026-06-18 | `docs/adr/0006-sandbox-network-policy-and-firewall-semantics.md` |
| 0007 | HCL network policy frontend                                   | Proposed    | 2026-07-04 | `docs/adr/0007-hcl-network-policy-frontend.md`   |
