# Embedded node contract

Pinned to `tailscale.com v1.102.5`, Go 1.26.6 (toolchain 1.26.8).
`adapter.go` is the single version-sensitive boundary for exported unstable
`Server.Sys().Dialer.GetOK().NetstackDialTCP`. Capture after `Up`, check every
pointer, call directly with a numeric `netip.AddrPort`. Do not replace it with
`Server.Dial`: that API falls back to a host dial when a peer disappears.
Never mutate the shared dialer's callbacks. Compile and real unregistered-node
tests cover the adapter; real-tailnet tests are explicitly credential-gated.
Packet routing classifies before host NAT so translation cannot erase DNS
provenance or replace a tailnet target with a loopback host connection.

Node initialization has one owner. Start is asynchronous after the worker's
startup report. Close cancels and joins initialization/Up/status watches before
Server.Close and waits for relays before the guest stack closes. Ordinary VM
networking does not wait for enrollment. State persists across process runs.
The launcher and foreground worker clear all ambient TS_/TSNET_ variables;
only explicit node configuration and the optional named auth-key slot apply.
The slot accepts only a literal ASCII `tskey-auth-...` enrollment key (or no
key). Constructor validation rejects OAuth/client secrets, WIF/JWT material,
URLs, query attributes and whitespace before constructing tsnet. Pinned
tsnet.Start otherwise resolves OAuth under its own shutdown context, outside
the caller's Up budget. netd never mints keys; taild/enrollment supplies them.
Qualification tests mint literal keys separately with bounded HTTP calls.
Rust strips TS_/TSNET_ before exec. Standalone binaries and node consumers import
the os-only bootenv guard before upstream environment registration; main-time
clearing is not used to repair unsupported integer caches. See
[bootenv's initialization contract](../bootenv/README.md).
Up attempts have a 10-second budget and retry every minute, with bounded status
and authentication-URL reporting. IPN changes invalidate DNS provenance.

Gateway DNS preserves static zones and uses peer DNSName for short names,
rejecting ambiguity. Classified names use bounded raw LocalClient.QueryDNS,
never public fallback. Answer provenance is capped at 4096 addresses/60 seconds
and invalidated on state/peer changes. Cached addresses are quarantined only
until their original TTL expires, so invalidation cannot create a direct-host
escape while the guest still has a cacheable answer. Stale/capacity-exhausted
answers fail DNS closed rather than returning untracked addresses.
Bounded negative classification retains known
short names and suffixes after disconnect/peer removal, preventing host DNS
escape. Classification capacity exhaustion fails DNS closed. Unknown ts.net
suffixes are rejected rather than sent to any public resolver.
Guest transport currently supports IPv4 only;
IPv6 destination classification remains fail closed.

User-selected admission is **connection attempts only**: an attached guest stack
and a bounded actual gonet TCP dial, with 256 simultaneous flows. There is no
guest status RPC or pre-agent readiness assertion. Port 22 is reserved and
rejected until phase 9 implements an actual mux CONNECT and pinned SSH handshake.
Failed attempts close and audit. Relays preserve half closes and join on shutdown.
netd disables upstream process-wide log upload and keeps its logs local.
