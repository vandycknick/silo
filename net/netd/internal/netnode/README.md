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

Inbound admission is **connection attempts only**: an attached guest stack
and a bounded actual gonet TCP dial, with 256 simultaneous flows shared across
fallback and configured forwards. There is no guest status RPC or pre-agent
readiness assertion. The generic fallback rejects port 22, reserved for the
session's separate SSH front door. Failed attempts close and audit. Raw relays
preserve half closes and join on shutdown. Netd disables upstream process-wide
log upload and keeps its logs local.

## Configured guest forwards

`forward "tailscale"` supports raw `tcp` and explicit managed `https`.
Compilation permits only `target = "self"` and a single node binding.
`Session.New` and `Node.New` independently require trusted
`AttachmentScopeDedicatedVM` for a nonempty forward list. Unknown/shared scope
rejects before networking resources are created; current VM count and topology
never confer eligibility. Named/shared launch support is not introduced here.

Configured listeners bind before fallback registration and before enrollment
or SSH readiness. Binding is all-or-nothing. Their ports remain reserved after
listener failure and emit `forward_unavailable` rather than reaching the generic
same-port guest relay. Each admission owns one flow slot through TLS handshakes,
keepalive, and HTTP upgrades. Socket close plus the last request reference
publishes the terminal audit before releasing the slot and join ownership.

HTTPS terminates TLS 1.2+ with HTTP/1.1 ALPN and proxies plaintext HTTP exclusively
through `Guest.DialGuest`, never host DNS, host dial, or environment proxies.
The exact verified node DNS must match SNI, certificate eligibility, and HTTP
Host (with the listener port required for non-443 listeners). Incoming forwarding
headers are replaced. CONNECT and mismatched authorities do not contact the guest.
Streaming and WebSockets retain stdlib reverse-proxy handling.

Certificate acquisition uses bounded local status calls and synchronous
`CertPairWithValidity(ctx, exactDNS, 24*time.Hour)` under a cancellable
per-node semaphore, followed by identity revalidation. Do not substitute
`ListenTLS`, `GetCertificate`, or zero-validity `CertPair`: the pinned upstream
versions introduce background contexts or asynchronous renewal. TLS failures
never downgrade to plaintext or use the outgoing MITM CA.

Each HTTPS listener owns its server, transport, pooled guest sockets, and
in-flight transport dial callbacks. Cleanup closes hijacked inbound and guest
sockets as well as listeners/idle connections, then joins owners before the
guest stack closes. Session drain precedes forced connection closure.

Local regressions use real TCP/TLS sockets and gVisor guests. Generated test
certificates establish transport behavior only. Real managed certificates,
backend cancellation, restart identity, and denied-peer access require the
credential-gated `TestLiveTailnetPolicyForwards` in taild; a skipped or
prerequisite-failed live test does not qualify them.
