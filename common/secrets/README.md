# Secret provider protocol

The initial netd secrets payload stays **version 1** (16 KiB JSON). Its optional
`provider` configuration is **version 2**, selecting the following request and
response contract. Version 1 provider configuration and OAuth-refresh requests
are unsupported.

Provider stdin and stdout each carry exactly one `Content-Length: N\r\n\r\n`
frame followed by EOF. The header is capped at 128 bytes and JSON at 1 MiB.
Unknown/duplicate fields, noncanonical base64, duplicate names, truncated frames
and trailing data are rejected. netd runs the absolute executable with an empty
environment, a configured timeout (default 10 seconds), and bounded output.

```json
{"version":2,"operation":"get","grant":"<base64 JSON grant>","scope":{"machine":"<32 lowercase hex>","run":"<run id>"},"names":["codex.oauth.access_token","codex.oauth.expires_at"],"reason":"expired"}
```

`reason` is `expired` or `expires_soon`. Success returns base64 bytes, including
expiry as an RFC 3339 projection:

```json
{"version":2,"status":"ok","secrets":[{"name":"codex.oauth.access_token","value":"<base64>"},{"name":"codex.oauth.expires_at","value":"<base64>"}]}
```

Errors return `{"version":2,"status":"error","error":{"code":...,"message":...,"retryable":false}}`.
Codes are `not_found`, `read_only`, `unauthorized`, `invalid_request`,
`provider_unavailable`, `provider_rejected`, `rate_limited`, `unsupported` and
`internal_error`. netd does not expose provider messages or stderr.

Grants contain `version:2`, `store:"file:<absolute selected Home record path>"`,
`machine`, `run`, `issued_at` and `allowed:[{slot,key,field,backing_scope}]`.
`backing_scope` uses `"Home"` or `{"Machine":{"id":"..."}}`. Only selected
OAuth projections are granted, never refresh tokens, plain overrides or `silo.*`.
An OAuth credential is refreshable only when its access token and expiry are
projections of the same selected scope/key. Overriding either disables refresh
for that credential. An independent raw account ID remains supported. netd
also checks the grant's pair before invoking the provider, and does not extend
the original token's expiry using a partial response.
The entire request and grant are checked before store IO. Machine backing IDs
must match the grant, and no Home fallback is performed. All unique scopes are
locked in deterministic file-path order and retained through the request. Every
requested record kind and projection is re-read and validated under those locks
before any remote refresh or store mutation. Missing optional projections or
invalid records reject the whole request without calling the token endpoint.

Each backing record is refreshed at most once if its expiry is within 300
seconds. Each successful rotation is immediately persisted by atomic file
replacement, retaining its scope lock, before another remote refresh is attempted.
Upstream rotation is irreversible: a later endpoint failure returns an error
without a partial response/cache update, but earlier successful rotations remain
durable in the store. Retrying reuses those fresh records. This is not a global
rollback transaction across records or scopes. A local persistence failure is
reported and stops further remote refreshes. Grants scope access within the
owning uid; they are not signed authentication capabilities against that uid.

Production `silo secret provide --store-file <path>` refreshes only OpenAI Codex
backing keys through the fixed OpenAI endpoint. Local HTTP verification injects
an endpoint into the internal handler in test-only processes, without adding a
production endpoint flag or environment override.
