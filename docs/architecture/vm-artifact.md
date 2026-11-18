# VM artifact format

A Silo VM artifact is an OCI artifact that carries the exact stored bytes of
one image or one snapshot. Pulling needs no conversion: every byte is checked
against content identities, and the pulled image or snapshot has the same id as
the source.

This document is normative. The codecs live in `runtime/oci/src/vm_artifact`
(syntax, bounds, graph verification) and `runtime/libvm/src/image/transport`
(semantic closure, export and import). The example configs below are checked
against the encoder by
`runtime/oci/src/vm_artifact/wire.rs`
(`golden_configs_are_canonical_and_documented_verbatim`), so they are the exact
bytes the encoder writes, pretty-printed.

Version identifiers in this document are the ones the current encoder writes.

## Registry layout

```text
OCI image index                       application/vnd.oci.image.index.v1+json
  artifactType: application/vnd.silo.vm.v2
├── [0] metadata manifest             artifactType application/vnd.silo.vm.metadata.v2
│       platform: {os, architecture}  (guest platform)
│       config:  application/vnd.silo.vm.config.v2+json   → VM artifact config
│       layers:  [ application/vnd.oci.empty.v1+json ]
└── [1..n] payload manifests          artifactType application/vnd.silo.vm.payloads.v2
        config:  application/vnd.oci.empty.v1+json
        layers:  every payload blob, at most 4096 per manifest and 4 MiB of JSON per manifest
```

- The index identifies exactly one VM encoding. It is not a multi-platform
  selection list; Silo checks its `artifactType` before any OCI platform
  resolution.
- The index and all manifests use OCI `schemaVersion: 2`.
- The metadata manifest is always first. Its descriptor carries the guest
  platform, which must equal the config's `guestPlatform`.
- Payload descriptors are unique across the artifact and sorted by digest. They
  are split greedily into payload manifests at the first 4096-entry or
  4 MiB-of-JSON limit. Every record page and every encoded chunk has a real
  descriptor, so registry garbage collection sees every edge.
- Empty descriptors use the OCI two-byte `{}` blob.
- Silo writes all of its JSON (config and records) canonically: compact, keys
  sorted. Readers accept only strict JSON: no duplicate keys, only unsigned
  integers up to 2^53 − 1, nesting depth at most 128, and at most 4 MiB.
  Content records must additionally be byte-for-byte canonical.

### Payload media types

| Media type | Content | Max size |
|---|---|---|
| `application/vnd.silo.vm.record.v2+json` | Canonical JSON records: content record, stream and object table roots and pages, transfer roots and pages, capture provenance | 4 MiB |
| `application/vnd.silo.vm.stream-map.v2` | Stream identity map (Merkle root over the stream's identity chunks) | 2083 B |
| `application/vnd.silo.vm.chunk.v1` | One raw 8 MiB stream chunk (shorter for the final chunk) | 8 MiB |
| `application/vnd.silo.vm.chunk.v1+zstd` | One independent zstd frame for one chunk, used only when smaller than raw | < decoded length |
| `application/vnd.silo.vm.execution.v1` | CPU and execution state (snapshot with memory only) | 16 MiB |
| `application/vnd.silo.vm.device-state.v1` | Virtual device state (snapshot with memory only) | 32 MiB |

## Config

The metadata manifest's config blob (`application/vnd.silo.vm.config.v2+json`)
describes what the artifact carries and what a reader needs before it fetches
any payload.

| Field | Meaning |
|---|---|
| `schema` | Config schema; `2` |
| `kind` | `vm-artifact` |
| `encoding` | Transfer encoding; `silo-chunks-v2` |
| `content` | `kind` (`image` or `snapshot`), `id` (the content id) and `record` (`{digest, size}` of the canonical content record) |
| `root` | `opaque-raw` or `linux-erofs-overlay` |
| `guestPlatform` | `{os: "linux", architecture: "amd64" \| "arm64"}` |
| `bootAbi` | Boot ABI of the pinned direct boot binding |
| `memory` | `null`, or the requirements of a snapshot with memory |
| `streams` | `{digest, size}` of the stream table root |
| `objects` | `{digest, size}` of the object table root |

An image:

<!-- golden: image-config -->
```json
{
  "bootAbi": "silo-direct-v2",
  "content": {
    "id": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "kind": "image",
    "record": {
      "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "size": 1874
    }
  },
  "encoding": "silo-chunks-v2",
  "guestPlatform": {
    "architecture": "arm64",
    "os": "linux"
  },
  "kind": "vm-artifact",
  "memory": null,
  "objects": {
    "digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "size": 655
  },
  "root": "linux-erofs-overlay",
  "schema": 2,
  "streams": {
    "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    "size": 412
  }
}
```

`memory` is `null` for images and for snapshots without memory. A snapshot
with memory:

<!-- golden: snapshot-config -->
```json
{
  "bootAbi": "silo-direct-v2",
  "content": {
    "id": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
    "kind": "snapshot",
    "record": {
      "digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
      "size": 2306
    }
  },
  "encoding": "silo-chunks-v2",
  "guestPlatform": {
    "architecture": "amd64",
    "os": "linux"
  },
  "kind": "vm-artifact",
  "memory": {
    "compatibilityProfile": {
      "architecture": "x86_64",
      "liveStateSchema": "silo.live-state/1",
      "profile": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
      "ramLayout": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
      "topology": "sha256:8888888888888888888888888888888888888888888888888888888888888888"
    },
    "deviceVersion": 1,
    "execution": "krun-v1",
    "executionAbi": 1,
    "executionVersion": 1,
    "provenance": {
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "size": 2210
    }
  },
  "objects": {
    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "size": 1957
  },
  "root": "opaque-raw",
  "schema": 2,
  "streams": {
    "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "size": 1203
  }
}
```

`memory.compatibilityProfile` pins the live-state schema, the CPU architecture,
and the digests of the CPU feature profile, the vCPU topology and the
guest-physical RAM layout. `memory.provenance` references the capture
provenance record.

### Validation

- `schema` is `2`, `kind` is `vm-artifact` and `encoding` is `silo-chunks-v2`.
  Anything else is refused as an unsupported format.
- Every field is required; `memory` must be present even when it is `null`.
  Unknown fields are rejected in the config and in every nested object.
- `content.kind` = `image` requires `memory` = `null`.
- `root` determines the backend: `opaque-raw` needs a backend that boots a raw
  block device; `linux-erofs-overlay` needs libkrun with the EROFS lower and
  overlay upper. Any other root is refused with a typed root-profile error.
- `memory.execution` is from a closed set (`krun-v1`), and `executionVersion`,
  `executionAbi` and `deviceVersion` must equal the supported versions (`1`).
- `memory.compatibilityProfile.liveStateSchema` is 1–256 bytes and
  `architecture` is 1–32 bytes, neither containing NUL.
- A snapshot with memory carries `memory.provenance`; it is not optional.
- Every record reference (`content.record`, `streams`, `objects`,
  `memory.provenance`) is within the 4 MiB record bound.
- `bootAbi` is not empty.

A config is also a pure projection of its content record. On import, Silo
derives the config from the verified record and the received table and
provenance references, and refuses the artifact unless it equals the received
config exactly. `root` follows the record's root profile; `memory` follows the
record's memory state; `bootAbi` and `guestPlatform` follow its pinned direct
boot binding.

## Records

All records are canonical JSON payloads with media type
`application/vnd.silo.vm.record.v2+json`.

- **Content record.** The canonical image record (`root`, `boot`, `process`) or
  snapshot record (`root`, `disks`, `platformFiles`, `configuration`, `boot`,
  `externalRequirements`, `memory`). Its digest determines the content id.
- **Stream table.** Root `{schema, kind: "stream-table", entries, pages[]}`;
  each page is `{schema, kind: "stream-table-page", firstEntry, entries[]}`.
  Each entry is `{stream, length, map, chunkSize, transport}`: the stream
  identity, the length in bytes, the identity map digest, the identity chunk
  size (8 MiB for disks, 64 KiB for RAM) and the transfer root record.
- **Object table.** Root `{schema, kind: "object-table", entries, pages[]}`;
  each page is `{schema, kind: "object-table-page", firstEntry, entries[]}`.
  Each entry is `direct {object, size, payload}` (a whole-byte object such as
  fsmeta, a kernel or an initramfs, carried as one payload) or
  `stream {object, size, stream}` (an object carried as a stream).
- **Transfer root.** `{schema, kind: "silo-chunks-v2", stream, length,
  chunkSize: 8388608, pages[]}`.
- **Transfer page.** `{schema, kind: "silo-chunk-map", firstChunk, entries[]}`.
  Each entry is `zero {length}` (not stored; the range is zeros) or
  `data {length, digest, encoded}`, where `digest` is the SHA-256 of the
  decoded chunk and `encoded` points at a raw or zstd chunk payload.

Table and transfer pages hold at most 4096 entries and 4 MiB each. Pages must
be contiguous: no gaps, overlaps or implicit tail. Every chunk is 8 MiB except
the final one.

## What each content kind carries

| Content | Streams | Objects |
|---|---|---|
| Raw image | root disk | boot files (kernel, initramfs, agent) |
| Layered image (OCI lower) | layer packs, upper | fsmeta, layer indexes, boot files |
| Snapshot without memory | root (raw, or upper and lower packs), extra disks | as above, plus platform files |
| Snapshot with memory | as above, plus the RAM stream | as above, plus execution state, device state and capture provenance |

## Pull verification order

1. Resolve the reference and fetch the index.
2. Fetch and validate the metadata manifest, the config and the table and
   transfer records, with no chunks or content record yet. Refuse the wrong
   content kind for the command (`image pull` expects an image, `restore` a
   snapshot), an unsupported format or root, or a platform that differs from
   the config.
3. Reserve worst-case disk space for the whole payload inventory.
4. Fetch the payloads into the transport cache. Each blob must match its
   descriptor's digest and size.
5. Verify the content record against `content.id`. Derive the expected stream
   and object closure and the expected config from the record and require
   them to equal the tables and the config exactly; this also pins `bootAbi`.
6. Decode every chunk, check it against its transfer page entry and place it
   into zero-filled staging. Rehash each stream into its identity map and
   check it against `map`. Check direct objects by whole-byte hash.
7. Publish to the pool and add the name.

## Push reproducibility

Push re-derives every byte from the canonical content record and reuses
retained chunk encodings, so a retried push produces identical bytes and the
same index digest. The chunk encoding (`--raw` or zstd) changes payload
digests, never the content id.

## Snapshot push

Silo does not publish snapshots: there is no `snapshot push`, and `image push`
refuses a snapshot. Snapshot push returns only with mandatory encryption and a
design for secrets held in memory (ADR 0014). Pulling snapshot artifacts is
still supported (`silo restore REF`); tests publish them through a
crate-internal path.
