# Phase 2 changeset conformance and independent evidence

This is test-only data and tooling for ADR 0014. It neither enables layered roots
by default nor migrates existing Silo state. Ordinary Cargo tests are offline,
unprivileged and hypervisor-free. Network acquisition, tool compilation and real
host extraction happen only through the explicit commands below.

## Independent boundaries

* `tests/support/fixtures.rs` declares operations and independently writes ustar,
  local PAX, old GNU sparse and PAX sparse 0.0/0.1/1.0 wire bytes.
* `tests/support/oracle.rs` interprets those declarations directly, with separate
  inode/name tables, queue-based root-bounded parent resolution, a pre-layer
  whiteout snapshot and its own listing construction. It imports no OCI code.
* `tests/support/abi.rs` writes expected index pages, packs, 8 MiB stream identity
  records, recipes and results from those declarations. It calls neither the
  production codec nor libvm's stream identity implementation.
* `tests/support/metadata_fixtures.rs` declares literal Linux ACL and capability
  bytes, independent text/binary ACL equivalents, SELinux/RHT and SMACK fixtures,
  raw/encoded xattr names, and actual-tar hardlink chains. ACL presence comes from
  the declared raw attribute names, not hardcoded false bits or parser output.
* `tests/support/production.rs` only observes the actual production namespace and
  streams actual pack bodies. It cannot construct oracle expectations.
* `tests/changeset_conformance.rs` compares decoder output, complete logical pack
  bytes, every index object, IDs and the final production namespace against the
  independent expectations. Hand-written listings anchor link-before-replace,
  lower-only whiteouts and hardlinked dangling symlinks. Comparator corruption
  controls cover opaque survival, hardlink groups, nanoseconds and raw names.
* `libvm/tests/changeset_qualification.rs` publishes the same fixtures through the
  real pool/catalog, compares independent IDs, removes source tars, recovers and
  composes a reused upper under two different lower bodies. Duplicate ordered
  occurrences are not replaced by deduplication of reusable results.

The independent small-fixture ABI writer intentionally handles the records in
this declared corpus. Production continuation-tree/resource-bound cases are
covered by the codec/decoder suites, not inferred from small fixture runs.

## Deterministic artifact generation

Prerequisites: the repository's locked Rust toolchain/dependency cache and host
build prerequisites. This command is offline once those are present:

```sh
make changeset-fixtures
```

The command invokes the explicitly ignored generator test, which ingests every
layer twice under different staging operation paths. Both builds compare full
logical pack and index bytes. Expected bytes are authored independently from the
declarations before either build is observed. It writes `generated/manifest.json`
and, for each layer, the exact `.tar`, `.pack`, `.index.json`, sparse/entry page
objects, `.stream.json`, `.recipe.json` and `.result.json`. There are no invented
hash constants or self-reported-only identity comparisons. Retain these generated
files in the phase commit after the supervisor observes successful generation.
Changing an identity byte is an ABI review, not a routine golden refresh.
The corpus includes a full 8 MiB zero chunk followed by a nonzero short pack tail,
in addition to empty/nonzero/all-hole cases. That full-byte boundary specimen
adds roughly 16 MiB of retained tar and pack bytes; it is not a small-limit
substitute for the actual stream chunk boundary.

`make changeset-fixtures CHANGESET_ARGS='--out target/changeset-fixtures-second'`
produces a second complete tree without replacing committed bytes. The ordinary
`committed_goldens_are_full_byte_artifacts` test checks every retained artifact,
including the independent stream/recipe/result records. No environment timestamp,
umask, source path or transport digest enters a layer recipe.

## Pinned containerd helper

Prerequisites: Linux, Go **1.26.6 or newer**, GNU `timeout`, and enough private
scratch space. No containerd daemon, runtime socket, VM, mount or hypervisor is
used. `GOTOOLCHAIN=local` prevents implicit toolchain installation.

```sh
make changeset-extractor
# Alternatively, once the exact module graph is cached:
make changeset-extractor CHANGESET_ARGS='--offline'
```

`extractor/go.mod` pins `github.com/containerd/containerd/v2 v2.4.2`. The complete
upstream v2.4.2 module graph and go.sum are retained, plus the module's checksum
from sum.golang.org. This deliberate full upstream graph avoids choosing an
unreviewed alternate transitive graph. `go build -mod=readonly` cannot silently
update it. Runtime build-info checks reject a different/replaced containerd.
The helper is test-only and is not registered in the production Go workspace.

The extraction call is exactly `archive.Apply(ctx, root, file)`, with **zero
options**: no `WithNoSameOwner`, no `WithParents`, no custom filter or whiteout
converter. Host warnings are retained verbatim in `extractor.log`. The collector
uses `lstat`, `Llistxattr` and `Lgetxattr`; hashes regular content in a stream;
never follows symlinks; and never opens FIFO/socket/device bodies. All names,
symlink targets, xattr names and values are unpadded base64url. Rows sort by raw
path bytes. Hardlink groups use the smallest raw member path per `(dev,ino)`
class, including hardlinked symlinks and FIFOs, never a host inode number.
Root metadata, nanoseconds and implicit directories are retained, not erased.

```sh
make qualify-changesets CHANGESET_ARGS='--user-namespace --out target/changeset-qualification/synthetic'
```

`--user-namespace` explicitly invokes
`unshare --user --map-auto --map-root-user --mount`; it requires suitable
subuid/subgid mappings and unprivileged user namespace support. Omit the flag to
measure the current privilege environment instead. Do not replace ownership
semantics with extractor options to manufacture equality. Linux namespace
CAP_MKNOD does not imply the host filesystem/security policy permits devices or
security/trusted xattrs. Actual propagated extraction/collection errors and the
source-backed default device skip can establish environment limits. A missing
trusted/security attribute alone cannot: successful omissions, including chown
clearing capabilities or an ignored unsupported xattr, remain semantic evidence.

Each invocation writes `differences.json`, `differences.md` and `extractor.log`.
The JSON contains both complete listings, all differing fields, layer facts,
actual Go module build info/helper hash, kernel, filesystem type, UID/GID maps,
process capability status and mount information. Outcomes are `equal`,
`semantic-difference`, `policy-difference`, `extraction-rejected` and
`environment-unavailable`. **No non-equal outcome counts as equality.** A report
may be emitted successfully while containing differences, as Phase 2 explicitly
requires. Operational failure/timeout fails the command and retains logs.
External Linux acquisition/extraction/helper subprocesses use GNU timeout at 290
seconds plus a five-second kill grace. The owner-approved focused star C build
has one combined 600-second budget across its seven steps, plus the same kill
grace; it is not an unbounded or full-schilytools build. Actual argv/deadline and
remaining per-step budget are retained with the logs.

## Published default corpus, separate from adversarial fixtures

`corpus.json` pins six real `linux/amd64` child manifests. Exact original registry
index/manifest/config bytes live in `corpus/NAME/`, and offline tests independently
recompute their SHA-256 digests, verify platform selection and layer/diff-id counts.
The pins were resolved read-only on 2026-11-01; no image layer was extracted during
coding. Pins are not mutable tag-based expectations.

| Builder | Resolver input | Exact child manifest | Actual builder evidence |
|---|---|---|---|
| Docker/BuildKit | docker.io/library/nginx:1.28.0-bookworm | `sha256:3b03dfd827515a07ccf4946000f0bbdd2a4fb6aca7499249fcb6b1f9726823d6` | Published config history has `buildkit.dockerfile.v0`; official NGINX maintainer label |
| Buildah | quay.io/buildah/stable:latest | `sha256:77a555756c942f4f0e2916a2a95bace8f109622201b3b70b008a597cf5b7aa69` | Config `io.buildah.version=1.43.5`, exact `built.by.commit`, repository and build-run URL; retained source invokes `buildah build` |
| kaniko | ghcr.io/int128/kaniko-action/example:main | `sha256:966746ce7ecad73431e51e3b588d88f17b100ebca52d8564c1a6cabbed70dbeb` | Config revision `72c12e191799ee153012b3f6d02b2a0bf9d101d0`; matching retained workflow invokes the local Kaniko action; retained `run.ts` invokes its executor |
| apko | ghcr.io/chainguard-images/static:latest | `sha256:cfcfc99c3e3a23c611610130482c821d44d6f89730c11e58234f6ddf23977609` | Config author `github.com/chainguard-dev/apko`, history `created_by=apko`, explicit single-layer-image comment |
| Nix | docker.io/nixos/nix:2.28.3 | `sha256:d078d7153763895fce17c5fbbdeb86fcfcac414ca0ba875d413c1df57be19931` | Actual per-layer store-path history and matching release source `dockerTools.buildLayeredImageWithNixDb` |
| Bazel | gcr.io/distroless/base-debian12:latest | `sha256:d2add786f2a5f43d1ab3ae54cd3193de929d0d12c378ff60891921f56f3e47ff` | Config history records actual `bazel build` targets; retained upstream release script invokes Bazel |

This is source/config provenance evidence, **not a claim that a signature or
SLSA attestation was verified**. Immutable source URLs and exact source byte hashes
are retained in `corpus/sources.json`; original workflow/script contents remain
there as reviewable evidence. In particular, kaniko's own executor release image
is built by Docker, so it is deliberately *not* mislabeled as a kaniko-produced
image. Debian nginx, Fedora Buildah and distroless cover usrmerged Linux bases;
Silo's synthetic usrmerge-parent fixtures separately require later writes through
`bin -> usr/bin`.

Acquisition is explicit and separate from tests/extraction. About 551 million bytes
of compressed layers across the six pins, plus decoded tars, packs and extraction
roots, are needed. Each output acquisition directory must be new. Run one image
at a time so failures/deadlines remain attributable:

```sh
make changeset-acquire CHANGESET_ARGS='--image docker'
make changeset-acquire CHANGESET_ARGS='--image buildah'
make changeset-acquire CHANGESET_ARGS='--image kaniko'
make changeset-acquire CHANGESET_ARGS='--image apko'
make changeset-acquire CHANGESET_ARGS='--image nix'
make changeset-acquire CHANGESET_ARGS='--image bazel'
```

The helper fetches the pinned manifest/config and every transport blob, verifies
all descriptor hashes and lengths, fully decodes/hashes the diff-id into retained
raw tar files, and writes `target/changeset-acquired/NAME/acquired.json` only after
all layers succeed. It uses no mutable tag for acquisition. Registry credentials
are anonymous bearer tokens; a deleted/rate-limited registry pin is an explicit
acquisition failure, not permission to substitute another image.

For each acquired image, use the exact name in both arguments below:

```sh
make qualify-changesets CHANGESET_ARGS='--acquired target/changeset-acquired/docker --out target/changeset-qualification/docker --user-namespace'
make qualify-changesets CHANGESET_ARGS='--acquired target/changeset-acquired/buildah --out target/changeset-qualification/buildah --user-namespace'
make qualify-changesets CHANGESET_ARGS='--acquired target/changeset-acquired/kaniko --out target/changeset-qualification/kaniko --user-namespace'
make qualify-changesets CHANGESET_ARGS='--acquired target/changeset-acquired/apko --out target/changeset-qualification/apko --user-namespace'
make qualify-changesets CHANGESET_ARGS='--acquired target/changeset-acquired/nix --out target/changeset-qualification/nix --user-namespace'
make qualify-changesets CHANGESET_ARGS='--acquired target/changeset-acquired/bazel --out target/changeset-qualification/bazel --user-namespace'
```

This first invokes the ignored acquired-image Rust test using the real decoder
and composer. Each admitted layer is built twice and full logical pack/index
bytes are compared; `silo-artifacts/case-NNNN/layer-NNNN/` retains packs, index objects,
stream maps, recipes/results, and independently reconstructed typed identities.
An explicit Silo rejection is retained if one occurs. The command then compares
with actual containerd extraction of the same retained raw layers. Published
corpus and synthetic/adversarial reports use distinct output directories. Phase 2
allows reported differences; this does not waive ADR 0014's later default gate.

### Observed admission and Phase 22 default gates

The supervisor's actual original-corpus runs admitted Docker, Buildah and Bazel,
but each retained **three root-metadata differences**: helper scratch-root mode
`0700` and current mtime versus Silo's canonical `0755` and time zero. These are
`policy-difference`, **not passes or equality**. Apko was admitted with the actual
device-creation limitation recorded. The historical original Kaniko run rejected
layers 1 and 5 for raw directory name `/`; retain that report. The owner then
approved a narrow current-profile correction: effective entry name **exactly `/`
only for a directory** becomes the explicit canonical root, preserving metadata
and operation order. `root-slash-metadata` independently exercises that real tar
spelling against the dot-root expectation; their pack/index match, but source
recipe/result identities remain distinct. Empty names, `//`, `/./`, absolute
children, non-directory `/`, absolute hardlink targets and duplicate normalized
root aliases remain rejected. The retained-byte Kaniko rerun admitted every
layer and retained only three root-metadata policy differences. The original
rejection report remains historical evidence, not the current admission verdict.

Original Nix layer 0 starts with `/nix/` and `/nix/store/`, which remain rejected.
The independently pinned additional Nix-built Cardano tracer specimen was
actually admitted by the supervisor, but its report retains five differences:
root mode/mtime and `nix/store` mtime. Its metadata/source provenance and measured
result are recorded in `.tmp/plan/research/phase-02-c4-candidates/README.md`.
It does not silently replace the original default inventory or rejection.

The exact pinned [containerd default applier](https://github.com/containerd/containerd/blob/v2.4.2/pkg/archive/tar.go#L264-L277)
unconditionally ignores an entry resolving to the extraction root. Thus changing
an extractor option or rewriting its final listing cannot honestly establish
root-metadata equality. A future separate probe could measure a real
snapshotter-backed mounted root, rather than a fresh private extraction
directory; that is a different reference surface and is **not** assumed to
produce canonical mtimes or erase the discrepancy. If that faithful measurement
still differs, an explicit owner-approved qualification-policy decision is
required. No default-qualification exemption is implemented here.

**Phase 22 must not make layered OCI the default while any default-corpus result
differs.** Successful report generation, ordinary tests, admitted non-root
entries, and classification as a policy difference do not satisfy that gate.
Candidate investigations must remain separate and retain the rejected original
evidence; accepting an alternative pin requires measured raw-layer admission and
reviewed actual builder provenance.

The final Linux synthetic comparison exercised 64 cases: 25 policy differences,
25 semantic differences, seven extraction rejections and seven environment
limitations. The real star socket was admitted and matched independent star
extraction; containerd instead created a regular file. All thirty producer-original
metadata comparisons ran with the documented Linux xattr options. In particular,
the star literal-equals specimen demonstrates why agreement between Silo and
containerd cannot substitute for agreement with the original inode. Ambiguous
escaped SCHILY names fail explicitly rather than guessing a producer dialect.

Complete local evidence is retained under `target/changeset-qualification/`:
`synthetic-final`, `kaniko-root-approved`, `socket`, `metadata-producers`, the
other original builder names, and `nix-cardano-tracer`. Reports retain both
listings, original-producer comparisons where available, typed rejections,
tool hashes, mappings and host limitations. None of these differences is waived.

## Independent real socket specimen

Owner-approved test-only source: schilytools/star commit
`e835e64f0d84a614b3c8d619ac646060ea6922a5`. `star-source.json` records the exact
upstream source tarball URL, observed size 5,898,475 bytes and actual SHA-256
`fd3db00278caecd94b3802e1f903bf235a7137511ac0a450b31d855e3a52917b`.
The source documents/emits `SCHILY.filetype=socket` in exustar dump mode:

* https://codeberg.org/schilytools/schilytools/src/commit/e835e64f0d84a614b3c8d619ac646060ea6922a5/star/star.5
* https://codeberg.org/schilytools/schilytools/src/commit/e835e64f0d84a614b3c8d619ac646060ea6922a5/star/xheader.c
* https://codeberg.org/schilytools/schilytools/src/commit/e835e64f0d84a614b3c8d619ac646060ea6922a5/star/extract.c

Prerequisites: the built pinned Go helper, network on first acquisition, GNU make,
a C compiler and normal host C build headers/libraries, curl and tar. No system
installation or production dependency is added.

```sh
make changeset-socket
make qualify-changesets CHANGESET_ARGS='--acquired runtime/oci/testdata/changesets/socket --out target/changeset-qualification/socket --user-namespace'
```

The task verifies source integrity and extracts a fresh private source tree.
It bootstraps the upstream `SMakefile` `RULES` target, builds `inc` first as
`README.compile` requires for subtree builds, then only the four static archives
named by `star/Makefile` and star itself:

```sh
make -f SMakefile RULES CC=gcc COPTX=-std=gnu17 CFLAGS= NOECHO=
make -C inc all CC=gcc COPTX=-std=gnu17 CFLAGS= NOECHO=
make -C libschily -f libschily.mk all CC=gcc COPTX=-std=gnu17 CFLAGS= NOECHO=
make -C libdeflt -f libdeflt.mk all CC=gcc COPTX=-std=gnu17 CFLAGS= NOECHO=
make -C librmt -f librmt.mk all CC=gcc COPTX=-std=gnu17 CFLAGS= NOECHO=
make -C libfind -f libfind.mk all CC=gcc COPTX=-std=gnu17 CFLAGS= NOECHO=
make -C star all CC=gcc COPTX=-std=gnu17 CFLAGS= NOECHO=
```

These are existing upstream static `.mk`/`all` targets, not guessed target names.
They avoid the root SSPM `TARGETS` traversal, profiling/shared-library variants and
unrelated programs such as cdda2wav. One combined600-second make budget bounds
the sequence; each subprocess receives only the remaining budget. Full step argv,
deadline and compiler output are retained in the build recipe/log.
This pins the supported GNU C17 language mode through upstream `COPTX`, which
`RULES/cc-gcc.rul` places last in `C_FLAGS`; `RULES/rules.cnf` and
`RULES/local.cnf` propagate those flags into configure probes too. It does not
suppress diagnostics or patch upstream source/generated headers. The actual
compiler version, make arguments and relevant flag environment are recorded in
`target/changeset-tools/star-build.json` before compilation; full commands remain
in `star-build.log`. Successful specimens also retain `build.json`.
The Go helper then creates a **real AF_UNIX socket** using
`bind`, archives with `star -c H=exustar -dump -f socket.tar socket`, independently
extracts with `star -x -f socket.tar`, and requires both `lstat` observations to be
S_IFSOCK. Go's separate archive/tar reader verifies the effective zero-body regular
member plus documented local PAX key. `socket/` retains actual upstream bytes,
source/extracted listings, full differences, tool version/binary hash, exact args
and environment. Build/create/extract logs are retained. Ordinary Rust tests read
these bytes offline and compare the socket's full metadata against the independent
star extraction; the external report still retains root-policy differences.

The real archive retains star's host dev/inode/nlink/ctime provenance. Regenerating
it is a new acquisition, not a claim that upstream dump archives ignore those
facts. Ingesting the **same retained bytes** twice must produce identical artifacts.
The synthetic minimal socket specimen is separate and deterministic. No invented
GNU socket typeflag or payload/IPC state is claimed. Output directories must be
new, never silently wiped by these commands.

## Producer-original raw xattr-name evidence

The synthetic metadata family is independent of the production parser: access
ACL v2 bytes literally encode owner6, named UID7 permission4, group4, mask4 and
other4. Its alternate ACL changes only UID7's permission to5, so both ACLs
individually agree with mode0644 while only explicit disagreement rejects a
hardlink. Equivalent textual ACLs must yield those exact literal bytes. Default
ACLs on explicit directories/root deliberately differ from their access mode.
Capability revisions1/2/3, cap40, rev3 high root IDs, terminal-NUL/no-NUL SELinux,
RHT equivalence, valid SMACK labels/EXEC/MMAP and directory/root TRANSMUTE all cross
the decoder, independent index/pack writer, namespace oracle and extraction lane.
The hardlink fixture combines ACL/capability/user attrs, advisory link-header
owner/mode/time, omitted attrs, a chain, target replacement and deletion.

Real producer evidence is a separate explicit command. Prerequisites beyond the
helper/star build are installed **GNU tar** (`tar`), **libarchive bsdtar**
(`bsdtar`), and a Linux filesystem allowing ordinary `user.*` xattrs. It installs
nothing and records the actual executable hashes, versions and exact options.

```sh
make changeset-extractor
make changeset-metadata
make qualify-changesets CHANGESET_ARGS='--acquired runtime/oci/testdata/changesets/metadata-producers --out target/changeset-qualification/metadata-producers --user-namespace'
```

`changeset-metadata` uses the same integrity-checked source and GNU C17 star build
as the socket command. It creates real files with individually isolated raw names
`user.a=b`, `user.a%b`, `user.a%3Db`, `user.a%25b`, `user.a b`, UTF-8/raw-FF names,
literal plus and an empty value, plus a complete simultaneous attribute set.
`Llistxattr`/`Lgetxattr` independently collect actual source inodes immediately
before and after each producer. They are not expectations reconstructed from tar.

Each producer writes nine isolated archives plus a complete-set archive:

* GNU tar: `--create --format=pax --xattrs --xattrs-include=* --file ARCHIVE FILE...`
* libarchive: `-c --format=pax --xattrs -f ARCHIVE FILE...` (no xattr-header override,
  retaining and checking the actual default dual-header representation).
* pinned star: `-c H=exustar -xattr-linux -f ARCHIVE FILE...` (regular metadata
  specimens do not use socket/dump mode); extraction is
  `-x -xattr-linux -f ARCHIVE`. Upstream's `-xattr` is NFSv4, not Linux xattrs:
  the pinned [option parser](https://codeberg.org/schilytools/schilytools/src/commit/e835e64f0d84a614b3c8d619ac646060ea6922a5/star/star.c#L2179)
  explicitly rejects that spelling on Linux.

The task actually extracts each unmodified archive with the same producer and
matching xattr options, independently collects that filesystem, and retains all
source-to-extracted differences. The output directory contains `producers.json`,
`producers.md`, thirty archive attempts, raw length-framed PAX key/value/record
bytes, source listings, executable/version/build evidence and create/extract logs.
Creation rejection, extraction rejection, source mutation, unavailable evidence
and semantic/policy differences are distinct outcomes. Even partial archives from
rejected attempts retain byte hashes when present. The diagnostic PAX inspector's
4 MiB evidence-record bound is not a production changeset format limit.
Regeneration is a new real acquisition: producer headers may retain source ctime
or other archive-provenance bytes. No byte-identical producer tar regeneration is
claimed. Each admitted retained archive is ingested twice with complete pack/index
byte comparisons and independently reconstructed IDs; rejection retains its
explicit category/message rather than fabricating artifacts.

The ordinary offline evidence test verifies actual source raw names, byte hashes,
the observed GNU-original `=` versus star-original literal `%3D` wire-identical
SCHILY record, and libarchive's actual dual headers. These observations do **not**
authorize guessing producer intent from incidental headers or decoding every
SCHILY percent sequence. Each independently archived name is qualified separately,
so an early ambiguous name cannot hide the other cases behind one rejection.

The final qualification command retains three distinct comparisons in its JSON:
`producerToSilo`, `producerToContainerd`, and ordinary Silo-to-containerd
`differences`, together with `producerOriginal`, typed `siloRejectionKind` and the
complete rejection message. A Silo rejection has no fabricated Silo listing.
**Silo and an extractor agreeing on the wrong producer-original name still yields
a semantic difference.** Complete name/value sets are compared, not just presence
of one expected attr. Host LSM/capability restrictions and read-side capability
revision1 versus host setxattr rejection remain external evidence, not reasons to
strip or silently change the admitted metadata.

## Research matrix and test layers

These are coverage locations, not a claim that commands were executed while coding.
`C1` denotes production decoder/parser/metadata stream unit tests; `C2` the
production namespace unit tests; `C3` codec and real publication/failure tests.
C4 is the independently authored fixture/oracle and external evidence lane above.

| Research rows | Concrete coverage boundary |
|---|---|
| N01, N02 | C4 empty/repeated and replacement/repeated fixtures; libvm ordered occurrences |
| N03, N04 | C4 opaque-first/reverse and explicit/implicit ancestor specimens |
| N05 | C4 explicit-whiteout-first/reverse; comparator wrong-survival control |
| N06, N07 | C4 directory/file/symlink replacements and explicit-parent attributes |
| N08, N09 | C4 link-before-replace, alternate lower body, link-chain-delete; real libvm reuse |
| N10, N11 | C4 structurally valid forward/self/cyclic/directory hardlink rejection |
| N12, N13 | C4 already-same-inode relink and hardlinked dangling symlink anchors |
| N14, N15 | C4 usrmerge parent, absolute/relative root clamp and 40/41-hop fixtures |
| N16, N17 | C4 dangling/looping parents and ordinal resolved-alias replacement |
| N18, N19 | C4 pre-layer symlink whiteout resolution and absent-target no-synthesis |
| M01 | C1 raw path/duplicate/control-byte parser rejection; C2 resolved path bounds |
| M02 | C4 raw names/targets, independent `.`/exact-directory `/` canonical-root metadata/index equivalence with distinct source recipe/results, and malformed/duplicate root controls; C1 strict entry boundary |
| M03, M04 | C1 marker types/names and numeric UID/GID boundary stream inputs |
| M05, M06 | C4 root/nanoseconds; C1 exact decimal times, modes and capabilities |
| M07 | C4 actual-tar ACL/capability/user hardlink chain, advisory/omitted attrs, isolated individually valid ACL conflicts; C2 metadata policy |
| M08 | C4 literal ACL/text equivalence/presence, capability revisions, SELinux/RHT, SMACK, raw names and producer-original GNU/libarchive/star evidence; C1 admission negatives |
| M09, M10 | C1 malformed/reserved attrs and encoded total/count bounds |
| M11 | C4 character/block/FIFO and hardlinked FIFO; C1 reserved/overflow rejection |
| M12 | C4 synthetic PAX socket plus independent real star archive/extraction |
| M13, M14 | C1 unsupported encodings, streamed PAX/GNU envelopes and precedence |
| V01 | C4 exact A/empty/BC pack and independent IDs; C1 aligned pack unit tests |
| V02 | C4 old GNU/PAX 0.0/0.1/1.0 and all-hole full-byte golden specimens |
| V03 | C1 sparse order/overlap/count/EOF parser negatives |
| V04 | C4 raw/gzip/zstd same-artifact test; C1 multi-member/frame inputs |
| V05, V06 | C1 independent diff-id and transport size/hash failures |
| V07, V08, V09 | C1 true decoded EOF/suffix, corruption, zstd window/skippable frames |
| V10, V11 | C1 streaming small-limit mechanisms; C2 resolved path/namespace/layers; C4 4097-byte resolved final-destination rejection |
| V12 | C2 hardlink group bound; C3 greedy entry/byte/page-list split tests |
| V13 | C1 short/checksum/oversized/overflow streaming parser inputs |
| V14 | C3 real pool+SQL failure/recovery, typed validation failure visibility |
| V15 | C4 real publication/source deletion and same upper under two lower bodies |
| V16 | C4 double complete fixture builds/independent identities; C3 stream boundaries |

Concrete C1 stream-test entry points live at the bottom of
`src/changeset/ingest.rs` in `mod tests`: `transport_size_digest_and_full_diff_id_are_independent_and_atomic`,
`all_compression_members_frames_and_suffix_bytes_participate`,
`compression_errors_after_tar_end_cannot_bypass_admission`,
`invalid_names_whiteouts_ids_times_flags_and_types_fail_before_publish`,
`pax_global_local_size_overrides_long_names_and_binary_attrs_are_exact`,
`socket_pax_and_device_profiles_have_no_payload_and_no_host_extraction`,
`all_four_sparse_forms_produce_exact_logical_pack_and_source_ranges`,
`malformed_sparse_maps_and_framing_never_return_staging`,
`tightened_bounds_are_enforced_on_actual_decoded_and_logical_bytes`,
`zstd_window_limit_is_independent_from_decoded_output_limit`,
`parser_metadata_matrix_preserves_acl_caps_labels_and_rejects_loss`,
`parser_xattr_and_path_boundaries_are_inclusive`, and
`sparse_continuations_all_holes_and_long_mtime_fractions_are_streamed`.
The sparse/PAX streaming tests in `tar.rs` additionally cover actual inputs beyond
the former arbitrary 4 MiB/one-million-range metadata caps.

Small-limit tests are mechanisms, not evidence of a 1 TiB or multi-gigabyte
benchmark. Cross-OS/architecture/scheduling lanes and geometric incompressible
benchmarks remain separately measured supervisor qualification, never inferred
from one local small-fixture execution.

## Supervisor verification commands

After all slice edits land, the supervisor runs formatting/lint/tests once, not
concurrently against partial integration. Commands, not claimed results:

```sh
cargo fmt
# Go helper is intentionally outside the product module/workspace:
gofmt -w runtime/oci/testdata/changesets/extractor/*.go
make clippy
make changeset-fixtures
make changeset-extractor
make changeset-socket
make changeset-metadata
cargo test --locked -p oci --test changeset_conformance
cargo test --locked -p libvm --test changeset_qualification
GOWORK=off GOTOOLCHAIN=local go -C runtime/oci/testdata/changesets/extractor test -mod=readonly .
```

Then run the actual synthetic, socket and six published-image acquisition/
qualification commands above and retain their JSON+Markdown evidence. No fixture
generation, build, test, formatter or extraction was executed by the slice coder.

## Phase 21 canonical EROFS compositions

`oci::composition` is a production, path-independent recipe/result boundary.
It does not select the runtime lower default or retire the flat renderer.
Recipes bind ordered `LayerResultId`/index-root pairs, a Linux OCI platform,
`silo-namespace-v1`, `silo-erofs-v1`, and `silo-overlay-v1`. Architecture and
optional variant are nonempty lowercase OCI tokens of at most 64 bytes.
Recipe and result IDs use separate `silo:composition-recipe:v1\n` and
`silo:composition-result:v1\n` SHA-256 domains. Records use the existing canonical
JSON conventions, closed true-object schemas, safe unsigned integers, strict
SHA-256 spellings, and a 1 MiB record limit. A result records the fsmeta digest,
exact padded length and lowercase raw-byte UUID, every ordered pack stream and
its byte/block range, total lower length, and the storage-owned lower stream ID.

The preparation sequence is:

1. Authenticate the layer results against the retained recipe. The optional
   `composition::authenticate_layer` helper decodes an exact canonical result
   against its expected ID, checks its diff-ID recipe and root digest, and
   authenticates all index pages using the existing changeset decoder.
2. Authenticate and retain immutable, exact pack file descriptors using the
   existing storage stream implementation. OCI deliberately supplies no pack or
   logical-lower stream hasher. Construct borrowed `erofs::Layer` values with
   each result, decoded changeset, and held pack.
3. Call `CompositionRecipe::from_layers` for a fresh recipe, or strictly decode
   the retained recipe and verify its expected recipe ID. Call
   `composition::prepare(&recipe, &layers, &mut staged_fsmeta)`.
   Preparation independently checks result IDs, canonical regenerated index
   roots, diff-ID recipe bindings, exact regular pack lengths, and namespace
   composition before invoking the EROFS encoder.
4. Compute the complete logical-lower identity with libvm's existing
   `StreamHasher`, over exact padded fsmeta followed by **every occurrence** of
   its complete logical pack bytes. Call `prepared.finalize(lower_stream)`.
   SHA-256 of the concatenation is not the stream identity ABI.
5. Publish only after finalization succeeds. Keep staging ownership and closure
   retention through failure cleanup. OCI borrows file handles and never owns
   or deletes caller paths.

`PreparedComposition::logical_extents` and `CompositionResult::logical_extents`
expose fsmeta first and then all pack occurrences, including empty slots and
repeated objects, with no paths or descriptor text. libvm resolves these
whole-object identities under closure retention and feeds the existing VMDK
planner. That planner splits nonempty occurrences at 2 GiB and emits no
zero-sector FLAT record. There is no second descriptor codec in OCI.

`composition::load_exact` invokes the bounded structural EROFS validator on an
exact retained fsmeta file, rebuilds the authenticated namespace, and compares
every result field other than the lower stream ID, which finalization compares
against the caller's independently computed ID. It does not invoke the writer.
`composition::regenerate_exact` writes only to a caller-owned staging file and
refuses any fsmeta digest/UUID/length, pack range, recipe, total-length, or final
lower-ID mismatch. A mismatch never authorizes replacing the retained result.

`erofs::encode`/`erofs::validate` accept the validated namespace, occurrence-
ordered borrowed layers, and the recipe ID's canonical ASCII spelling. Their
`EncodedFsmeta` returns digest, length, UUID and ordered device ranges.
The fixed binary ABI uses a zero boot/checksum block except for the superblock,
an occurrence-preserving device table starting in block 1, component-sorted DFS
extended inodes, sorted inline xattrs, streamed 4 KiB chunk indexes, and canonical
NULL records for all logically zero chunks regardless of host allocation.
Fsmeta is bounded at 4 GiB, total lower at 1 TiB, and occurrence count at 1024.

The unit tests at the bottom of `src/composition.rs` cover exact canonical
recipe bytes and independent identity domains/UUID derivation, malformed and
non-object record variants, authenticated result/index/page corruption,
occurrence ordering and empty/repeated slots, deterministic sparse/dense pack
copies, retained-fsmeta corruption, and regeneration/finalization mismatch
refusal. Run `cargo test --locked -p oci composition::tests` alongside
`cargo test --locked -p oci erofs::tests`. These unit tests do not replace
independent binary-reader or kernel admission evidence.

`libvm::storage::composition::{compose,load_exact,regenerate_exact}` authenticates
held pack descriptors against the existing stream ABI before invoking OCI.
Its bounded concatenation scanner preserves file offsets and repeated
occurrences, checks input fingerprints, and independently binds the fsmeta
whole-byte digest and complete lower stream map. Callers retain closure leases
through publication.

`cargo run --locked -p libvm --example erofs_qualification -- OUTPUT rich`
produces controlled fixtures through those public APIs and the existing pool
and VMDK planner. Supported fixtures are `empty`, `metadata`, `rich`, `many`
(1024 occurrences, including zero-length slots), and `split` (a sparse file
larger than 2 GiB). Every run exercises exact regeneration and retained loading.
The independent guest probe and upstream fsck/dump commands are documented in
`smoke/README.md`. Linux x86_64 is exercised locally; other host lanes remain
pending and must run the same golden vectors, not adopt host-specific digests.
