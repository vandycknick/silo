"""Controlled CNCF Distribution registry for OCI push/pull/delete/GC qualification.

Unlike `registry.LoopbackRegistry` (a preloaded GET/HEAD fixture), this runs the
real, pinned Distribution `registry` executable with persistent filesystem
storage, the OCI upload API, deletion and stop-the-world garbage collection:

    install_distribution(cache)      pinned release archive -> verified binary
            |
    DistributionRegistry(...)        disposable root: config, TLS leaf, storage, logs
      start() --- serve ---> stop()  TLS on 127.0.0.1, port kept across restarts
      garbage_collect()              offline only: refuses while the server runs
      client()                       bounded OCI Distribution API client
      stored_blob_digests()          on-disk blob inventory, proves physical sweep

The registry is anonymous: Silo's OCI client uses anonymous registry access, and
TLS uses a leaf signed by the shared suite CA that smoke workspaces trust through
`SSL_CERT_FILE`. Nothing here contacts or mutates a hosted registry.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import http.client
from email.message import Message
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

from .config import RUN_ROOT_PARENT
from .errors import SmokeAssertion, SmokeEnvironmentError
from .registry import ensure_ca, issue_leaf_certificate

# Source: https://github.com/distribution/distribution/releases/tag/v3.1.2 (stable,
# 2026-09-24). Archive digests equal the release API asset `digest` fields and the
# published `<archive>.sha256` assets. The annotated, GitHub-verified tag object
# c9f69bb1182cd91e41ef545c5ec8e03c4f20bd35 points at commit DISTRIBUTION_COMMIT.
# Binary digests and sizes were measured from the `registry` member of each
# verified archive; `registry --version` prints
# `github.com/distribution/distribution/v3 3.1.2`. No macOS asset is published.
DISTRIBUTION_VERSION = "3.1.2"
DISTRIBUTION_COMMIT = "3220848f15d9279c66a41aa0a257469e6aede1e9"
DISTRIBUTION_MODULE = "github.com/distribution/distribution/v3"
_RELEASE_URL = f"https://github.com/distribution/distribution/releases/download/v{DISTRIBUTION_VERSION}"
_BINARY_MEMBER = "registry"
_DOWNLOAD_TIMEOUT = 120.0
_IO_CHUNK = 1024 * 1024

EMPTY_JSON = b"{}"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_EMPTY = "application/vnd.oci.empty.v1+json"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REPOSITORY = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


@dataclass(frozen=True)
class DistributionRelease:
    """One pinned release archive and the exact executable it must contain."""

    version: str
    arch: str
    url: str
    archive_sha256: str
    archive_size: int
    binary_sha256: str
    binary_size: int

    @property
    def archive_name(self) -> str:
        return Path(urlsplit(self.url).path).name


RELEASES: Mapping[str, DistributionRelease] = {
    "amd64": DistributionRelease(
        version=DISTRIBUTION_VERSION, arch="amd64",
        url=f"{_RELEASE_URL}/registry_{DISTRIBUTION_VERSION}_linux_amd64.tar.gz",
        archive_sha256="40df2224d410f72ae425c3371873b078bbdbda3b8b612be9571f0e6751f3acc8", archive_size=16032585,
        binary_sha256="7f9e0df42bd028efb1a11eb7f92ef494156bf308770303a256d3acdcadb378cd", binary_size=55808162,
    ),
    "arm64": DistributionRelease(
        version=DISTRIBUTION_VERSION, arch="arm64",
        url=f"{_RELEASE_URL}/registry_{DISTRIBUTION_VERSION}_linux_arm64.tar.gz",
        archive_sha256="09d26f88d2c0f161bd1b8bfc6c123571cc3d291dcca8af5477b3cacc4ec95e73", archive_size=14303844,
        binary_sha256="f235c54564601f209a052e4399086d4194dd3e4964f3b7d01e1ba90abbe55c85", binary_size=52297890,
    ),
}


def host_release() -> DistributionRelease:
    system, machine = platform.system(), platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if system != "Linux" or arch is None:
        raise SmokeEnvironmentError(
            f"Distribution v{DISTRIBUTION_VERSION} publishes no registry executable for {system} {machine}; "
            "the controlled registry lane requires Linux amd64 or arm64")
    return RELEASES[arch]


@dataclass(frozen=True)
class InstalledDistribution:
    release: DistributionRelease
    binary: Path

    def identity(self) -> dict[str, object]:
        return {"version": self.release.version, "commit": DISTRIBUTION_COMMIT, "arch": self.release.arch,
                "url": self.release.url, "archiveSha256": self.release.archive_sha256,
                "binarySha256": self.release.binary_sha256, "binary": str(self.binary)}


def _sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _matches(path: Path, sha256: str, size: int) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and path.stat().st_size == size and _sha256_file(path) == sha256
    except OSError:
        return False


@contextmanager
def _install_lock(directory: Path) -> Iterator[None]:
    # Parallel pytest processes share the cache; only one may download or replace.
    with (directory / "install.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def _download(release: DistributionRelease, target: Path) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=f".{target.name}-", delete=False) as output:
            temporary = Path(output.name)
            digest = hashlib.sha256()
            received = 0
            try:
                with urllib.request.urlopen(release.url, timeout=_DOWNLOAD_TIMEOUT) as response:
                    while chunk := response.read(_IO_CHUNK):
                        received += len(chunk)
                        if received > release.archive_size:
                            raise SmokeEnvironmentError(
                                f"Distribution archive {release.url} exceeds its pinned size of {release.archive_size} bytes")
                        digest.update(chunk)
                        output.write(chunk)
            except (OSError, urllib.error.URLError) as error:
                raise SmokeEnvironmentError(
                    f"Cannot download the pinned Distribution archive {release.url} "
                    f"(sha256 {release.archive_sha256}): {error}. Place that exact archive at {target} to run offline") from error
            if received != release.archive_size or digest.hexdigest() != release.archive_sha256:
                raise SmokeEnvironmentError(
                    f"Distribution archive {release.url} does not match its pin: expected {release.archive_size} bytes "
                    f"sha256 {release.archive_sha256}, got {received} bytes sha256 {digest.hexdigest()}")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _extract_binary(archive: Path, release: DistributionRelease, target: Path) -> None:
    """Copy exactly the pinned `registry` member out of a verified archive.

    Archive member names never become output paths: the single regular member
    named `registry` is streamed into `target`, hashed and size-bounded.
    """
    temporary: Path | None = None
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            candidates = [member for member in bundle if member.name == _BINARY_MEMBER]
            if len(candidates) != 1:
                raise SmokeEnvironmentError(
                    f"{archive} must contain exactly one {_BINARY_MEMBER!r} member, found {len(candidates)}")
            member = candidates[0]
            if not member.isreg() or member.size != release.binary_size:
                raise SmokeEnvironmentError(
                    f"{archive} member {_BINARY_MEMBER!r} is not a regular {release.binary_size}-byte file")
            source = bundle.extractfile(member)
            if source is None:
                raise SmokeEnvironmentError(f"{archive} member {_BINARY_MEMBER!r} has no file content")
            with source, tempfile.NamedTemporaryFile(dir=target.parent, prefix=f".{target.name}-", delete=False) as output:
                temporary = Path(output.name)
                digest = hashlib.sha256()
                copied = 0
                while chunk := source.read(_IO_CHUNK):
                    copied += len(chunk)
                    if copied > release.binary_size:
                        raise SmokeEnvironmentError(f"{archive} member {_BINARY_MEMBER!r} exceeds its pinned size")
                    digest.update(chunk)
                    output.write(chunk)
                if copied != release.binary_size or digest.hexdigest() != release.binary_sha256:
                    raise SmokeEnvironmentError(
                        f"{archive} member {_BINARY_MEMBER!r} does not match its pin: expected sha256 "
                        f"{release.binary_sha256}, got {digest.hexdigest()}")
                output.flush()
                os.fchmod(output.fileno(), 0o755)
                os.fsync(output.fileno())
        os.replace(temporary, target)
        temporary = None
    except (tarfile.TarError, EOFError, OSError) as error:
        raise SmokeEnvironmentError(f"Cannot extract the Distribution executable from {archive}: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def install_distribution(cache_dir: Path, release: DistributionRelease | None = None) -> InstalledDistribution:
    """Return the verified pinned executable, acquiring it into `cache_dir` if needed.

    Layout: `<cache>/distribution-registry/<version>/<arch>/{<archive>,registry}`.
    A cached binary or archive is reused only after its exact SHA256 and size
    match the pin; anything else is replaced from the pinned source.
    """
    release = release or host_release()
    directory = cache_dir / "distribution-registry" / release.version / release.arch
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    binary = directory / _BINARY_MEMBER
    archive = directory / release.archive_name
    with _install_lock(directory):
        if not _matches(binary, release.binary_sha256, release.binary_size):
            if not _matches(archive, release.archive_sha256, release.archive_size):
                _download(release, archive)
            _extract_binary(archive, release, binary)
        if binary.stat().st_mode & 0o111 == 0:
            binary.chmod(0o755)
    return InstalledDistribution(release, binary)


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _checked_digest(value: str) -> str:
    if not _DIGEST.fullmatch(value):
        raise ValueError(f"Not a lowercase sha256 digest: {value!r}")
    return value


def _checked_repository(value: str) -> str:
    if len(value) > 255 or not _REPOSITORY.fullmatch(value):
        raise ValueError(f"Invalid OCI repository name: {value!r}")
    return value


def _checked_reference(value: str) -> str:
    if _DIGEST.fullmatch(value) or _TAG.fullmatch(value):
        return value
    raise ValueError(f"Invalid manifest reference (tag or sha256 digest): {value!r}")


@dataclass(frozen=True)
class RegistryResponse:
    status: int
    headers: Message
    body: bytes


@dataclass(frozen=True)
class FetchedManifest:
    media_type: str
    digest: str
    body: bytes


@dataclass(frozen=True)
class UploadSession:
    """An open blob upload: exact server `Location` path+query, kept verbatim."""

    location: str
    offset: int


class DistributionClient:
    """Bounded OCI Distribution client for fixtures and oracles, not Silo's client."""

    def __init__(self, host: str, port: int, ca_path: Path, *, timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self._context = ssl.create_default_context(cafile=str(ca_path))
        self._timeout = timeout

    def request(self, method: str, target: str, *, body: bytes | None = None,
                headers: Mapping[str, str] | None = None, limit: int = 64 * 1024 * 1024) -> RegistryResponse:
        connection = http.client.HTTPSConnection(self.host, self.port, context=self._context, timeout=self._timeout)
        try:
            connection.request(method, target, body=body, headers=dict(headers or {}))
            response = connection.getresponse()
            payload = b"" if method == "HEAD" else response.read(limit + 1)
            if len(payload) > limit:
                raise SmokeAssertion(f"{method} {target} response exceeds {limit} bytes")
            return RegistryResponse(response.status, response.headers, payload)
        except (OSError, http.client.HTTPException) as error:
            raise SmokeAssertion(f"{method} https://{self.host}:{self.port}{target} failed: {error}") from error
        finally:
            connection.close()

    def _expect(self, response: RegistryResponse, expected: int, action: str) -> RegistryResponse:
        if response.status != expected:
            raise SmokeAssertion(f"{action}: expected HTTP {expected}, got {response.status}: {response.body[:2048]!r}")
        return response

    def _upload_target(self, location: str | None) -> str:
        if not location:
            raise SmokeAssertion("Upload response has no Location")
        parts = urlsplit(location)
        if parts.scheme or parts.netloc:
            if parts.scheme != "https" or parts.netloc != f"{self.host}:{self.port}":
                raise SmokeAssertion(f"Upload Location leaves the registry origin: {location}")
        return parts.path + (f"?{parts.query}" if parts.query else "")

    def ping(self) -> None:
        response = self._expect(self.request("GET", "/v2/"), 200, "GET /v2/")
        if response.headers.get("Docker-Distribution-API-Version") != "registry/2.0":
            raise SmokeAssertion(f"/v2/ lacks Docker-Distribution-API-Version: {dict(response.headers)}")

    def start_upload(self, repository: str) -> UploadSession:
        response = self._expect(self.request("POST", f"/v2/{_checked_repository(repository)}/blobs/uploads/",
                                             headers={"Content-Length": "0"}), 202, "start upload")
        return UploadSession(self._upload_target(response.headers.get("Location")), 0)

    def upload_chunk(self, session: UploadSession, data: bytes) -> UploadSession:
        """PATCH the next contiguous range; returns the server-acknowledged state."""
        if not data:
            raise ValueError("An upload chunk must contain at least one byte")
        end = session.offset + len(data) - 1
        response = self._expect(self.request("PATCH", session.location, body=data, headers={
            "Content-Type": "application/octet-stream", "Content-Length": str(len(data)),
            "Content-Range": f"{session.offset}-{end}"}), 202, "upload chunk")
        acknowledged = _held_bytes(response.headers.get("Range"), end + 1)
        if acknowledged != end + 1:
            raise SmokeAssertion(f"Upload acknowledged {acknowledged} bytes, expected {end + 1}")
        return UploadSession(self._upload_target(response.headers.get("Location")), acknowledged)

    def upload_status(self, session: UploadSession) -> UploadSession:
        """Server-held offset of an existing session, e.g. after a lost PATCH response."""
        response = self._expect(self.request("GET", session.location), 204, "upload status")
        return UploadSession(self._upload_target(response.headers.get("Location")),
                             _held_bytes(response.headers.get("Range"), session.offset))

    def finish_upload(self, session: UploadSession, digest: str, data: bytes = b"") -> str:
        separator = "&" if "?" in session.location else "?"
        response = self._expect(self.request("PUT", f"{session.location}{separator}digest={quote(_checked_digest(digest))}",
                                             body=data, headers={"Content-Type": "application/octet-stream",
                                                                 "Content-Length": str(len(data))}), 201, "finish upload")
        if response.headers.get("Docker-Content-Digest") != digest:
            raise SmokeAssertion(f"Upload committed {response.headers.get('Docker-Content-Digest')}, expected {digest}")
        return digest

    def push_blob(self, repository: str, data: bytes) -> str:
        return self.finish_upload(self.start_upload(repository), digest_of(data), data)

    def push_manifest(self, repository: str, reference: str, body: bytes, media_type: str) -> str:
        target = f"/v2/{_checked_repository(repository)}/manifests/{_checked_reference(reference)}"
        response = self.request("PUT", target, body=body, headers={"Content-Type": media_type,
                                                                   "Content-Length": str(len(body))})
        self._expect(response, 201, f"PUT manifest {repository}:{reference}")
        digest = digest_of(body)
        if response.headers.get("Docker-Content-Digest") != digest:
            raise SmokeAssertion(f"Manifest stored as {response.headers.get('Docker-Content-Digest')}, expected {digest}")
        return digest

    def manifest(self, repository: str, reference: str) -> FetchedManifest | None:
        target = f"/v2/{_checked_repository(repository)}/manifests/{_checked_reference(reference)}"
        response = self.request("GET", target, headers={"Accept": f"{OCI_INDEX}, {OCI_MANIFEST}"}, limit=4 * 1024 * 1024)
        if response.status == 404:
            return None
        self._expect(response, 200, f"GET manifest {repository}:{reference}")
        digest = digest_of(response.body)
        if response.headers.get("Docker-Content-Digest") != digest or (_DIGEST.fullmatch(reference) and reference != digest):
            raise SmokeAssertion(f"Manifest {repository}:{reference} bytes hash to {digest}, "
                                 f"server claimed {response.headers.get('Docker-Content-Digest')}")
        return FetchedManifest(response.headers.get("Content-Type", ""), digest, response.body)

    def blob(self, repository: str, digest: str) -> bytes | None:
        response = self.request("GET", f"/v2/{_checked_repository(repository)}/blobs/{_checked_digest(digest)}")
        if response.status == 404:
            return None
        self._expect(response, 200, f"GET blob {repository}@{digest}")
        if digest_of(response.body) != digest:
            raise SmokeAssertion(f"Blob {repository}@{digest} returned bytes hashing to {digest_of(response.body)}")
        return response.body

    def blob_exists(self, repository: str, digest: str) -> bool:
        response = self.request("HEAD", f"/v2/{_checked_repository(repository)}/blobs/{_checked_digest(digest)}")
        if response.status not in (200, 404):
            raise SmokeAssertion(f"HEAD blob {repository}@{digest}: unexpected HTTP {response.status}")
        return response.status == 200

    def delete_manifest(self, repository: str, reference: str) -> None:
        """Delete by digest (manifest and every tag naming it) or by tag (only that tag)."""
        target = f"/v2/{_checked_repository(repository)}/manifests/{_checked_reference(reference)}"
        self._expect(self.request("DELETE", target), 202, f"DELETE manifest {repository}:{reference}")

    def delete_blob(self, repository: str, digest: str) -> None:
        target = f"/v2/{_checked_repository(repository)}/blobs/{_checked_digest(digest)}"
        self._expect(self.request("DELETE", target), 202, f"DELETE blob {repository}@{digest}")

    def tags(self, repository: str) -> list[str]:
        response = self.request("GET", f"/v2/{_checked_repository(repository)}/tags/list")
        if response.status == 404:
            return []
        self._expect(response, 200, f"GET tags {repository}")
        parsed = json.loads(response.body)
        tags = parsed.get("tags") or []
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise SmokeAssertion(f"Malformed tag list for {repository}: {parsed!r}")
        return sorted(tags)


def _held_bytes(range_header: str | None, believed: int) -> int:
    """Bytes the server holds, from Distribution's inclusive `Range: 0-N`.

    Distribution reports both an empty and a one-byte upload as `0-0`; only the
    caller's own count (`believed`, 0 or 1) can disambiguate. Any other belief
    with `0-0` means the server lost data and is reported, not guessed.
    """
    match = re.fullmatch(r"0-(\d+)", range_header or "")
    if match is None:
        raise SmokeAssertion(f"Malformed upload Range header: {range_header!r}")
    end = int(match.group(1))
    if end > 0:
        return end + 1
    if believed in (0, 1):
        return believed
    raise SmokeAssertion(f"Upload Range 0-0 is ambiguous for a session believed to hold {believed} bytes")


@dataclass(frozen=True)
class GcReport:
    delete_untagged: bool
    dry_run: bool
    marked: frozenset[str]
    eligible_blobs: frozenset[str]
    eligible_manifests: frozenset[tuple[str, str]]
    removed_layer_links: frozenset[tuple[str, str]]
    stdout: str
    stderr: str


_GC_MARK = re.compile(r"(\S+): marking (?:manifest|blob) (sha256:[0-9a-f]{64}) ?")
_GC_SUMMARY = re.compile(r"(\d+) blobs marked, (\d+) blobs and (\d+) manifests eligible for deletion")
_GC_BLOB = re.compile(r"blob eligible for deletion: (sha256:[0-9a-f]{64})")
_GC_MANIFEST = re.compile(r"manifest eligible for deletion: \{(\S+) (sha256:[0-9a-f]{64}) \[[^\]]*\]\}")
_GC_LINK = re.compile(r"(\S+): layer link eligible for deletion: (sha256:[0-9a-f]{64})")
_GC_NO_TAGS = re.compile(r"manifest tags path of repository (\S+) does not exist")


def parse_gc_output(stdout: str, stderr: str, *, delete_untagged: bool, dry_run: bool) -> GcReport:
    """Strictly parse v3.1.2 `garbage-collect` stdout; unknown lines are drift, not noise."""
    marked: set[str] = set()
    blobs: set[str] = set()
    manifests: set[tuple[str, str]] = set()
    links: set[tuple[str, str]] = set()
    summary: tuple[int, int, int] | None = None
    for line in stdout.splitlines():
        if not line.strip() or _GC_NO_TAGS.fullmatch(line):
            continue
        if match := _GC_MARK.fullmatch(line):
            marked.add(match.group(2))
        elif match := _GC_SUMMARY.fullmatch(line):
            if summary is not None:
                raise SmokeAssertion(f"Repeated garbage-collect summary:\n{stdout}")
            summary = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        elif match := _GC_BLOB.fullmatch(line):
            blobs.add(match.group(1))
        elif match := _GC_MANIFEST.fullmatch(line):
            manifests.add((match.group(1), match.group(2)))
        elif match := _GC_LINK.fullmatch(line):
            links.add((match.group(1), match.group(2)))
        elif not _REPOSITORY.fullmatch(line):
            raise SmokeAssertion(f"Unrecognized garbage-collect output line {line!r}:\n{stdout}")
    if summary is None:
        raise SmokeAssertion(f"garbage-collect printed no summary:\n{stdout}\n{stderr}")
    if summary != (len(marked), len(blobs), len(manifests)):
        raise SmokeAssertion(f"garbage-collect summary {summary} disagrees with its listing "
                             f"({len(marked)}, {len(blobs)}, {len(manifests)}):\n{stdout}")
    if manifests and not delete_untagged:
        raise SmokeAssertion(f"garbage-collect removed manifests without --delete-untagged:\n{stdout}")
    return GcReport(delete_untagged, dry_run, frozenset(marked), frozenset(blobs), frozenset(manifests),
                    frozenset(links), stdout, stderr)


_LISTENING = re.compile(r"listening on 127\.0\.0\.1:(\d+), tls")


def default_parent() -> Path:
    """Same scratch placement as `Workspace`: process TMPDIR on Linux, else the run root."""
    return Path(os.environ.get("TMPDIR", RUN_ROOT_PARENT) if platform.system() == "Linux" else RUN_ROOT_PARENT)


class DistributionRegistry:
    """One disposable registry instance with persistent storage across restarts.

    The root directory is created by and exclusively owned by this instance;
    `close` removes only that directory. The listening port is chosen by the
    kernel on first start and reused on every restart, so references recorded
    by Silo stay valid across stop/GC/start.
    """

    host = "127.0.0.1"

    def __init__(self, installed: InstalledDistribution, cache_dir: Path, parent: Path | None = None, *,
                 startup_timeout: float = 30.0, stop_timeout: float = 20.0, gc_timeout: float = 300.0) -> None:
        self.installed = installed
        self.ca_path, _ = ensure_ca(cache_dir)
        self.root = Path(tempfile.mkdtemp(prefix="silo-smoke-distribution-", dir=parent or default_parent()))
        self.root.chmod(0o700)
        self.storage = self.root / "storage"
        self.logs = self.root / "logs"
        self.config_path = self.root / "config.yml"
        self.port: int | None = None
        self._startup_timeout = startup_timeout
        self._stop_timeout = stop_timeout
        self._gc_timeout = gc_timeout
        self._process: subprocess.Popen[bytes] | None = None
        self._log: Path | None = None
        self._runs = 0
        self._gcs = 0
        # One HTTP secret for the instance's life keeps upload `_state` valid across restarts.
        self._secret = secrets.token_hex(32)
        try:
            for directory in (self.storage, self.logs, self.root / "tls"):
                directory.mkdir(mode=0o700)
            self._certificate, self._key = issue_leaf_certificate(cache_dir, self.root / "tls")
        except BaseException:
            shutil.rmtree(self.root)
            raise

    @property
    def running(self) -> bool:
        return self._process is not None

    @property
    def address(self) -> str:
        if self.port is None:
            raise SmokeAssertion("The registry has not been started")
        return f"{self.host}:{self.port}"

    def reference(self, repository: str, reference: str) -> str:
        """A Silo/OCI reference: `host:port/repo:tag` or `host:port/repo@sha256:...`."""
        separator = "@" if _DIGEST.fullmatch(_checked_reference(reference)) else ":"
        return f"{self.address}/{_checked_repository(repository)}{separator}{reference}"

    def client(self, *, timeout: float = 30.0) -> DistributionClient:
        if self.port is None:
            raise SmokeAssertion("The registry has not been started")
        return DistributionClient(self.host, self.port, self.ca_path, timeout=timeout)

    def _config(self) -> dict[str, object]:
        # JSON is valid YAML flow syntax for Distribution's yaml.v2 parser and
        # quotes every path exactly.
        return {
            "version": "0.1",
            "log": {"level": "info", "formatter": "json", "accesslog": {"disabled": False}},
            "storage": {
                "filesystem": {"rootdirectory": str(self.storage)},
                "delete": {"enabled": True},
                "redirect": {"disable": True},
                # Keep abandoned uploads for explicit resume tests; GC owns cleanup.
                "maintenance": {"uploadpurging": {"enabled": False}, "readonly": {"enabled": False}},
            },
            "http": {
                "addr": f"{self.host}:{self.port or 0}",
                "secret": self._secret,
                "draintimeout": "5s",
                "tls": {"certificate": str(self._certificate), "key": str(self._key), "minimumtls": "tls1.2"},
                "headers": {"X-Content-Type-Options": ["nosniff"]},
            },
            # Explicit defaults: reject manifest URLs and require every index child to exist.
            "validation": {"disabled": False, "manifests": {"indexes": {"platforms": "all"}}},
        }

    def _write_config(self) -> None:
        temporary = self.config_path.with_name(".config.yml.tmp")
        temporary.write_text(json.dumps(self._config(), indent=2) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.config_path)

    def _env(self) -> dict[str, str]:
        # A clean environment: no inherited LISTEN_FDS socket activation, REGISTRY_*
        # overrides, proxies or OTLP exporter targets.
        return {"HOME": str(self.root), "PATH": os.defpath, "OTEL_TRACES_EXPORTER": "none"}

    def log_text(self) -> str:
        return self._log.read_text(errors="replace") if self._log is not None and self._log.exists() else ""

    def start(self) -> None:
        if self._process is not None:
            raise SmokeAssertion("The registry is already running")
        self._runs += 1
        self._write_config()
        self._log = self.logs / f"serve-{self._runs}.log"
        with self._log.open("ab") as log:
            self._process = subprocess.Popen(
                [str(self.installed.binary), "serve", str(self.config_path)], env=self._env(), cwd=self.root,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, close_fds=True)
        try:
            port = self._await_listening()
            if self.port is not None and port != self.port:
                raise SmokeAssertion(f"Registry restarted on port {port}, expected {self.port}")
            self.port = port
            self._await_ready()
        except BaseException:
            self._terminate(expect_clean=False)
            raise
        self._write_identity()

    def _await_listening(self) -> int:
        assert self._process is not None
        deadline = time.monotonic() + self._startup_timeout
        while True:
            for line in self.log_text().splitlines():
                try:
                    message = json.loads(line).get("msg", "")
                except (json.JSONDecodeError, AttributeError):
                    continue
                if isinstance(message, str) and (match := _LISTENING.fullmatch(message)):
                    return int(match.group(1))
            status = self._process.poll()
            if status is not None:
                raise SmokeAssertion(f"Registry exited with {status} before listening:\n{self.log_text()[-8192:]}")
            if time.monotonic() >= deadline:
                raise SmokeAssertion(f"Registry did not listen within {self._startup_timeout}s:\n{self.log_text()[-8192:]}")
            time.sleep(0.05)

    def _await_ready(self) -> None:
        assert self._process is not None
        deadline = time.monotonic() + self._startup_timeout
        while True:
            try:
                self.client(timeout=5.0).ping()
                return
            except SmokeAssertion as error:
                if self._process.poll() is not None or time.monotonic() >= deadline:
                    raise SmokeAssertion(f"Registry never answered /v2/: {error}\n{self.log_text()[-8192:]}") from error
                time.sleep(0.05)

    def stop(self) -> None:
        """Graceful SIGTERM shutdown; a non-zero exit or forced kill is a failure."""
        if self._process is None:
            raise SmokeAssertion("The registry is not running")
        self._terminate(expect_clean=True)

    def _terminate(self, *, expect_clean: bool) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                status = process.wait(timeout=self._stop_timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=self._stop_timeout)
                if expect_clean:
                    raise SmokeAssertion(f"Registry ignored SIGTERM for {self._stop_timeout}s and was killed:\n"
                                         f"{self.log_text()[-8192:]}")
                return
        finally:
            self._process = None
        if expect_clean and status != 0:
            raise SmokeAssertion(f"Registry exited with {status} on SIGTERM:\n{self.log_text()[-8192:]}")
        if self.port is not None:
            with socket.socket() as probe:
                probe.settimeout(1.0)
                if probe.connect_ex((self.host, self.port)) == 0:
                    raise SmokeAssertion(f"Port {self.port} still accepts connections after registry exit")

    def restart(self) -> None:
        self.stop()
        self.start()

    def garbage_collect(self, *, delete_untagged: bool, dry_run: bool = False) -> GcReport:
        """Run Distribution's stop-the-world collector against the persistent storage.

        Upstream requires the registry to be stopped or read-only during GC;
        this harness admits only the stopped state.
        """
        if self._process is not None:
            raise SmokeAssertion("Refusing garbage-collect while the registry serves; stop it first")
        self._gcs += 1
        self._write_config()
        command = [str(self.installed.binary), "garbage-collect", *(["--delete-untagged"] if delete_untagged else []),
                   *(["--dry-run"] if dry_run else []), str(self.config_path)]
        try:
            result = subprocess.run(command, env=self._env(), cwd=self.root, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, errors="replace", timeout=self._gc_timeout)
        except subprocess.TimeoutExpired as error:
            raise SmokeAssertion(f"garbage-collect exceeded {self._gc_timeout}s: {error}") from error
        log = self.logs / f"gc-{self._gcs}.log"
        log.write_text(f"$ {' '.join(command)}\nexit {result.returncode}\n--- stdout\n{result.stdout}--- stderr\n{result.stderr}")
        if result.returncode != 0:
            raise SmokeAssertion(f"garbage-collect exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
        return parse_gc_output(result.stdout, result.stderr, delete_untagged=delete_untagged, dry_run=dry_run)

    def stored_blob_digests(self) -> frozenset[str]:
        """Blob digests physically present in filesystem storage (`blobs/sha256/xx/<hex>/data`)."""
        root = self.storage / "docker/registry/v2/blobs/sha256"
        if not root.is_dir():
            return frozenset()
        found: set[str] = set()
        for prefix in root.iterdir():
            if not prefix.is_dir():
                continue
            for entry in prefix.iterdir():
                if (entry / "data").is_file() and re.fullmatch(r"[0-9a-f]{64}", entry.name) and entry.name[:2] == prefix.name:
                    found.add("sha256:" + entry.name)
        return frozenset(found)

    def identity(self) -> dict[str, object]:
        return self.installed.identity() | {
            "address": self.address if self.port is not None else None,
            "configSha256": _sha256_file(self.config_path) if self.config_path.exists() else None,
            "root": str(self.root),
        }

    def _write_identity(self) -> None:
        (self.root / "identity.json").write_text(json.dumps(self.identity(), indent=2, sort_keys=True) + "\n")

    def close(self, *, retain: bool = False) -> None:
        """Stop if running (killing if needed), then remove the owned root unless retained."""
        try:
            self._terminate(expect_clean=False)
        finally:
            if retain:
                print(f"Distribution registry evidence retained at {self.root}")
            else:
                shutil.rmtree(self.root)


@contextmanager
def running_distribution(cache_dir: Path, parent: Path | None = None, *, keep: bool = False) -> Iterator[DistributionRegistry]:
    """Install, start and finally clean up one registry; evidence is kept on failure or `keep`."""
    instance = DistributionRegistry(install_distribution(cache_dir), cache_dir, parent)
    failed = True
    try:
        instance.start()
        yield instance
        failed = False
    finally:
        instance.close(retain=failed or keep)
