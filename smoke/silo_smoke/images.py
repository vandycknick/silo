from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import os
import platform
import posixpath
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ALPINE_VERSION = "3.21.3"
ALPINE_SHA256: dict[str, str] = {
    "x86_64": "1a694899e406ce55d32334c47ac0b2efb6c06d7e878102d1840892ad44cd5239",
    "aarch64": "ead8a4b37867bd19e7417dd078748e2312c0aea364403d96758d63ea8ff261ea",
}
APK_SHA256: dict[tuple[str, str, str], str] = {
    ("ca-certificates", "20260909-r0", "x86_64"): "21cbb1f7b825c7fee9fe469e0ee18f61da7fe62075796daf8c94b5da74b355d3",
    ("ca-certificates", "20260909-r0", "aarch64"): "e229a539af3c7c9042ffd359089305fa9e98bd778a6b53e6cb077be5506d9526",
}



def alpine_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    raise ValueError(f"Unsupported Alpine architecture: {machine}")


def oci_arch() -> str:
    return {"x86_64": "amd64", "aarch64": "arm64"}[alpine_arch()]


def fetch_alpine(cache_dir: Path) -> Path:
    arch = alpine_arch()
    expected = ALPINE_SHA256[arch]
    cache_dir.mkdir(parents=True, exist_ok=True)
    filename = f"alpine-minirootfs-{ALPINE_VERSION}-{arch}.tar.gz"
    target = cache_dir / filename
    if target.is_file():
        with target.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() == expected:
                return target
    url = f"https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/{arch}/{filename}"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=cache_dir, prefix=f".{filename}-", delete=False) as output:
            temporary = Path(output.name)
            digest = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=120) as response:
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != expected:
                raise ValueError(f"Alpine SHA256 mismatch for {url}: expected {expected}, got {digest.hexdigest()}")
        os.replace(temporary, target)
        return target
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def fetch_apk(cache_dir: Path, name: str, version: str, arch: str) -> Path:
    expected = APK_SHA256[(name, version, arch)]
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / f"{name}-{version}-{arch}.apk"
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
        return target
    url = f"https://dl-cdn.alpinelinux.org/alpine/v3.21/main/{arch}/{name}-{version}.apk"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"APK SHA256 mismatch for {url}")
    with tempfile.NamedTemporaryFile(dir=cache_dir, delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(data)
            output.flush()
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    return target


def apk_members(path: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    result: list[tuple[tarfile.TarInfo, bytes | None]] = []
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(path.read_bytes())), mode="r:", ignore_zeros=True) as archive:
        for member in archive:
            if member.name.startswith("."):
                continue
            name = _path(member.name)
            if name in seen:
                raise ValueError(f"Duplicate APK payload path: {name}")
            seen.add(name)
            if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"Unsupported APK member: {name}")
            if member.islnk():
                _path(member.linkname)
            source = archive.extractfile(member) if member.isreg() else None
            try:
                result.append((member, source.read() if source is not None else None))
            finally:
                if source is not None:
                    source.close()
    return result


@dataclass(frozen=True)
class ApkPackage:
    name: str
    version: str


@dataclass(frozen=True)
class GuestFile:
    data: bytes
    mode: int = 0o644
    uid: int = 0
    gid: int = 0


@dataclass(frozen=True)
class GuestDir:
    mode: int = 0o755
    uid: int = 0
    gid: int = 0


@dataclass(frozen=True)
class ImageSpec:
    name: str
    files: dict[str, GuestFile | bytes]
    dirs: dict[str, GuestDir]
    remove: frozenset[str]
    append: dict[str, bytes]
    packages: tuple[ApkPackage, ...] = ()


@dataclass(frozen=True)
class OciImage:
    manifest: bytes
    manifest_digest: str
    config: bytes
    config_digest: str
    layer: bytes
    layer_digest: str


def _path(name: str, *, base: bool = False) -> str:
    if base and name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if (not name or name == "." or name.startswith("/") or "\\" in name
            or "\x00" in name or ".." in name.split("/") or posixpath.normpath(name) != name):
        raise ValueError(f"Unsafe guest archive path: {name!r}")
    return name


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build(spec: ImageSpec, base_tar_gz: Path) -> OciImage:
    files: dict[str, GuestFile] = {}
    dirs: dict[str, GuestDir] = {}
    append: dict[str, bytes] = {}
    seen: set[str] = set()
    for paths in (spec.files, spec.dirs, spec.append):
        for path in paths:
            name = _path(path)
            if name in seen:
                raise ValueError(f"Duplicate guest archive path: {name!r}")
            seen.add(name)
    for path, file in spec.files.items():
        files[_path(path)] = GuestFile(file) if isinstance(file, bytes) else file
    dirs = {_path(path): directory for path, directory in spec.dirs.items()}
    append = {_path(path): data for path, data in spec.append.items()}
    remove = {_path(path) for path in spec.remove}
    if remove & seen:
        raise ValueError("Removed guest paths cannot also be overlaid or appended")
    for entry in (*files.values(), *dirs.values()):
        if entry.mode < 0 or entry.mode & ~0o777 or entry.uid < 0 or entry.gid < 0:
            raise ValueError("Invalid guest archive mode or ownership")
    payload: dict[str, tuple[tarfile.TarInfo, bytes | None]] = {}
    for package in spec.packages:
        path = fetch_apk(base_tar_gz.parent, package.name, package.version, alpine_arch())
        for member, data in apk_members(path):
            name = _path(member.name)
            if name not in remove and name not in files and name not in dirs:
                payload[name] = (member, data)

    archive = io.BytesIO()
    with tarfile.open(base_tar_gz, "r:gz") as base:
        members: dict[str, tarfile.TarInfo] = {}
        for member in base.getmembers():
            if member.name in (".", "./") and member.isdir():
                continue
            name = _path(member.name, base=True)
            if name in members:
                raise ValueError(f"Duplicate base archive path: {name!r}")
            members[name] = member
        for name in append:
            if name not in members or not members[name].isreg():
                raise ValueError(f"Append requires an existing regular file: {name!r}")
        kinds = {name: member.isdir() for name, member in members.items() if name not in remove}
        kinds.update({name: member.isdir() for name, (member, _) in payload.items()})
        kinds.update({name: False for name in files})
        kinds.update({name: True for name in dirs})
        for name in seen | payload.keys():
            parent = posixpath.dirname(name)
            while parent:
                if parent in kinds and not kinds[parent]:
                    raise ValueError(f"Guest archive parent is not a directory: {parent!r}")
                parent = posixpath.dirname(parent)
        with tarfile.open(fileobj=archive, mode="w", format=tarfile.GNU_FORMAT) as output:
            for name, member in members.items():
                if name in remove or name in files or name in dirs or name in payload:
                    continue
                header = copy.copy(member)
                header.name = name + ("/" if member.isdir() else "")
                source = base.extractfile(member) if member.isreg() else None
                try:
                    if name in append:
                        assert source is not None
                        data = source.read()
                        if data and not data.endswith(b"\n"):
                            data += b"\n"
                        data += append[name]
                        header.size = len(data)
                        header.mtime = 0
                        output.addfile(header, io.BytesIO(data))
                    else:
                        output.addfile(header, source)
                finally:
                    if source is not None:
                        source.close()
            for name, (member, data) in sorted(payload.items()):
                header = copy.copy(member)
                header.name = name
                output.addfile(header, io.BytesIO(data) if data is not None else None)
            for name, directory in sorted(dirs.items()):
                header = tarfile.TarInfo(name + "/")
                header.type = tarfile.DIRTYPE
                header.mode, header.uid, header.gid = directory.mode, directory.uid, directory.gid
                output.addfile(header)
            for name, file in sorted(files.items()):
                header = tarfile.TarInfo(name)
                header.mode, header.uid, header.gid = file.mode, file.uid, file.gid
                header.size = len(file.data)
                output.addfile(header, io.BytesIO(file.data))
    raw = archive.getvalue()
    layer = gzip.compress(raw, mtime=0)
    config = json.dumps({"architecture": oci_arch(), "os": "linux", "rootfs": {"type": "layers", "diff_ids": [_digest(raw)]}, "config": {}}, separators=(",", ":")).encode()
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": _digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": _digest(layer), "size": len(layer)}],
    }, separators=(",", ":")).encode()
    return OciImage(manifest, _digest(manifest), config, _digest(config), layer, _digest(layer))


BASIC = ImageSpec(
    name="basic",
    files={"etc/proof": b"silo-smoke-proof\n"},
    dirs={"home/silo": GuestDir(uid=1000, gid=1000)},
    remove=frozenset({"sbin/init"}),
    append={"etc/passwd": b"silo:x:1000:1000:silo:/home/silo:/bin/sh\n", "etc/group": b"silo:x:1000:\n"},
)


CA_TRUST = ImageSpec(
    name="ca-trust",
    files=BASIC.files,
    dirs=BASIC.dirs,
    remove=BASIC.remove,
    append=BASIC.append,
    packages=(ApkPackage("ca-certificates", "20260909-r0"),),
)
