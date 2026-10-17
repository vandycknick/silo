from __future__ import annotations

import http.server
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .images import OciImage


_CA_LOCK = threading.Lock()


def ca_cert_path(cache_dir: Path) -> Path:
    return cache_dir / "registry-ca" / "ca.pem"


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30)


def ensure_ca(cache_dir: Path) -> tuple[Path, Path]:
    cert = ca_cert_path(cache_dir)
    key = cert.with_name("ca.key")
    with _CA_LOCK:
        if cert.is_file() and key.is_file():
            return cert, key
        cert.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=cert.parent) as temporary:
            temporary_key = Path(temporary) / "ca.key"
            temporary_cert = Path(temporary) / "ca.pem"
            _openssl("ecparam", "-genkey", "-name", "prime256v1", "-out", str(temporary_key))
            temporary_key.chmod(0o600)
            _openssl("req", "-x509", "-new", "-key", str(temporary_key), "-days", "3650",
                     "-subj", "/CN=silo-smoke-ca", "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(temporary_cert))
            temporary_key.replace(key)
            temporary_cert.replace(cert)
    return cert, key


@dataclass(frozen=True)
class _Publication:
    name: str
    tag: str
    image: OciImage


class LoopbackRegistry:
    def __init__(self, cache_dir: Path) -> None:
        self.ca_path, ca_key = ensure_ca(cache_dir)
        self.host = "127.0.0.1"
        self.requests = 0
        self._publications: list[_Publication] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stopped = False
        self._leaf_dir = Path(tempfile.mkdtemp(prefix="silo-smoke-registry-"))
        leaf = self._leaf_dir / "leaf.pem"
        key = self._leaf_dir / "leaf.key"
        csr = self._leaf_dir / "leaf.csr"
        extensions = self._leaf_dir / "leaf.ext"
        self._server: http.server.ThreadingHTTPServer | None = None
        try:
            _openssl("ecparam", "-genkey", "-name", "prime256v1", "-out", str(key))
            key.chmod(0o600)
            _openssl("req", "-new", "-key", str(key), "-subj", "/CN=localhost", "-out", str(csr))
            extensions.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
            with _CA_LOCK:
                _openssl("x509", "-req", "-in", str(csr), "-CA", str(self.ca_path), "-CAkey", str(ca_key),
                         "-CAcreateserial", "-days", "3650", "-extfile", str(extensions), "-out", str(leaf))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(leaf, key)
            registry = self

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, format: str, *args: object) -> None:
                    pass

                def parse_request(self) -> bool:
                    with registry._lock:
                        registry.requests += 1
                    return super().parse_request()

                def end_headers(self) -> None:
                    self.send_header("Docker-Distribution-API-Version", "registry/2.0")
                    super().end_headers()

                def do_GET(self) -> None:
                    self._serve(head=False)

                def do_HEAD(self) -> None:
                    self._serve(head=True)

                def _serve(self, *, head: bool) -> None:
                    with registry._lock:
                        publications = tuple(registry._publications)
                    path = urlsplit(self.path).path
                    body: bytes | None = None
                    media = "application/octet-stream"
                    digest: str | None = None
                    if path == "/v2/":
                        body, media = b"{}", "application/json"
                    for publication in publications:
                        image = publication.image
                        prefix = f"/v2/smoke/{publication.name}/"
                        if path in (prefix + "manifests/" + publication.tag, prefix + "manifests/" + image.manifest_digest):
                            body = image.manifest
                            media = "application/vnd.oci.image.manifest.v1+json"
                            digest = image.manifest_digest
                            break
                        if path == prefix + "blobs/" + image.config_digest:
                            body = image.config
                            digest = image.config_digest
                            break
                        if path == prefix + "blobs/" + image.layer_digest:
                            body = image.layer
                            digest = image.layer_digest
                            break
                    self.send_response(200 if body is not None else 404)
                    self.send_header("Content-Type", media)
                    self.send_header("Content-Length", str(len(body) if body is not None else 0))
                    if digest is not None:
                        self.send_header("Docker-Content-Digest", digest)
                    self.end_headers()
                    if body is not None and not head:
                        self.wfile.write(body)

            self._server = http.server.ThreadingHTTPServer((self.host, 0), Handler)
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
            self.port = self._server.server_port
        except BaseException:
            if self._server is not None:
                self._server.server_close()
            shutil.rmtree(self._leaf_dir)
            raise

    def start(self) -> None:
        if self._stopped:
            raise RuntimeError("A stopped registry cannot be restarted")
        if self._thread is None:
            assert self._server is not None
            self._thread = threading.Thread(target=self._server.serve_forever, name="smoke-registry", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        if self._stopped:
            return
        assert self._server is not None
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join()
        self._server.server_close()
        shutil.rmtree(self._leaf_dir)
        self._stopped = True

    def publish(self, image: OciImage, name: str, tag: str = "latest") -> str:
        if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", name):
            raise ValueError(f"Invalid registry image name: {name!r}")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
            raise ValueError(f"Invalid registry image tag: {tag!r}")
        if self._stopped:
            raise RuntimeError("Cannot publish to a stopped registry")
        with self._lock:
            self._publications = [entry for entry in self._publications if (entry.name, entry.tag) != (name, tag)]
            self._publications.append(_Publication(name, tag, image))
        return f"{self.host}:{self.port}/smoke/{name}:{tag}"
