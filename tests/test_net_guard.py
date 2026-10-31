"""Outbound fetches must not be steerable at internal addresses.

Claude's review found this: a mesh directory is fetched over the network and then
supplies the witness base URLs, so a hostile document could point the client at
loopback, link-local metadata (`169.254.169.254`) or an RFC1918 host. Before this,
both call sites used urlopen directly with no address check at all.
"""
import socket

import pytest

from avm_mesh import MeshError, net
from avm_mesh.directory import load_directory


def _resolve_to(monkeypatch, mapping: dict[str, str]):
    """Make DNS answer with chosen addresses, so no test touches the network."""
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        address = mapping.get(host)
        if address is None:
            return real(host, port, *args, **kwargs)
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.mark.parametrize("address,label", [
    ("127.0.0.1", "loopback"),
    ("10.1.2.3", "RFC1918"),
    ("192.168.0.10", "RFC1918"),
    ("172.16.0.5", "RFC1918"),
    ("169.254.169.254", "link-local metadata service"),
    ("0.0.0.0", "unspecified"),
    ("::1", "IPv6 loopback"),
])
def test_internal_addresses_are_refused(monkeypatch, address, label):
    _resolve_to(monkeypatch, {"evil.example": address})
    with pytest.raises(MeshError, match="not a public address"):
        net.fetch("http://evil.example/witness", timeout=2, limit=1024)


def test_a_public_address_is_allowed_through_the_guard(monkeypatch):
    """The guard must not be a blanket refusal: a public host reaches the transport."""
    _resolve_to(monkeypatch, {"public.example": "93.184.216.34"})
    called = {}

    class FakeResponse:
        status = 200
        headers: dict = {}

        def read(self, size=-1):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class FakeOpener:
        def open(self, url, timeout=None):
            called["url"] = url
            return FakeResponse()

    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: FakeOpener())
    status, body = net.fetch("https://public.example/witness", timeout=2, limit=1024)
    assert status == 200 and body == b"{}"
    assert called["url"].startswith("https://public.example")


def test_the_opt_in_allows_loopback_for_a_witness_you_run(monkeypatch):
    _resolve_to(monkeypatch, {"localhost.example": "127.0.0.1"})

    class FakeResponse:
        status = 200
        headers: dict = {}

        def read(self, size=-1):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class FakeOpener:
        def open(self, url, timeout=None):
            return FakeResponse()

    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: FakeOpener())
    status, _ = net.fetch("http://localhost.example/witness", timeout=2, limit=1024,
                          allow_private=True)
    assert status == 200


def test_a_redirect_to_an_internal_address_is_refused(monkeypatch):
    """A public host is free to redirect -- so each hop is re-checked."""
    _resolve_to(monkeypatch, {"public.example": "93.184.216.34",
                              "metadata.example": "169.254.169.254"})
    handler = net._GuardedRedirects(allow_private=False)
    request = __import__("urllib.request", fromlist=["Request"]).Request(
        "https://public.example/start")
    with pytest.raises(MeshError, match="not a public address"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://metadata.example/")


def test_scheme_and_type_are_checked():
    for bad in ("ftp://example/key", "file:///etc/passwd", ""):
        with pytest.raises(MeshError):
            net.fetch(bad, timeout=2, limit=1024)
    with pytest.raises(MeshError, match="timeout"):
        net.fetch("https://example/x", timeout=0, limit=1024)
    with pytest.raises(MeshError, match="limit"):
        net.fetch("https://example/x", timeout=2, limit=0)


def test_a_directory_url_cannot_point_at_the_metadata_service(monkeypatch):
    """The concrete path Claude described: --directory <hostile url>."""
    _resolve_to(monkeypatch, {"hostile.example": "169.254.169.254"})
    with pytest.raises(MeshError, match="not a public address"):
        load_directory("http://hostile.example/mesh-directory.json")


def test_a_declared_small_length_with_a_larger_body_is_refused(monkeypatch):
    """A server can lie about Content-Length, so the read itself must be capped."""
    class FakeResponse:
        status = 200
        headers: dict = {"Content-Length": "10"}      # a lie

        def read(self, size: int = -1) -> bytes:
            return b" " * 1024

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> bool:
            return False

    class FakeOpener:
        def open(self, url, timeout=None):
            return FakeResponse()

    monkeypatch.setattr("avm_mesh.net._check_url", lambda *a, **k: None)
    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: FakeOpener())
    with pytest.raises(MeshError, match="returned more than"):
        net.fetch("https://example.invalid/x", timeout=2, limit=256)
