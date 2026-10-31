"""Outbound fetching, guarded against server-side request forgery.

Two places fetch URLs a caller does not fully control: a mesh directory (which the
user may pass as a URL, and which then supplies the witness base URLs) and the witness
endpoints themselves. Before this module both used ``urlopen`` directly, so a document
could point the client at ``http://169.254.169.254/`` and the client would fetch it.

The rule: resolve the host, refuse anything that is not a public address, and re-validate
every redirect hop, because a public host is free to redirect to a private one. Loopback
is refused by default too -- a local witness is a legitimate deployment, but it has to be
opted into explicitly rather than inherited from whatever document was fetched.

This is defence in depth, not a sandbox: it stops the obvious internal-target fetches and
makes the trust boundary explicit. It cannot stop a name that resolves differently between
our check and the connection's own resolution, which is why the allowlist is opt-in and the
response is size-capped and timed out as well.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request

from .receipt import MeshError

#: Address ranges that must never be fetched on a caller's behalf.
def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified)


def _check_url(url: str, *, allow_private: bool) -> None:
    if not isinstance(url, str) or not url:
        raise MeshError("URL must be a non-empty string")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise MeshError(f"unsupported URL scheme {parsed.scheme!r}; only http and https")
    host = parsed.hostname
    if not host:
        raise MeshError("URL has no host")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise MeshError(f"cannot resolve {host}: {exc}") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise MeshError(f"{host} resolved to no addresses")
    for address in addresses:
        if not _is_public(address):
            raise MeshError(
                f"refusing to fetch {host}: it resolves to {address}, which is not a public "
                "address (pass allow_private=True only for a witness you run yourself)")


class _GuardedRedirects(urllib.request.HTTPRedirectHandler):
    """Re-check every redirect: a public host may redirect to a private one."""

    def __init__(self, allow_private: bool) -> None:
        self.allow_private = allow_private

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl, allow_private=self.allow_private)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, *, timeout: float, limit: int, allow_private: bool = False) -> tuple[int, bytes]:
    """GET ``url`` with a public-address guard, a byte cap and a timeout.

    Returns ``(status, body)``. An HTTP error status is returned rather than raised, so a
    caller can report it as that endpoint's failure; anything that makes the request
    impossible (bad scheme, private target, oversize body, unreachable host) raises
    ``MeshError``.
    """
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise MeshError("timeout must be a positive number of seconds")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise MeshError("limit must be a positive integer")

    _check_url(url, allow_private=allow_private)
    opener = urllib.request.build_opener(_GuardedRedirects(allow_private))
    try:
        with opener.open(url, timeout=timeout) as response:
            declared = response.headers.get("Content-Length")
            if declared is not None and declared.isdigit() and int(declared) > limit:
                raise MeshError(f"{url} declares {declared} bytes, over the {limit} limit")
            body = response.read(limit + 1)
            if len(body) > limit:
                raise MeshError(f"{url} returned more than the {limit} byte limit")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except urllib.error.URLError as exc:
        raise MeshError(f"cannot reach {url}: {exc}") from exc
    except OSError as exc:
        raise MeshError(f"cannot reach {url}: {exc}") from exc
