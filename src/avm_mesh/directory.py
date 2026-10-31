"""Mesh directories: how a client finds witnesses instead of being told their URLs.

A directory is a published document, not a service. It lists witnesses and what
each one claims about itself, so a client can corroborate without someone pasting
URLs into a chat window. Two rules keep it honest:

- **A directory is a lead, never a trust root.** Every entry is checked against
  the witness's own card at collection time. A directory that claims an operator
  for a URL does not make it so, and a disagreement is reported rather than
  resolved in the directory's favour.
- **Anything unrecognised is refused.** A directory is fetched over the network,
  so unknown fields, missing URLs, or a wrong document version are errors. Being
  permissive here would let a hostile directory steer a client at endpoints it
  never intended to talk to.

The document is deliberately boring::

    {
      "version": 1,
      "witnesses": [
        {"url": "https://w1.example.org", "operator_id": "op-a", "chain": "mainnet-v1.0"},
        {"url": "https://w2.example.net", "operator_id": "op-b", "chain": "mainnet-v1.0"}
      ]
    }
"""
from __future__ import annotations

import json
import pathlib
import urllib.error
import urllib.request

from . import net
from .receipt import MeshError

DIRECTORY_VERSION = 1
#: A directory arrives over the network, so its size and length are bounded before
#: parsing. Without a cap a hostile URL is a memory-exhaustion primitive.
MAX_DIRECTORY_BYTES = 1024 * 1024
#: And it cannot make a client fan out indefinitely.
MAX_WITNESSES = 1000
#: The path a witness or mesh publishes its directory at.
WELL_KNOWN_PATH = "/.well-known/mesh-directory.json"
_ALLOWED_KEYS = {"url", "operator_id", "witness_id", "chain", "escrow_txid"}


def parse_directory(document: dict) -> list[dict]:
    """Validate a directory document and return its witness entries."""
    if not isinstance(document, dict):
        raise MeshError("directory must be a JSON object")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) \
            or version != DIRECTORY_VERSION:
        raise MeshError(
            f"unsupported directory version {document.get('version')!r}; "
            f"this client understands {DIRECTORY_VERSION}")
    entries = document.get("witnesses")
    if not isinstance(entries, list) or not entries:
        raise MeshError("directory must list at least one witness")
    if len(entries) > MAX_WITNESSES:
        raise MeshError(
            f"directory lists more than {MAX_WITNESSES} witnesses; refusing to fan out")

    seen_urls: set[str] = set()
    cleaned: list[dict] = []
    for index, entry in enumerate(entries):
        where = f"witnesses[{index}]"
        if not isinstance(entry, dict):
            raise MeshError(f"{where} must be an object")
        unknown = set(entry) - _ALLOWED_KEYS
        if unknown:
            raise MeshError(f"{where} has unknown field(s) {sorted(unknown)}")
        url = entry.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise MeshError(f"{where}.url must be an http(s) URL")
        for field in ("operator_id", "witness_id", "chain", "escrow_txid"):
            value = entry.get(field)
            if value is not None and not isinstance(value, str):
                raise MeshError(f"{where}.{field} must be a string")
        if url in seen_urls:
            raise MeshError(f"{where}.url {url} appears twice")
        seen_urls.add(url)
        cleaned.append({k: v for k, v in entry.items() if v is not None})
    return cleaned


def load_directory(source: str, *, timeout: float = 5.0,
                   allow_private: bool = False) -> list[dict]:
    """Load a directory from an http(s) URL or a local path."""
    if not isinstance(source, str) or not source:
        raise MeshError("directory source must be a non-empty string")

    if source.startswith(("http://", "https://")):
        status, body = net.fetch(source, timeout=timeout, limit=MAX_DIRECTORY_BYTES,
                                 allow_private=allow_private)
        if status != 200:
            raise MeshError(f"directory at {source} returned HTTP {status}")
    else:
        path = pathlib.Path(source)
        try:
            if path.stat().st_size > MAX_DIRECTORY_BYTES:
                raise MeshError(f"directory is too large (over {MAX_DIRECTORY_BYTES} bytes)")
            body = path.read_bytes()
        except MeshError:
            raise
        except OSError as exc:
            raise MeshError(f"cannot read directory {source}: {exc}") from exc

    if len(body) > MAX_DIRECTORY_BYTES:
        raise MeshError(f"directory is too large (over {MAX_DIRECTORY_BYTES} bytes)")
    try:
        document = json.loads(body)
    except RecursionError as exc:            # deep nesting is an attack, not a crash
        raise MeshError("directory JSON is nested too deeply") from exc
    except ValueError as exc:
        raise MeshError(f"directory is not valid JSON: {exc}") from exc
    return parse_directory(document)


def urls_from_directories(directory_entries: list[dict]) -> list[str]:
    """The witness URLs a directory lists, in order, deduplicated."""
    urls: list[str] = []
    for entry in directory_entries:
        url = entry["url"]
        if url not in urls:
            urls.append(url)
    return urls
