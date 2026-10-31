"""Witness service: what a mesh operator actually runs.

A witness holds evidence and serves it. It does not decide anything and it does
not vouch for settlements -- it publishes sealed receipts and the proofpacks they
point at, content-addressed, so a verifier can check them offline and never has
to trust the server that handed them over.

That distinction is the whole design. The service is a COURIER. If a witness
lies about which proofpack it serves, the digest in the receipt catches it; the
worker cannot substitute evidence even if it wants to, because the receipt was
sealed by the settler and commits to the digest.

Storage is content-addressed on purpose: the filename IS the digest, so writing
twice is idempotent and a swapped blob is detectable by name alone.

Stdlib only (http.server). A witness should be boring enough to run for years
without a dependency upgrade.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import threading
import time
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .receipt import MeshError, SettlementReceipt, bundle_digest

# A stored artefact is addressed by a single name, never a path. Allowing a
# separator, a dot-segment or a NUL would let a request walk out of the store
# and read or write an arbitrary file: the courier must not pick the bytes.
_SAFE_NAME = re.compile(r"\A[A-Za-z0-9_-]{1,128}\Z")


#: A witness refuses to serve a proofpack larger than this. Real ones are ~0.4-0.9 MB;
#: the cap exists so a hostile or broken store cannot make a witness stream gigabytes.
DEFAULT_MAX_PROOF_BYTES = 8 * 1024 * 1024
#: Requests per client address per window, and the window length.
DEFAULT_RATE_LIMIT = 120
DEFAULT_RATE_WINDOW_S = 10.0
#: A client that does not send a full request within this many seconds is dropped.
SOCKET_TIMEOUT_S = 10.0
#: Longest request line accepted. Anything longer is not a resource we serve.
MAX_PATH_CHARS = 2048


class StoreNameError(MeshError):
    """A requested store name is malformed: a client error, not corruption.

    Kept distinct from a plain MeshError so the HTTP layer can answer a bad
    name with 404 (we have no such resource) rather than 500 (a fault on our
    side), while every ``except MeshError`` still catches it.
    """


def _safe_name(value: str, kind: str) -> str:
    if not isinstance(value, str) or not _SAFE_NAME.match(value):
        raise StoreNameError(f"{kind} is not a valid store name")
    return value


def _within_store(base: pathlib.Path, path: pathlib.Path) -> None:
    """A store entry serves its own bytes, never a symlink redirecting outside.

    _safe_name already forbids separators in the name, so the only remaining
    escape is a symlink planted at the entry itself (or a symlinked parent):
    get_receipt('SAFE') following receipts/SAFE.json -> /etc/x.json would hand
    a caller a file the store never wrote. Refuse the link and assert the
    resolved path still sits directly in the store directory.
    """
    if path.is_symlink():
        raise StoreNameError("refusing to serve a symlinked store entry")
    try:
        resolved = path.resolve()
        root = base.resolve()
    except OSError as exc:
        raise MeshError("could not resolve store path") from exc
    if resolved.parent != root:
        raise StoreNameError("store entry escapes the store root")


class Store:
    """Filesystem store: proofpacks by digest, receipts by txid."""

    def __init__(self, root: pathlib.Path | str,
                 max_proofpack_bytes: int = DEFAULT_MAX_PROOF_BYTES) -> None:
        if not isinstance(max_proofpack_bytes, int) or isinstance(max_proofpack_bytes, bool) \
                or max_proofpack_bytes <= 0:
            raise MeshError("max_proofpack_bytes must be a positive integer")
        self.max_proofpack_bytes = max_proofpack_bytes
        self.root = pathlib.Path(root)
        self.proofpacks = self.root / "proofpacks"
        self.receipts = self.root / "receipts"
        # Wrap filesystem failures in the module's own error type. Callers are told
        # never to expect TypeError/OSError from this package, and a path that is a
        # file rather than a directory is a configuration error, not a crash.
        try:
            self.proofpacks.mkdir(parents=True, exist_ok=True)
            self.receipts.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise MeshError(f"store root {self.root} is unusable: {exc.strerror or exc}") from exc

    # -- writes ---------------------------------------------------------
    def put_proofpack(self, bundle: dict) -> str:
        digest = bundle_digest(bundle)
        encoded_len = len(json.dumps(bundle).encode("utf-8"))
        if encoded_len > self.max_proofpack_bytes:
            raise MeshError(
                f"proofpack is {encoded_len} bytes, over the {self.max_proofpack_bytes} "
                "byte limit this witness serves")
        path = self.proofpacks / f"{digest}.json"
        if path.exists():
            # Content-addressed: an existing file with this name is the same bytes.
            return digest
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(bundle), encoding="utf-8")
        tmp.replace(path)
        return digest

    def put_receipt(self, receipt: SettlementReceipt) -> str:
        """Store a receipt, refusing to replace a different one for the same txid.

        Receipts are append-only per txid. Without this a witness can equivocate:
        serve one receipt to a client that verifies it, then quietly replace it
        with another (a different tier, pointer or corroboration) for the next
        client. Both receipts may be individually valid; the *service* would be
        the attack. Identical re-writes are idempotent, so a retry is harmless.
        """
        if not isinstance(receipt, SettlementReceipt):
            raise MeshError("put_receipt expects a SettlementReceipt")
        _safe_name(receipt.txid, "txid")
        payload = json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        path = self.receipts / f"{receipt.txid}.json"
        if path.is_file():
            existing = hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
            if existing != digest:
                raise MeshError(
                    f"receipt for {receipt.txid} already exists with different content; "
                    "refusing to replace it"
                )
            return receipt.txid
        tmp = path.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(path)
        (self.receipts / f"{receipt.txid}.sha256").write_text(digest, encoding="utf-8")
        return receipt.txid

    # -- reads ----------------------------------------------------------
    def get_proofpack(self, digest: str) -> dict:
        _safe_name(digest, "digest")
        path = self.proofpacks / f"{digest}.json"
        _within_store(self.proofpacks, path)
        if not path.is_file():
            raise FileNotFoundError(digest)
        bundle = json.loads(path.read_text(encoding="utf-8"))
        # Verify the name still matches the content: a truncated write or a
        # tampered file must fail here rather than propagate to a verifier.
        if bundle_digest(bundle) != digest:
            raise MeshError(f"stored proofpack {digest[:16]}... no longer matches its name")
        return bundle

    def get_receipt(self, txid: str) -> dict:
        _safe_name(txid, "txid")
        path = self.receipts / f"{txid}.json"
        _within_store(self.receipts, path)
        if not path.is_file():
            raise FileNotFoundError(txid)
        raw = path.read_text(encoding="utf-8")
        sidecar = self.receipts / f"{txid}.sha256"
        if sidecar.is_file():
            expected = sidecar.read_text(encoding="utf-8").strip()
            actual = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if actual != expected:
                raise MeshError(
                    f"stored receipt {txid} no longer matches its recorded digest"
                )
        return json.loads(raw)

    @staticmethod
    def uri_for(digest: str) -> str:
        """The canonical URI a receipt should carry for this store."""
        if not isinstance(digest, str) or len(digest) != 64:
            raise MeshError("digest must be a 64-char sha256 hex string")
        return f"proofpack:{digest}"

    def resolve(self, uri: str) -> dict:
        """Resolver for verify_receipt. Accepts proofpack:<digest> and plain paths.

        Refuses a URI that does not name a digest: resolving by anything else
        would let the store pick the evidence, which is the courier deciding.
        """
        if uri.startswith("proofpack:"):
            digest = uri.split(":", 1)[1]
        else:
            digest = uri.rsplit("/", 1)[-1]
            if digest.endswith(".json"):
                digest = digest[:-5]
        if len(digest) != 64:
            raise MeshError(f"{uri!r} does not name a proofpack digest")
        return self.get_proofpack(digest)


class WitnessInfo:
    """The public description a witness publishes about itself."""

    def __init__(self, witness_id: str, operator_id: str, chain: str,
                 escrow_txid: str, anchor_voters_commitment_b64: str,
                 anchor_ln_proven_weight: int) -> None:
        for name, value in (("witness_id", witness_id), ("operator_id", operator_id),
                            ("chain", chain), ("escrow_txid", escrow_txid)):
            if not isinstance(value, str) or not value:
                raise MeshError(f"{name} must be a non-empty string")
        self.witness_id = witness_id
        self.operator_id = operator_id
        self.chain = chain
        self.escrow_txid = escrow_txid
        self.anchor_voters_commitment_b64 = anchor_voters_commitment_b64
        self.anchor_ln_proven_weight = anchor_ln_proven_weight

    def to_dict(self) -> dict:
        return {
            "witness_id": self.witness_id,
            "operator_id": self.operator_id,
            "chain": self.chain,
            "escrow_txid": self.escrow_txid,
            "anchor_voters_commitment_b64": self.anchor_voters_commitment_b64,
            "anchor_ln_proven_weight": self.anchor_ln_proven_weight,
            "serves": ["receipt", "proofpack"],
            "note": "a witness is a courier, not a trust source; verify evidence, never the courier",
        }


def _make_handler(store: Store, info: WitnessInfo | None,
                  rate_limit: int = DEFAULT_RATE_LIMIT,
                  rate_window_s: float = DEFAULT_RATE_WINDOW_S):
    if not isinstance(rate_limit, int) or isinstance(rate_limit, bool) or rate_limit <= 0:
        raise MeshError("rate_limit must be a positive integer")
    if not isinstance(rate_window_s, (int, float)) or isinstance(rate_window_s, bool) \
            or rate_window_s <= 0:
        raise MeshError("rate_window_s must be a positive number of seconds")
    # Shared across handler instances: one counter per client address.
    seen: dict[str, tuple[float, int]] = {}
    seen_lock = threading.Lock()

    def rate_limited(address: str) -> bool:
        now = time.monotonic()
        with seen_lock:
            if len(seen) > 10_000:
                # Drop windows that have already expired. Without this the table is a
                # memory sink for anyone able to source requests from many addresses.
                for key in [k for k, (start, _) in seen.items()
                            if now - start >= rate_window_s]:
                    del seen[key]
            window_start, count = seen.get(address, (now, 0))
            if now - window_start >= rate_window_s:
                seen[address] = (now, 1)
                return False
            if count >= rate_limit:
                return True
            seen[address] = (window_start, count + 1)
            return False

    class Handler(BaseHTTPRequestHandler):
        server_version = "avm-mesh-witness/0.2"
        # Drop a connection that goes quiet mid-request rather than holding a thread.
        timeout = SOCKET_TIMEOUT_S

        def _json(self, code: int, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if len(self.path) > MAX_PATH_CHARS:
                return self._json(414, {"error": "request path too long"})
            client = self.client_address[0] if self.client_address else "unknown"
            if rate_limited(client):
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", str(int(rate_window_s)))
                body = json.dumps({"error": "rate limit exceeded"}).encode()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            path = self.path.split("?", 1)[0].rstrip("/")
            try:
                if path in ("/healthz", ""):
                    return self._json(200, {"ok": True})
                if path == "/witness":
                    if info is None:
                        return self._json(404, {"error": "no witness identity configured"})
                    return self._json(200, info.to_dict())
                if path.startswith("/receipts/"):
                    txid = path[len("/receipts/"):]
                    return self._json(200, store.get_receipt(txid))
                if path.startswith("/proofpacks/"):
                    digest = path[len("/proofpacks/"):]
                    if digest.endswith(".json"):
                        digest = digest[:-5]
                    _safe_name(digest, "digest")
                    stored = store.proofpacks / f"{digest}.json"
                    if stored.exists() and stored.stat().st_size > store.max_proofpack_bytes:
                        return self._json(413, {"error": "proofpack too large to serve"})
                    return self._json(200, store.get_proofpack(digest))
            except FileNotFoundError:
                return self._json(404, {"error": "not found"})
            except StoreNameError:
                # A malformed name is a client error: we have no such resource.
                # Answer 404 rather than leaking that it was rejected (and never
                # 500, which would imply a fault on our side).
                return self._json(404, {"error": "not found"})
            except MeshError as exc:
                # A stored artefact that no longer matches its name is a fault on
                # OUR side; 500 is honest, 404 would hide corruption.
                return self._json(500, {"error": str(exc)})
            return self._json(404, {"error": "not found"})

        def log_message(self, fmt: str, *args: Any) -> None:  # keep the console clean
            return

    return Handler


def make_server(store: Store, host: str = "127.0.0.1", port: int = 0,
                info: WitnessInfo | None = None, *,
                rate_limit: int = DEFAULT_RATE_LIMIT,
                rate_window_s: float = DEFAULT_RATE_WINDOW_S) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port), _make_handler(store, info, rate_limit, rate_window_s))
    server.daemon_threads = True
    return server


def serve_forever(store: Store, host: str = "127.0.0.1", port: int = 8080,
                  info: WitnessInfo | None = None, **limits: Any) -> None:
    server = make_server(store, host, port, info, **limits)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def run_in_thread(store: Store, info: WitnessInfo | None = None) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start on an ephemeral port. Used by tests and by embedders."""
    server = make_server(store, info=info)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
