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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .receipt import MeshError, SettlementReceipt, bundle_digest


class Store:
    """Filesystem store: proofpacks by digest, receipts by txid."""

    def __init__(self, root: pathlib.Path | str) -> None:
        self.root = pathlib.Path(root)
        self.proofpacks = self.root / "proofpacks"
        self.receipts = self.root / "receipts"
        self.proofpacks.mkdir(parents=True, exist_ok=True)
        self.receipts.mkdir(parents=True, exist_ok=True)

    # -- writes ---------------------------------------------------------
    def put_proofpack(self, bundle: dict) -> str:
        digest = bundle_digest(bundle)
        path = self.proofpacks / f"{digest}.json"
        if path.exists():
            # Content-addressed: an existing file with this name is the same bytes.
            return digest
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(bundle), encoding="utf-8")
        tmp.replace(path)
        return digest

    def put_receipt(self, receipt: SettlementReceipt) -> str:
        if not isinstance(receipt, SettlementReceipt):
            raise MeshError("put_receipt expects a SettlementReceipt")
        path = self.receipts / f"{receipt.txid}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(receipt.to_dict()), encoding="utf-8")
        tmp.replace(path)
        return receipt.txid

    # -- reads ----------------------------------------------------------
    def get_proofpack(self, digest: str) -> dict:
        path = self.proofpacks / f"{digest}.json"
        if not path.is_file():
            raise FileNotFoundError(digest)
        bundle = json.loads(path.read_text(encoding="utf-8"))
        # Verify the name still matches the content: a truncated write or a
        # tampered file must fail here rather than propagate to a verifier.
        if bundle_digest(bundle) != digest:
            raise MeshError(f"stored proofpack {digest[:16]}... no longer matches its name")
        return bundle

    def get_receipt(self, txid: str) -> dict:
        path = self.receipts / f"{txid}.json"
        if not path.is_file():
            raise FileNotFoundError(txid)
        return json.loads(path.read_text(encoding="utf-8"))

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
                raise MeshError(f"{name} is required")
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


def _make_handler(store: Store, info: WitnessInfo | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "avm-mesh-witness/0.1"

        def _json(self, code: int, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
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
                    return self._json(200, store.get_proofpack(digest))
            except FileNotFoundError:
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
                info: WitnessInfo | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _make_handler(store, info))
    server.daemon_threads = True
    return server


def serve_forever(store: Store, host: str = "127.0.0.1", port: int = 8080,
                  info: WitnessInfo | None = None) -> None:
    server = make_server(store, host, port, info)
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
