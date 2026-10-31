"""A hostile or broken witness must become a failed view, never a crashed collection.

Codex's review found three ways one endpoint could distort or abort the whole run:
an unhashable operator id, an empty one satisfying a threshold, and unbounded or
deeply nested responses. Each case is a witness here rather than a unit call,
because the defect was in how the collector handled a real endpoint.
"""
import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from avm_mesh.corroborate import collect
from avm_mesh.receipt import ProofpackPointer, SettlementReceipt, bundle_digest

BUNDLE = {"transaction": {"txid": "HOSTILE", "round": 66457600}, "state_proof_message": {}}
DIGEST = bundle_digest(BUNDLE)
TXID = "HOSTILE"


def _receipt(chain="mainnet-v1.0", tier="structural") -> dict:
    return SettlementReceipt(
        version=1, chain=chain, txid=TXID, round=66457600, trust_root=tier,
        pointer=ProofpackPointer(uri="proofpack:" + DIGEST, digest=DIGEST,
                                 first_attested_round=66457344,
                                 last_attested_round=66457600)).to_dict()


class FakeWitness:
    """A loopback witness whose answers are whatever the test needs them to be."""

    def __init__(self, *, operator="op-a", chain="mainnet-v1.0", receipt=None,
                 card_override=None, raw_card=None, receipt_chain=None):
        self.card = card_override if card_override is not None else {
            "witness_id": "w", "operator_id": operator, "chain": chain}
        self.raw_card = raw_card
        receipt = receipt or _receipt(chain=receipt_chain or chain)
        body = json.dumps(receipt).encode()
        bundle = json.dumps(BUNDLE).encode()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.rstrip("/").endswith("/witness"):
                    payload = outer.raw_card if outer.raw_card is not None \
                        else json.dumps(outer.card).encode()
                elif "/receipts/" in self.path:
                    payload = body
                elif "/proofpacks/" in self.path:
                    payload = bundle
                else:
                    payload = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()


@pytest.fixture
def honest():
    w = FakeWitness(operator="op-honest")
    yield w
    w.close()


def _collect(urls, min_operators=2, allow_private=True):
    return collect(TXID, urls, min_operators=min_operators, timeout=5, allow_private=True)


def test_an_unhashable_operator_id_does_not_crash_the_collection(honest):
    """A list operator_id previously raised TypeError from a set() outside the guard."""
    bad = FakeWitness(card_override={"witness_id": "w", "operator_id": [], "chain": "mainnet-v1.0"})
    try:
        result = _collect([honest.url, bad.url], allow_private=True)
        assert result.agreed is False
        offender = [v for v in result.views if v.url == bad.url][0]
        assert offender.problem and "non-empty string" in offender.problem
        assert not offender.counts
    finally:
        bad.close()


def test_an_empty_operator_id_cannot_satisfy_the_threshold(honest):
    bad = FakeWitness(card_override={"witness_id": "w", "operator_id": "", "chain": "mainnet-v1.0"})
    try:
        result = _collect([honest.url, bad.url], allow_private=True)
        assert result.agreed is False
        assert result.operators == ("op-honest",)
    finally:
        bad.close()


def test_an_oversized_receipt_is_refused_not_read_fully(honest):
    """The receipt cap matters independently of the card cap."""
    blob = json.dumps({"canonical_bytes_b64": base64.b64encode(b"x" * 10).decode(),
                       "content_hash": "a" * 64, "pad": "x" * (200_000)}).encode()
    bad = FakeWitness.__new__ if False else None
    bad = FakeWitness.__wrapped__ if False else None

    class OversizedReceiptWitness:
        def __init__(self):
            self.card = {"witness_id": "w", "operator_id": "op-x", "chain": "mainnet-v1.0"}
            self.receipt_blob = blob

            class H(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path.rstrip("/").endswith("/witness"):
                        payload = json.dumps(self.outer.card).encode()
                    elif "/receipts/" in self.path:
                        payload = self.outer.receipt_blob
                    else:
                        payload = b"{}"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, *a):
                    return

            H.outer = self
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

        def close(self):
            self.server.shutdown()

    bad = OversizedReceiptWitness()
    try:
        result = _collect([honest.url, bad.url])
        offender = [v for v in result.views if v.url == bad.url][0]
        assert offender.problem and "limit" in offender.problem
        assert not offender.counts
    finally:
        bad.close()


def test_an_oversized_proofpack_is_refused_at_the_cap(honest):
    """The proofpack cap must also bite independently of the card/receipt caps."""
    big = "x" * 200_000
    body = json.dumps({"blob": big}).encode()
    # Slighty over the 8 MiB cap. The cap bites during the read, before any
    # hashing or JSON parsing happens, so the form of the body is irrelevant.
    parts = b"x" * (8 * 1024 * 1024 + 1024)

    class BadProofpackWitness:
        def __init__(self):
            self.card = {"witness_id": "w", "operator_id": "op-x", "chain": "mainnet-v1.0"}

            class H(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path.rstrip("/").endswith("/witness"):
                        payload = json.dumps(self.outer.card).encode()
                    elif "/receipts/" in self.path:
                        payload = json.dumps(_receipt(chain="mainnet-v1.0")).encode()
                    elif "/proofpacks/" in self.path:
                        payload = parts
                    else:
                        payload = b"{}"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, *a):
                    return

            H.outer = self
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

        def close(self):
            self.server.shutdown()

    bad = BadProofpackWitness()
    try:
        result = _collect([honest.url, bad.url])
        offender = [v for v in result.views if v.url == bad.url][0]
        assert offender.problem and "limit" in offender.problem
        assert not offender.counts
    finally:
        bad.close()


def test_a_deeply_nested_card_is_reported_not_raised(honest):
    bad = FakeWitness(raw_card=b"[" * 100_000 + b"]" * 100_000)
    try:
        result = _collect([honest.url, bad.url], allow_private=True)
        offender = [v for v in result.views if v.url == bad.url][0]
        assert offender.problem
        assert not offender.counts
        assert result.agreed is False
    finally:
        bad.close()


def test_an_oversized_card_is_refused(honest):
    blob = json.dumps({"witness_id": "w", "operator_id": "op-x",
                       "chain": "mainnet-v1.0", "pad": "x" * (200_000)}).encode()
    bad = FakeWitness(raw_card=blob)
    try:
        result = _collect([honest.url, bad.url], allow_private=True)
        offender = [v for v in result.views if v.url == bad.url][0]
        assert offender.problem and "limit" in offender.problem
        assert not offender.counts
    finally:
        bad.close()


def test_witnesses_on_different_chains_do_not_agree(honest):
    """Same digest, same round, same tier -- but not the same chain."""
    other = FakeWitness(operator="op-b", chain="voimain-v1.0")
    try:
        result = _collect([honest.url, other.url], allow_private=True)
        assert result.agreed is False
        assert any("chain" in p for p in result.problems)
    finally:
        other.close()


def test_a_card_that_contradicts_its_own_receipt_is_not_counted(honest):
    contradictory = FakeWitness(operator="op-b", chain="mainnet-v1.0",
                               receipt_chain="voimain-v1.0")
    try:
        result = _collect([honest.url, contradictory.url], allow_private=True)
        offender = [v for v in result.views if v.url == contradictory.url][0]
        assert offender.problem and "card claims chain" in offender.problem
        assert not offender.counts
        assert result.agreed is False
    finally:
        contradictory.close()
