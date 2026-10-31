"""End to end: capture output -> stored evidence -> receipt -> policy verification.

This is the path a deployment actually runs, and the only test that exercises all
of it together: produce, store, policy, verify. Sockets are blocked for the
verification half, because "offline" is the product claim and a test that quietly
falls back to the network would never notice if it stopped being true.

The fixture is a real Algorand mainnet bundle. Regenerate with:

    python -m avm_proofpack.cli capture --node https://mainnet-api.algonode.cloud \
        --txid <txid> --round <round multiple of 256> --chain algorand-mainnet -o bundle.json

and commit it gzipped as tests/fixtures/stake_attested_algorand_66457600.json.gz.
"""
import base64
import copy
import gzip
import json
import os
import pathlib
import socket

import pytest

import _assets

from avm_mesh.produce import produce
from avm_mesh.receipt import MeshError, SettlementReceipt
from avm_mesh.sealed import verify_sealed
from avm_mesh.service import Store, run_in_thread
from avm_mesh.trust import TrustPolicy, verify_with_policy

DEFAULT_FIXTURE = _assets.fixture_bundle()
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="


@pytest.fixture(scope="module")
def real_bundle():
    path = pathlib.Path(os.environ.get("AVM_MESH_FIXTURE", DEFAULT_FIXTURE))
    _assets.require(path, "fixture")
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def _policy_dict(bundle):
    prev = bundle["previous_state_proof_message"]
    return {
        "chain": "mainnet-v1.0",
        "genesis_hash_b64": GENESIS,
        "anchor_voters_commitment_b64": prev["voters_commitment_b64"],
        "anchor_ln_proven_weight": int(prev["ln_proven_weight"]),
        "witnesses": [],
        "corroboration_threshold": 0,
    }


def _block_network(monkeypatch):
    class Blocked(socket.socket):
        def __init__(self, *a, **k):
            raise OSError("NETWORK DISABLED")

    monkeypatch.setattr(socket, "socket", Blocked)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("NETWORK DISABLED")))


def test_full_path_verifies_offline(real_bundle, tmp_path, monkeypatch):
    """produce -> store -> policy -> verify, with the network removed."""
    policy = TrustPolicy.from_dict(_policy_dict(real_bundle))
    store = Store(tmp_path)

    # The fixture is a 1-microalgo payment; the amount is now bound to the
    # authenticated transaction, so the receipt must state what actually moved.
    receipt, sealed = produce(real_bundle, store, trusted_voters=policy.trusted_voters(),
                              amount="1", asset="microalgo", issuer="AlgoVoi")
    assert receipt.trust_root == "stake_attested"
    assert sealed is None  # no signer, so no LEVEL 2 claim is invented

    _block_network(monkeypatch)
    report = verify_with_policy(receipt, store.resolve, policy)
    assert report.trust_root == "stake_attested"
    assert report.txid == receipt.txid
    assert "state-proof-stake-attested" in report.checks


def test_full_path_with_sealed_envelope(real_bundle, tmp_path, monkeypatch):
    """The same path through the wire format the rails already speak."""
    policy = TrustPolicy.from_dict(_policy_dict(real_bundle))
    store = Store(tmp_path)
    _, sealed = produce(real_bundle, store, trusted_voters=policy.trusted_voters(),
                        amount="1", sign=lambda d: {"sig_b64": "AAAA",
                                                    "algorithm": "falcon-1024"})
    assert sealed is not None

    _block_network(monkeypatch)
    out = verify_sealed(sealed, store.resolve,
                        trusted_voters=policy.trusted_voters(),
                        expected_genesis_hash_b64=GENESIS,
                        verify_signature=lambda cb, sig: True)
    assert out["trust_root"] == "stake_attested"


def test_served_receipt_verifies_identically(real_bundle, tmp_path):
    """What the witness hands over must verify the same as what we stored."""
    import urllib.request

    policy = TrustPolicy.from_dict(_policy_dict(real_bundle))
    store = Store(tmp_path)
    receipt, _ = produce(real_bundle, store, trusted_voters=policy.trusted_voters(),
                         amount="1")

    server, _thread = run_in_thread(store)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(f"{base}/receipts/{receipt.txid}", timeout=5) as r:
            served = json.loads(r.read().decode())
        report = verify_with_policy(SettlementReceipt.from_dict(served), store.resolve, policy)
        assert report.trust_root == "stake_attested"
        assert report.txid == receipt.txid
    finally:
        server.shutdown()
        server.server_close()


def test_a_different_settlement_cannot_reuse_the_evidence(real_bundle, tmp_path):
    """Same proofpack, different txid on the receipt: refused."""
    policy = TrustPolicy.from_dict(_policy_dict(real_bundle))
    store = Store(tmp_path)
    receipt, _ = produce(real_bundle, store, trusted_voters=policy.trusted_voters(),
                         amount="1")
    forged = SettlementReceipt.from_dict({**receipt.to_dict(), "txid": "A" * 52})
    with pytest.raises(MeshError, match="different settlement"):
        verify_with_policy(forged, store.resolve, policy)


def test_evidence_that_does_not_match_the_policy_chain_is_refused(real_bundle, tmp_path):
    """The policy is the root: evidence for another chain must not verify under it."""
    policy_dict = _policy_dict(real_bundle)
    store = Store(tmp_path)
    receipt, _ = produce(real_bundle, store, trusted_voters=TrustPolicy.from_dict(
        policy_dict).trusted_voters(), amount="1")

    voi_policy = TrustPolicy.from_dict({**policy_dict, "chain": "voimain-v1.0"})
    with pytest.raises(MeshError, match="policy is for"):
        verify_with_policy(receipt, store.resolve, voi_policy)
