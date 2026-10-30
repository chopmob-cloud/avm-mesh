"""Producer path: evidence stored before the receipt that points at it."""
import copy

import pytest

from avm_mesh.produce import produce, settlement_from_bundle
from avm_mesh.receipt import MeshError, verify_receipt
from avm_mesh.service import Store


def test_produce_stores_evidence_then_issues_a_verifiable_receipt(bundle, anchor, tmp_path):
    store = Store(tmp_path)
    receipt, sealed = produce(bundle, store, trusted_voters=anchor, amount="1000000",
                              issuer="AlgoVoi")

    assert receipt.trust_root == "stake_attested"
    assert receipt.pointer.uri == store.uri_for(receipt.pointer.digest)
    assert store.get_proofpack(receipt.pointer.digest) == bundle
    assert sealed is None  # no signer supplied, so no LEVEL 2 claim is invented

    report = verify_receipt(receipt, store.resolve, trusted_voters=anchor)
    assert report.txid == receipt.txid


def test_produce_serialises_a_sealed_envelope_when_a_signer_is_given(bundle, anchor, tmp_path):
    store = Store(tmp_path)
    receipt, sealed = produce(bundle, store, trusted_voters=anchor, amount="1000000",
                              sign=lambda digest: {"sig_b64": "AAAA", "algorithm": "falcon-1024"})
    assert sealed is not None
    assert "canonical_bytes_b64" in sealed and "signature" in sealed
    assert receipt.trust_root == "stake_attested"


def test_produce_refuses_evidence_that_cannot_reach_the_tier(bundle, tmp_path):
    """No anchor means no stake_attested, so no receipt is issued at all."""
    weak = copy.deepcopy(bundle)
    weak.pop("previous_state_proof_message", None)
    with pytest.raises(MeshError):
        produce(weak, Store(tmp_path), trusted_voters=None, amount="1")


def test_settlement_uses_the_bundles_own_verified_identity(bundle):
    s = settlement_from_bundle(bundle, "1000000", issuer="AlgoVoi")
    assert s["chain_txid"] == bundle["transaction"]["txid"]
    assert s["round"] == bundle["transaction"]["round"]
    assert s["amount"] == "1000000"
    assert s["issuer"] == "AlgoVoi"
