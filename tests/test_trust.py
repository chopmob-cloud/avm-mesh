"""Trust policy: every pin in one auditable document."""
import json

import pytest

from avm_mesh.receipt import MeshError, create_receipt
from avm_mesh.service import Store
from avm_mesh.trust import TrustPolicy, load_policy, verify_with_policy


def _policy_bytes(bundle, anchor, **over):
    prev = bundle["previous_state_proof_message"]
    d = {
        "chain": "mainnet-v1.0",
        "genesis_hash_b64": "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
        "anchor_voters_commitment_b64": prev["voters_commitment_b64"],
        "anchor_ln_proven_weight": int(prev["ln_proven_weight"]),
        "corroboration_threshold": 0,
        "witnesses": [],
    }
    d.update(over)
    return d


def test_policy_round_trips(bundle, anchor):
    p = TrustPolicy.from_dict(_policy_bytes(bundle, anchor))
    again = TrustPolicy.from_dict(json.loads(json.dumps(p.to_dict())))
    assert again == p


def test_policy_builds_the_anchor_it_describes(bundle, anchor):
    p = TrustPolicy.from_dict(_policy_bytes(bundle, anchor))
    tv = p.trusted_voters()
    assert tv.voters_commitment == anchor.voters_commitment
    assert tv.ln_proven_weight == anchor.ln_proven_weight


def test_verification_uses_every_pin(bundle, anchor, tmp_path):
    store = Store(tmp_path)
    digest = store.put_proofpack(bundle)
    receipt = create_receipt(bundle, store.uri_for(digest), trusted_voters=anchor)
    p = TrustPolicy.from_dict(_policy_bytes(bundle, anchor))
    report = verify_with_policy(receipt, store.resolve, p)
    assert report.trust_root == "stake_attested"


def test_wrong_genesis_in_policy_is_enforced(bundle, anchor, tmp_path):
    store = Store(tmp_path)
    digest = store.put_proofpack(bundle)
    receipt = create_receipt(bundle, store.uri_for(digest), trusted_voters=anchor)
    bad = _policy_bytes(bundle, anchor,
                        genesis_hash_b64="r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=")
    with pytest.raises(MeshError):
        verify_with_policy(receipt, store.resolve, TrustPolicy.from_dict(bad))


def test_wrong_anchor_in_policy_is_enforced(bundle, anchor, tmp_path):
    store = Store(tmp_path)
    digest = store.put_proofpack(bundle)
    receipt = create_receipt(bundle, store.uri_for(digest), trusted_voters=anchor)
    import base64
    bad = _policy_bytes(bundle, anchor,
                        anchor_voters_commitment_b64=base64.b64encode(bytes(64)).decode())
    with pytest.raises(MeshError):
        verify_with_policy(receipt, store.resolve, TrustPolicy.from_dict(bad))


def test_policy_refuses_a_threshold_it_cannot_deliver(bundle, anchor):
    """Fail at load, not on every request months later."""
    bad = _policy_bytes(bundle, anchor, corroboration_threshold=2, witnesses=[
        {"witness_id": "w1", "operator_id": "op-1", "chain": "mainnet-v1.0",
         "bond_microalgo": 1_000_000, "escrow_txid": "E1"},
    ])
    with pytest.raises(MeshError, match="only 1 are bonded"):
        TrustPolicy.from_dict(bad).require_witness_coverage()


def test_malformed_policy_is_refused():
    with pytest.raises(MeshError):
        TrustPolicy.from_dict({"chain": "x"})
    with pytest.raises(MeshError, match="32 bytes"):
        TrustPolicy.from_dict({"chain": "mainnet-v1.0", "genesis_hash_b64": "AAAA",
                               "anchor_voters_commitment_b64": "A" * 86 + "==",
                               "anchor_ln_proven_weight": 1, "witnesses": []})


def test_load_policy_from_file(bundle, anchor, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy_bytes(bundle, anchor)), encoding="utf-8")
    p = load_policy(str(path))
    assert p.chain == "mainnet-v1.0"
