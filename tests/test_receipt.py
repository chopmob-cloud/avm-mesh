"""Settlement receipt tests.

The fixture is a real Algorand mainnet bundle borrowed from the avm-proofpack
checkout (round 66457600). It is not vendored here because it is 635 KB
gzipped; set AVM_MESH_FIXTURE to override, or skip when absent.
"""
import copy
import gzip
import json
import os
import pathlib

import pytest

from avm_mesh import (
    MeshError,
    ProofpackPointer,
    SettlementReceipt,
    create_receipt,
    verify_receipt,
)
from avm_mesh.receipt import bundle_digest

DEFAULT_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "avm-proofpack" / "tests" / "fixtures"
    / "stake_attested_algorand_66457600.json.gz"
)


def _resolver(bundle):
    return lambda uri: copy.deepcopy(bundle)


def test_receipt_records_the_tier_the_bundle_earns(bundle, anchor):
    receipt = create_receipt(bundle, "ipfs://QmExample/proofpack.json", trusted_voters=anchor)
    assert receipt.trust_root == "stake_attested"
    assert receipt.txid == bundle["transaction"]["txid"]
    assert receipt.pointer.digest == bundle_digest(bundle)


def test_receipt_round_trips_through_json(bundle, anchor):
    receipt = create_receipt(bundle, "ipfs://QmExample/proofpack.json", trusted_voters=anchor)
    revived = SettlementReceipt.from_dict(json.loads(json.dumps(receipt.to_dict())))
    assert revived == receipt


def test_valid_receipt_verifies(bundle, anchor):
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    report = verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, expected_chain="mainnet-v1.0")
    assert report.trust_root == "stake_attested"


def test_substituted_bundle_is_rejected(bundle, anchor):
    """A different bundle behind the same pointer must not verify."""
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    other = copy.deepcopy(bundle)
    other["state_proof_message"] = dict(other["state_proof_message"])
    other["state_proof_message"]["ln_proven_weight"] += 1
    with pytest.raises(MeshError, match="digest mismatch"):
        verify_receipt(receipt, _resolver(other), trusted_voters=anchor)


def test_receipt_cannot_upgrade_a_weaker_bundle(bundle, anchor, wrong_anchor):
    """Claiming stake_attested for a bundle that earns less must fail.

    Strip the previous interval: the bundle can still verify its own
    structure but can no longer authenticate the signing weight.
    """
    weakened = copy.deepcopy(bundle)
    weakened.pop("previous_state_proof_message", None)
    receipt = create_receipt(weakened, "file://proofpack.json", trusted_voters=None)
    assert receipt.trust_root == "unattested"

    # forge the tier on the receipt
    forged = SettlementReceipt.from_dict({**receipt.to_dict(), "trust_root": "stake_attested"})
    with pytest.raises(MeshError, match="trust tier mismatch"):
        verify_receipt(forged, _resolver(weakened), trusted_voters=None)


def test_receipt_for_another_settlement_is_rejected(bundle, anchor):
    """A receipt naming a different txid must not accept this bundle.

    Note: the bundle's own txid is COMPUTED from its transaction bytes, not read
    from the declared "txid" field -- tampering the declared field changes
    nothing, which is why this test tampers the receipt instead of the bundle.
    """
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = SettlementReceipt.from_dict({**receipt.to_dict(), "txid": "A" * 52})
    with pytest.raises(MeshError, match="different settlement"):
        verify_receipt(forged, _resolver(bundle), trusted_voters=anchor)


def test_wrong_chain_is_rejected(bundle, anchor):
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    with pytest.raises(MeshError, match="verifier expected"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, expected_chain="voi-mainnet")


def test_unresolvable_pointer_fails_closed(bundle, anchor):
    receipt = create_receipt(bundle, "file://missing.json")

    def boom(uri):
        raise FileNotFoundError(uri)

    with pytest.raises(MeshError, match="could not resolve"):
        verify_receipt(receipt, boom, trusted_voters=anchor)


def test_malformed_receipts_are_rejected():
    with pytest.raises(MeshError):
        ProofpackPointer.from_dict({"uri": "x", "digest": "nothex", "first_attested_round": 1,
                                    "last_attested_round": 2})
    with pytest.raises(MeshError):
        ProofpackPointer.from_dict({"uri": "x", "digest": "a" * 64, "first_attested_round": 9,
                                    "last_attested_round": 2})
    with pytest.raises(MeshError):
        SettlementReceipt.from_dict({"version": 1, "chain": "c", "txid": "t", "round": 1,
                                     "trust_root": "trust_me", "pointer": {}})


ALGORAND_GENESIS_B64 = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
VOI_GENESIS_B64 = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="


def test_genesis_pin_is_enforced_against_the_authenticated_header(bundle, anchor):
    """A chain id string can be reused by a fork; only the genesis hash cannot."""
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    report = verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor,
                            expected_genesis_hash_b64=ALGORAND_GENESIS_B64)
    assert report.genesis_hash_b64 == ALGORAND_GENESIS_B64


def test_wrong_genesis_pin_is_refused(bundle, anchor):
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    with pytest.raises(MeshError):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor,
                       expected_genesis_hash_b64=VOI_GENESIS_B64)


def test_malformed_genesis_pin_is_refused(bundle, anchor):
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    with pytest.raises(MeshError, match="not valid base64"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor,
                       expected_genesis_hash_b64="!!!not base64!!!")


def test_short_genesis_pin_is_refused(bundle, anchor):
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    with pytest.raises(MeshError, match="must be 32 bytes"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor,
                       expected_genesis_hash_b64="AAAA")


def test_attested_interval_claim_must_match_the_evidence(bundle, anchor):
    """A real proofpack attesting a different interval must not pass.

    Round is left honest so the identity check passes and only the interval
    guard can catch this.
    """
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    pointer = dict(receipt.pointer.to_dict())
    pointer["first_attested_round"] -= 256
    pointer["last_attested_round"] -= 256
    forged = SettlementReceipt.from_dict({**receipt.to_dict(), "pointer": pointer})
    with pytest.raises(MeshError, match="attested interval mismatch"):
        verify_receipt(forged, _resolver(bundle), trusted_voters=anchor)
