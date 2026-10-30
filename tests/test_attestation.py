"""LEVEL 3 consensus attestation.

The property under test is not "does it verify" but "can an operator, a
bundle author, or a middleman manufacture a passing attestation".
"""
import copy
import json

import pytest

from avm_mesh import ConsensusAttestation, MeshError, attest, verify_attestation
from avm_mesh.receipt import bundle_digest

ALGORAND_GENESIS_B64 = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
VOI_GENESIS_B64 = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="
GOOD_VC = "A" * 86 + "=="


def _resolver(b):
    return lambda uri: copy.deepcopy(b)


def test_attestation_is_built_against_the_supplied_anchor(bundle, anchor):
    att = attest(bundle, "ipfs://Qm/proofpack.json", trusted_voters=anchor)
    assert att.trust_root == "stake_attested"
    assert att.chain == "mainnet-v1.0"
    assert att.genesis_hash_b64 == ALGORAND_GENESIS_B64
    assert att.evidence_digest == bundle_digest(bundle)
    assert att.anchor_ln_proven_weight == anchor.ln_proven_weight


def test_attestation_verifies_with_pinned_genesis(bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    report = verify_attestation(att, _resolver(bundle), trusted_voters=anchor,
                                expected_genesis_hash_b64=ALGORAND_GENESIS_B64)
    assert report.trust_root == "stake_attested"


def test_attest_requires_an_anchor(bundle):
    """Without an anchor there is no trust root to build a claim on."""
    with pytest.raises(MeshError, match="trusted voters anchor is required"):
        attest(bundle, "file://proofpack.json", trusted_voters=None)


def test_verify_requires_an_anchor(bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    with pytest.raises(MeshError, match="trusted voters anchor is required"):
        verify_attestation(att, _resolver(bundle), trusted_voters=None)


def test_a_different_recorded_anchor_is_refused(bundle, anchor, wrong_anchor):
    """A verifier holding a different anchor must not accept the claim."""
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    with pytest.raises(MeshError, match="anchor mismatch"):
        verify_attestation(att, _resolver(bundle), trusted_voters=wrong_anchor)


def test_a_different_genesis_pin_is_refused(bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    with pytest.raises(MeshError, match="genesis hash mismatch"):
        verify_attestation(att, _resolver(bundle), trusted_voters=anchor,
                           expected_genesis_hash_b64=VOI_GENESIS_B64)


def test_substituted_evidence_is_refused(bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    other = copy.deepcopy(bundle)
    other["state_proof_message"]["ln_proven_weight"] += 1
    with pytest.raises(MeshError, match="evidence digest mismatch"):
        verify_attestation(att, _resolver(other), trusted_voters=anchor)


def test_attestation_for_another_settlement_is_refused(bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    with pytest.raises(MeshError, match="different settlement"):
        verify_attestation(forged, _resolver(bundle), trusted_voters=anchor)


def test_a_forged_attested_interval_is_refused(bundle, anchor):
    """The sealing operator is not trusted: it cannot claim an interval the
    evidence does not attest, just as the receipt path already enforces."""
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({
        **att.to_dict(),
        "last_attested_round": att.last_attested_round + 1,
    })
    with pytest.raises(MeshError, match="attested interval mismatch"):
        verify_attestation(forged, _resolver(bundle), trusted_voters=anchor)


def test_v1_attestations_are_refused_by_name():
    """v1 semantics were forgeable; they must not be accepted as equivalent."""
    with pytest.raises(MeshError, match="forgeable"):
        ConsensusAttestation(
            scheme="avm-stateproof-falcon1024", chain="mainnet-v1.0",
            genesis_hash_b64=ALGORAND_GENESIS_B64, txid="A" * 52, round=1,
            trust_root="stake_attested", evidence_uri="x", evidence_digest="a" * 64,
            first_attested_round=0, last_attested_round=1,
            anchor_voters_commitment_b64=GOOD_VC, anchor_ln_proven_weight=1,
        )


def test_chains_without_state_proofs_are_rejected():
    with pytest.raises(MeshError, match="no state-proof consensus"):
        ConsensusAttestation(
            scheme="avm-stateproof-falcon1024-v2", chain="hedera-mainnet",
            genesis_hash_b64=ALGORAND_GENESIS_B64, txid="A" * 52, round=1,
            trust_root="stake_attested", evidence_uri="x", evidence_digest="a" * 64,
            first_attested_round=0, last_attested_round=1,
            anchor_voters_commitment_b64=GOOD_VC, anchor_ln_proven_weight=1,
        )


def test_short_genesis_or_commitment_is_rejected():
    for field, value, msg in (
        ("genesis_hash_b64", "AAAA", "genesis hash must be 32 bytes"),
        ("anchor_voters_commitment_b64", "AAAA", "voters commitment must be 64 bytes"),
    ):
        kwargs = dict(
            scheme="avm-stateproof-falcon1024-v2", chain="mainnet-v1.0",
            genesis_hash_b64=ALGORAND_GENESIS_B64, txid="A" * 52, round=1,
            trust_root="stake_attested", evidence_uri="x", evidence_digest="a" * 64,
            first_attested_round=0, last_attested_round=1,
            anchor_voters_commitment_b64=GOOD_VC, anchor_ln_proven_weight=1,
        )
        kwargs[field] = value
        with pytest.raises(MeshError, match=msg):
            ConsensusAttestation(**kwargs)
