"""The committed testnet PoC example must keep verifying, and the PoC flow it
backs must keep working. `examples/testnet-proofpack-68812906.json` is a real
Algorand testnet bundle captured from a live node; if a change breaks it, the
demo in docs/POC-RUNBOOK.md breaks with it.

The anchor comes from the bundle's own previous state-proof message, the same
non-independent anchor the mainnet example uses: it exercises the tier mechanics
against real data, not an independent attestation.
"""
import base64
import json
import pathlib

import pytest

from avm_mesh import MeshError, attest, verify_attestation
from avm_mesh.attestation import ConsensusAttestation
from avm_mesh.bond import Witness, WitnessSet
from avm_mesh.poc import REMOVED, UPHELD, EnforcementLedger, verify_ledger

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
BUNDLE = EXAMPLES / "testnet-proofpack-68812906.json"
TESTNET_GENESIS = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="
CHAIN = "testnet-v1.0"


def _bundle():
    return json.loads(BUNDLE.read_text(encoding="utf-8"))


def _anchor(bundle):
    from avm_proofpack.verify import TrustedVoters
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]),
    )


def test_the_testnet_example_is_committed():
    assert BUNDLE.exists(), "the testnet PoC example bundle is missing"
    assert BUNDLE.stat().st_size > 0


def test_testnet_example_reaches_stake_attested():
    bundle = _bundle()
    anchor = _anchor(bundle)
    att = attest(bundle, "proofpack:testnet-example", trusted_voters=anchor)
    assert att.chain == CHAIN
    report = verify_attestation(att, lambda uri: bundle, trusted_voters=anchor,
                                expected_genesis_hash_b64=TESTNET_GENESIS)
    assert report.trust_root == "stake_attested"


def test_testnet_example_without_an_anchor_fails_closed():
    bundle = _bundle()
    att = attest(bundle, "proofpack:testnet-example", trusted_voters=_anchor(bundle))
    with pytest.raises(MeshError, match="anchor"):
        verify_attestation(att, lambda uri: bundle, trusted_voters=None)


def test_testnet_poc_flow_removes_a_false_witness(tmp_path):
    bundle = _bundle()
    anchor = _anchor(bundle)
    att = attest(bundle, "proofpack:testnet-example", trusted_voters=anchor)
    ws = WitnessSet((
        Witness("w1", "op-a", CHAIN, 1_000_000, "ESCROW-w1"),
        Witness("w2", "op-b", CHAIN, 1_000_000, "ESCROW-w2"),
    ))
    ledger = EnforcementLedger(ws, tmp_path / "ledger.jsonl")

    upheld = ledger.challenge("w1", att, lambda uri: bundle, trusted_voters=anchor,
                              expected_genesis_hash_b64=TESTNET_GENESIS)
    assert upheld.verdict == UPHELD

    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    removed = ledger.challenge("w2", forged, lambda uri: bundle, trusted_voters=anchor,
                               expected_genesis_hash_b64=TESTNET_GENESIS)
    assert removed.verdict == REMOVED

    live = ledger.active_witnesses()
    assert [w.witness_id for w in live.independent_corroborators(CHAIN)] == ["w1"]
    assert verify_ledger(ledger.path) == 2
