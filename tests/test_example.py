"""The committed worked example must keep verifying.

`examples/receipt-66457600.json` points at `examples/proofpack-66457600.json`, which
is real Algorand mainnet evidence for one payment. If a change breaks verification of
evidence we published, a stranger would find out before we did.

The anchor is the caveat: it comes from the bundle's own previous state-proof message,
because that is all the fixture carries offline. The library never accepts a bundle's
own message silently -- an anchor must be passed explicitly -- so this test pins the
tier's mechanics against real data, not an independent attestation.
"""
import base64
import json
import pathlib

import pytest

from avm_mesh import MeshError
from avm_mesh.sealed import verify_sealed

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
RECEIPT = EXAMPLES / "receipt-66457600.json"
PROOF_PACK = EXAMPLES / "proofpack-66457600.json"
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
TXID = "J6FPFF4CKP4XUWUEDLEENV7EV5YDKFZHZJC6UYYWBDVBJLAT7IIA"


def _receipt():
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _bundle():
    return json.loads(PROOF_PACK.read_text(encoding="utf-8"))


def _anchor(bundle):
    from avm_proofpack.verify import TrustedVoters
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]),
    )


def test_example_files_are_committed_and_small_enough_to_be_useful():
    assert RECEIPT.exists(), "the receipt a reader is told to verify is missing"
    assert PROOF_PACK.exists(), "the proofpack the receipt points at is missing"
    assert 0 < RECEIPT.stat().st_size < 5_000, "a receipt should be small; this one is not"


def test_example_reaches_the_stake_attested_tier():
    bundle = _bundle()
    report = verify_sealed(_receipt(), resolve=lambda uri: bundle,
                           trusted_voters=_anchor(bundle),
                           expected_genesis_hash_b64=GENESIS)
    assert report["levels"]["consensus"] == "stake_attested"
    assert report["trust_root"] == "stake_attested"


def test_example_without_an_anchor_fails_closed():
    """Publishing an example must not weaken the rule that made it safe."""
    bundle = _bundle()
    with pytest.raises(MeshError, match="anchor"):
        verify_sealed(_receipt(), resolve=lambda uri: bundle,
                      expected_genesis_hash_b64=GENESIS)


def test_example_is_bound_to_its_own_transaction():
    bundle = _bundle()
    assert bundle["transaction"]["txid"] == TXID
    tampered = {k: v for k, v in bundle.items()}
    tampered["transaction"] = dict(bundle["transaction"], txid="A" * 52)
    with pytest.raises(MeshError):
        verify_sealed(_receipt(), resolve=lambda uri: tampered,
                      trusted_voters=_anchor(bundle),
                      expected_genesis_hash_b64=GENESIS)
