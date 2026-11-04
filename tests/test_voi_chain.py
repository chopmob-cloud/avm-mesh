"""A genuine Voi mainnet bundle, verified. The second chain, on real data.

Every other Voi reference in this suite is a *label*: `chain="voimain-v1.0"` passed to
a bond or corroboration helper, and one policy-refusal test. None of them ever verified
a Voi bundle, so the claim "works on both AVM chains" rested on shared code and an
argument about shared encoding rather than on evidence.

This file is that evidence. `examples/voi-proofpack-24213754.json.gz` is a Voi mainnet
capture, taken from `https://mainnet-api.voi.nodely.dev` for transaction
`75LUFZZNQNOPS3SLQRHZZKZIECEEVGGP4N3ZZ2UU2UKFFJU5WG4A` in round 24213754, with the
bundle's SHA-256 pinned below so it cannot drift.

What it proves: the receipt path is chain-agnostic where it claims to be. The Voi bundle
reaches `stake_attested` against a Voi genesis pin and a Voi anchor, the amount binding
reads a real Voi asset transfer, and an Algorand genesis pin is refused for it.

What it does not prove: Voi and Algorand share an encoding (they do not share a genesis,
which is the point), or that the Voi node is honest. It is one capture from one endpoint.
"""
import base64
import gzip
import hashlib
import json
import pathlib
from typing import Any

import pytest

from avm_mesh import MeshError
from avm_mesh.effects import verify_settlement_amount
from avm_mesh.receipt import _verify_bundle_dict
from avm_proofpack.verify import TrustedVoters

BUNDLE = pathlib.Path(__file__).resolve().parents[1] / "examples" / "voi-proofpack-24213754.json.gz"

#: SHA-256 of the uncompressed bundle as captured. Changing the fixture changes this.
BUNDLE_SHA256 = "5ba9ffb8a97da8ea477a5c22e929bc89af954479ad306b003b09375c84a8fc57"

VOI_GENESIS = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="
ALGORAND_GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="

TXID = "75LUFZZNQNOPS3SLQRHZZKZIECEEVGGP4N3ZZ2UU2UKFFJU5WG4A"
ROUND = 24213754
ASSET_ID = 586896


def _bundle() -> dict[str, Any]:
    if not BUNDLE.exists():
        pytest.skip(f"Voi fixture absent: {BUNDLE}")
    return json.loads(gzip.decompress(BUNDLE.read_bytes()))


def _anchor(bundle: dict[str, Any]) -> TrustedVoters:
    """The anchor a Voi operator would supply: the previous interval's message.

    Deliberately the same construction the Algorand tests use, so a difference in
    outcome would be a difference in the chain rather than in the test.
    """
    previous = bundle["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(previous["voters_commitment_b64"]),
                         int(previous["ln_proven_weight"]))


# ---------------------------------------------------------------- the fixture itself


def test_the_captured_bytes_are_the_bytes_that_were_verified():
    """A fixture whose hash is not pinned is a fixture that can drift silently."""
    digest = hashlib.sha256(gzip.decompress(BUNDLE.read_bytes())).hexdigest()
    assert digest == BUNDLE_SHA256, "the Voi fixture changed; re-verify before updating the pin"


def test_the_bundle_identifies_itself_as_voi():
    bundle = _bundle()
    assert bundle["chain"]["genesis_id"] == "voimain-v1.0"
    assert bundle["chain"]["genesis_hash_b64"] == VOI_GENESIS
    assert bundle["transaction"]["txid"] == TXID
    assert bundle["transaction"]["round"] == ROUND


# ------------------------------------------------------------------ the real claim


def test_a_voi_bundle_reaches_stake_attested_with_a_voi_anchor():
    """The tier that requires an anchor, on the second chain, for the first time."""
    bundle = _bundle()
    report = _verify_bundle_dict(bundle, _anchor(bundle), base64.b64decode(VOI_GENESIS))
    assert report.trust_root == "stake_attested"
    assert report.genesis_id == "voimain-v1.0"
    assert report.txid == TXID
    assert report.round == ROUND


def test_an_algorand_genesis_pin_refuses_a_voi_bundle():
    """The genesis pin is what stops a receipt moving between the two chains."""
    bundle = _bundle()
    with pytest.raises(Exception) as exc:
        _verify_bundle_dict(bundle, _anchor(bundle), base64.b64decode(ALGORAND_GENESIS))
    assert "different chain" in str(exc.value)


def test_a_voi_bundle_without_an_anchor_stays_unattested():
    """No anchor, no stake_attested -- the anchor is what the tier is defined against."""
    bundle = _bundle()
    report = _verify_bundle_dict(bundle, None, base64.b64decode(VOI_GENESIS))
    assert report.trust_root == "unattested"


# ------------------------------------------------------------- amount binding on Voi


def test_the_amount_binding_reads_a_real_voi_asset_transfer():
    """The Voi fixture is an ASA transfer, so the binding must speak asset units."""
    bundle = _bundle()
    report = _verify_bundle_dict(bundle, _anchor(bundle), base64.b64decode(VOI_GENESIS))
    # The captured axfer moved 0 units of asset 586896; asserting the true value
    # rather than a convenient one is the point of the test.
    assert verify_settlement_amount(
        bundle, {"asset": ASSET_ID, "amount": "0"}, report.genesis_id) is None


def test_a_voi_amount_the_transaction_did_not_move_is_refused():
    bundle = _bundle()
    report = _verify_bundle_dict(bundle, _anchor(bundle), base64.b64decode(VOI_GENESIS))
    with pytest.raises(MeshError, match="does not match the on-chain transfer"):
        verify_settlement_amount(bundle, {"asset": ASSET_ID, "amount": "1"}, report.genesis_id)


def test_a_voi_asset_id_the_transaction_did_not_move_is_refused():
    bundle = _bundle()
    report = _verify_bundle_dict(bundle, _anchor(bundle), base64.b64decode(VOI_GENESIS))
    with pytest.raises(MeshError, match="moved asset"):
        verify_settlement_amount(bundle, {"asset": 999, "amount": "0"}, report.genesis_id)


def test_a_native_unit_claim_on_an_asset_transfer_is_refused():
    """Voi's native unit cannot be claimed against an ASA transfer."""
    bundle = _bundle()
    report = _verify_bundle_dict(bundle, _anchor(bundle), base64.b64decode(VOI_GENESIS))
    with pytest.raises(MeshError, match="not a payment"):
        verify_settlement_amount(bundle, {"amount": "0"}, report.genesis_id)


# ------------------------------------------------------------ the walk on Voi, offline


def test_a_voi_state_proof_chains_forward_from_a_voi_checkpoint():
    """The anchor walk on Voi, using captures checked in beside this test."""
    from avm_mesh.anchor import walk

    captures = pathlib.Path(__file__).resolve().parents[1] / "examples" / "walk-voi-24213760"
    if not captures.exists():
        pytest.skip("Voi walk captures absent")

    with gzip.open(captures / "24213248.json.gz", "rt", encoding="utf-8") as handle:
        anchor_message = json.load(handle)["state_proof_message"]

    result = walk(
        genesis_hash_b64=VOI_GENESIS,
        anchor_round=int(anchor_message["last_attested_round"]),
        voters_commitment_b64=anchor_message["voters_commitment_b64"],
        ln_proven_weight=int(anchor_message["ln_proven_weight"]),
        target_round=24213760,
        bundles=captures,
    )
    assert result.ok, result.failure
    assert result.links_verified == 2


# ------------------------------------- through the public API, not the private helper
#
# The tests above call `_verify_bundle_dict` directly, which is why a mutation that
# removed the anchor from `verify_receipt` left the whole file green. A user never
# calls the private helper: they call `create_receipt` and `verify_receipt`. These
# two tests are the ones that would have caught it.


def test_a_voi_receipt_round_trips_through_the_public_api(tmp_path):
    """Create a receipt from a Voi bundle, then verify it -- the path a user walks."""
    from avm_mesh.receipt import create_receipt, verify_receipt

    bundle = _bundle()
    anchor = _anchor(bundle)
    receipt = create_receipt(bundle, "voi://bundle", trusted_voters=anchor)

    assert receipt.chain == "voimain-v1.0"
    assert receipt.txid == TXID
    assert receipt.round == ROUND
    assert receipt.trust_root == "stake_attested"
    # The pointer records the attested INTERVAL, not the transaction's own round:
    # the interval is 256 rounds wide and 24213754 sits inside it.
    assert receipt.pointer.last_attested_round == 24213760
    assert receipt.pointer.first_attested_round == 24213760 - 255
    assert receipt.pointer.first_attested_round <= ROUND <= receipt.pointer.last_attested_round

    report = verify_receipt(
        receipt,
        lambda uri: bundle,
        expected_genesis_hash_b64=VOI_GENESIS,
        trusted_voters=anchor,
    )
    assert report.trust_root == "stake_attested"
    assert report.genesis_id == "voimain-v1.0"


def test_a_voi_receipt_verified_with_an_algorand_genesis_is_refused():
    """The public path must honour the genesis pin, not merely the private helper."""
    from avm_mesh.receipt import create_receipt, verify_receipt

    bundle = _bundle()
    anchor = _anchor(bundle)
    receipt = create_receipt(bundle, "voi://bundle", trusted_voters=anchor)

    with pytest.raises(MeshError, match="different chain"):
        verify_receipt(receipt, lambda uri: bundle,
                       expected_genesis_hash_b64=ALGORAND_GENESIS,
                       trusted_voters=anchor)


def test_a_voi_receipt_verified_without_its_anchor_is_refused():
    """A receipt that claims stake_attested must not verify when the anchor is missing."""
    from avm_mesh.receipt import create_receipt, verify_receipt

    bundle = _bundle()
    receipt = create_receipt(bundle, "voi://bundle", trusted_voters=_anchor(bundle))

    with pytest.raises(MeshError) as exc:
        verify_receipt(receipt, lambda uri: bundle, expected_genesis_hash_b64=VOI_GENESIS)
    # Without an anchor the bundle cannot reach the tier the receipt claims.
    assert "trust root" in str(exc.value) or "stake_attested" in str(exc.value)
