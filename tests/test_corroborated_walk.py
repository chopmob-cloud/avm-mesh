"""A walk whose intervals were corroborated across unrelated operators at capture time.

The claim this file is built to test is narrow and checkable: the anchor a walk derives is
the same anchor the operators independently reported, so provenance is not one endpoint's
private view. Every earlier walk in this repository was a single-endpoint capture and said
so in its provenance.

What is tested here:

* the recorded capture set walks from its own first interval to its last, deriving an
  anchor with no reference to the network;
* the derived `ln_proven_weight` equals what the capture set's corroboration block records
  every operator reporting for the interval that produced it — agreement between two
  independently obtained facts, not between a fact and itself;
* the capture set refuses to overstate itself: a bundle edited to claim a round it does not
  attest is refused, and a missing interval breaks the chain rather than being skipped.

What is NOT tested here, because it cannot be: that the two endpoints are commercially
separate. `provenance.json` says so in its `independence` field, in the same words, and a
reader who knows otherwise should say so rather than trusting the field.
"""
import base64
import gzip
import json
import pathlib
import shutil

import pytest

from avm_mesh.anchor import walk
from avm_mesh.receipt import MeshError

GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
CAPTURES = pathlib.Path(__file__).resolve().parents[1] / "examples" / "walk-mainnet-corroborated"

pytestmark = pytest.mark.skipif(
    not CAPTURES.exists(), reason="corroborated walk captures are not present")


def _provenance() -> dict:
    return json.loads((CAPTURES / "provenance.json").read_text(encoding="utf-8"))


def _bundle(round_number: int) -> dict:
    return json.loads(gzip.decompress((CAPTURES / f"{round_number}.json.gz").read_bytes()))


def _rounds() -> list[int]:
    return _provenance()["captured_rounds"]


def test_the_capture_set_is_marked_corroborated_across_operators():
    """The property that makes this capture set different from every earlier one."""
    record = _provenance()
    assert record["cross_operator_agreement"] is True
    assert len(record["operators"]) >= 2
    assert len({op["endpoint"] for op in record["operators"]}) == len(record["operators"])
    for entry in record["corroboration"]:
        assert entry["corroborated"] is True, entry
        assert len(entry["operators_answering"]) >= 2, entry


def test_the_provenance_names_what_independence_does_not_mean():
    """A reader must not take 'agreed' as 'these are separately owned'."""
    record = _provenance()
    assert "not proof of independent ownership" in record["independence"]
    assert "shared upstream" in record["independence"]
    assert "retention_note" in record, "the retention limit must be recorded, not implied"
    assert "three" in record["retention_note"]


def test_the_walk_verifies_and_derives_the_reported_anchor():
    """The two facts that must agree: what the walk derives, what the operators said.

    This is the whole point of the exercise. A corroborated capture is only worth
    something if the anchor derived from it lands on a value an independent operator also
    reported for the same interval, so the test compares the walk's output against the
    recorded corroboration rather than against a constant this file could have been
    written to satisfy.
    """
    rounds = _rounds()
    first = _bundle(rounds[0])["state_proof_message"]
    result = walk(
        genesis_hash_b64=GENESIS,
        anchor_round=first["last_attested_round"],
        voters_commitment_b64=first["voters_commitment_b64"],
        ln_proven_weight=first["ln_proven_weight"],
        target_round=rounds[-1],
        bundles=CAPTURES,
    )
    assert result.ok is True, result.failure
    assert result.links_verified == len(rounds) - 1

    # `target_inputs` are the inputs needed to VERIFY the target's proof, which is the
    # PRECEDING interval's signing set -- not the target's own. Getting this the wrong way
    # round was the first version of this test, and it failed by one unit of weight
    # (2230294 vs 2230295), which is exactly the kind of off-by-one-interval mistake a
    # test should be written against deliberately rather than adjusted until it passes.
    preceding = next(e for e in _provenance()["corroboration"]
                     if e["round"] == rounds[-2])
    reported = {r["fields"]["LnProvenWeight"] for r in preceding["responses"].values()
                if r["ok"]}
    commitments = {r["fields"]["VotersCommitment"] for r in preceding["responses"].values()
                   if r["ok"]}
    assert len(reported) == 1, "operators did not agree on the weight they reported"
    assert len(commitments) == 1, "operators did not agree on the commitment they reported"

    # The walk derived these from the proofs alone. The operators reported them from their
    # own ledgers. Two independent derivations landing on the same value is the evidence.
    assert result.ln_proven_weight == reported.pop()
    assert result.voters_commitment_b64 == commitments.pop()


def test_the_full_chain_links_every_interval():
    rounds = _rounds()
    assert len(rounds) >= 3, "a corroborated walk should span at least three intervals"
    first = _bundle(rounds[0])["state_proof_message"]
    result = walk(
        genesis_hash_b64=GENESIS,
        anchor_round=first["last_attested_round"],
        voters_commitment_b64=first["voters_commitment_b64"],
        ln_proven_weight=first["ln_proven_weight"],
        target_round=rounds[-1],
        bundles=CAPTURES,
    )
    assert result.ok is True, result.failure
    assert result.links_verified == len(rounds) - 1


def test_every_capture_states_which_operators_corroborated_it():
    """A capture that does not say who agreed is not evidence of agreement."""
    for entry in _provenance()["captures"]:
        assert entry["corroborated_by"], entry
        assert len(entry["corroborated_by"]) >= 2, entry


def test_the_recorded_hashes_match_the_committed_bytes():
    """Pins the fixtures: a walk that verifies from drifted bytes proves nothing."""
    import hashlib
    for entry in _provenance()["captures"]:
        raw = (CAPTURES / entry["file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["sha256_gz"], entry["file"]


# ------------------------------------------------------------- hostile variants


def test_a_capture_claimed_for_a_round_it_does_not_attest_is_refused(tmp_path):
    rounds = _rounds()
    for entry in _provenance()["captures"]:
        shutil.copy(CAPTURES / entry["file"], tmp_path / entry["file"])
    bundle = _bundle(rounds[1])
    bundle["state_proof_message"]["last_attested_round"] = rounds[1] + 256
    (tmp_path / f"{rounds[1]}.json.gz").write_bytes(
        gzip.compress(json.dumps(bundle, sort_keys=True).encode(), 9, mtime=0))

    first = _bundle(rounds[0])["state_proof_message"]
    with pytest.raises(MeshError):
        walk(genesis_hash_b64=GENESIS,
             anchor_round=first["last_attested_round"],
             voters_commitment_b64=first["voters_commitment_b64"],
             ln_proven_weight=first["ln_proven_weight"],
             target_round=rounds[-1],
             bundles=tmp_path)


def test_a_missing_interval_breaks_the_chain_instead_of_being_skipped(tmp_path):
    rounds = _rounds()
    for entry in _provenance()["captures"]:
        if entry["round"] == rounds[1]:
            continue   # drop the middle
        shutil.copy(CAPTURES / entry["file"], tmp_path / entry["file"])

    first = _bundle(rounds[0])["state_proof_message"]
    # Reported, not raised: `walk` returns AnchorWalk(ok=False) for a chain that cannot be
    # completed, and raises only for malformed input. A caller must be unable to mistake
    # the two, so the distinction is asserted rather than flattened.
    result = walk(genesis_hash_b64=GENESIS,
                  anchor_round=first["last_attested_round"],
                  voters_commitment_b64=first["voters_commitment_b64"],
                  ln_proven_weight=first["ln_proven_weight"],
                  target_round=rounds[-1],
                  bundles=tmp_path)
    assert result.ok is False
    assert "missing link for round" in (result.failure or "")
    assert result.links_verified == 0, "a broken chain must not report partial links as success"


def test_the_genesis_pin_is_bookkeeping_in_a_walk_and_the_docs_must_not_claim_more():
    """A walk does NOT cryptographically bind the chain. This test exists to stop anyone
    "fixing" that by asserting a property the wire format cannot support.

    A state proof and its signed message contain no genesis field, so a genesis hash
    passed to `walk` cannot be checked against the proof: it only labels the links
    consistently. The chain binding comes from the ANCHOR's voters commitment, which the
    proofs ARE verified against. `avm_proofpack.consensus.chain.ChainAnchor` documents
    this. The receipt path is different and stronger -- `expected_genesis_hash_b64` there
    is checked against the authenticated block header -- and README says so.

    So a walk given a Voi genesis pin over Algorand captures still succeeds, and that is
    correct behaviour rather than a hole. What would be wrong is documentation implying
    otherwise, or a caller relying on this argument for cross-chain safety.
    """
    rounds = _rounds()
    first = _bundle(rounds[0])["state_proof_message"]
    result = walk(genesis_hash_b64="r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=",
                  anchor_round=first["last_attested_round"],
                  voters_commitment_b64=first["voters_commitment_b64"],
                  ln_proven_weight=first["ln_proven_weight"],
                  target_round=rounds[1],
                  bundles=CAPTURES)
    assert result.ok is True, (
        "if this ever fails, the wire format changed and a genesis field appeared; "
        "update the docs AND this comment rather than deleting the test")

    # The real binding: the anchor's voters commitment. Switch it to something else and
    # the walk must refuse, which is what makes cross-chain replay impossible.
    other = base64.b64encode(bytes(range(64))).decode()
    refused = walk(genesis_hash_b64=GENESIS,
                   anchor_round=first["last_attested_round"],
                   voters_commitment_b64=other,
                   ln_proven_weight=first["ln_proven_weight"],
                   target_round=rounds[1],
                   bundles=CAPTURES)
    assert refused.ok is False, "a wrong voters commitment verified a chain"
    assert refused.failure
