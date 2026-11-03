"""Three consecutive mainnet intervals, walked. The chaining claim, on real data.

Until now the anchor walk had only ever been proven across one interval, because it
needed two captures and only one had been published. Three consecutive captures of
Algorand mainnet are checked in beside this test, fetched by
`tools/fetch_walk_captures.py` and pinned by hash in `provenance.json`, so the claim
is reproducible offline and cannot quietly stop being true.

What this establishes: each interval verifies against voters derived from the previous
interval's authenticated message, so a single pinned checkpoint carries two intervals.
That is the mechanism the module exists for, exercised for the first time.

What it does not establish: that the captures came from independent sources. All three
came from one public endpoint in one fetch. The walk proves chaining, not independence,
and `provenance.json` says so in its own `independence` field.
"""
import base64
import gzip
import hashlib
import json
import pathlib
import shutil
from typing import Any

import pytest

from avm_mesh import MeshError
from avm_mesh.anchor import links_from_directory, walk

CAPTURES = pathlib.Path(__file__).resolve().parents[1] / "examples" / "walk-mainnet-66606848"
PROVENANCE = CAPTURES / "provenance.json"

ANCHOR = 66606336
MIDDLE = 66606592
TARGET = 66606848


def _provenance() -> dict[str, Any]:
    return json.loads(PROVENANCE.read_text(encoding="utf-8"))


def _bundle(round_number: int) -> dict[str, Any]:
    with gzip.open(CAPTURES / f"{round_number}.json.gz", "rt", encoding="utf-8") as handle:
        return json.load(handle)


def _copy(tmp_path: pathlib.Path) -> pathlib.Path:
    """A private copy, so a destructive test cannot damage the checked-in evidence.

    An earlier version shared one module-scoped copy; a test that deleted a capture
    left every later test reading a directory that no longer matched the fixture.
    """
    directory = tmp_path / "captures"
    directory.mkdir()
    for path in CAPTURES.glob("*.json.gz"):
        shutil.copy(path, directory / path.name)
    return directory


def _walk(directory: pathlib.Path, *, anchor: int = ANCHOR, target: int = TARGET,
          **overrides: Any):
    message = _bundle(anchor)["state_proof_message"]
    kwargs: dict[str, Any] = {
        "genesis_hash_b64": _provenance()["genesis_hash_b64"],
        "anchor_round": anchor,
        "voters_commitment_b64": message["voters_commitment_b64"],
        "ln_proven_weight": int(message["ln_proven_weight"]),
        "target_round": target,
        "bundles": directory,
    }
    kwargs.update(overrides)
    return walk(**kwargs)


# ------------------------------------------------------------- the checked-in data


def test_the_captures_match_the_hashes_recorded_when_they_were_fetched():
    """Evidence whose hashes are not pinned is evidence you cannot date or check."""
    record = _provenance()
    assert record["chain"] == "algorand-mainnet"
    assert record["hops"] == [ANCHOR, MIDDLE, TARGET]
    assert "not source independence" in record["independence"]
    for entry in record["files"]:
        digest = hashlib.sha256((CAPTURES / entry["file"]).read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"{entry['file']} does not match its pinned hash"


def test_every_capture_attests_the_round_its_name_claims():
    for round_number in (ANCHOR, MIDDLE, TARGET):
        message = _bundle(round_number)["state_proof_message"]
        assert int(message["last_attested_round"]) == round_number
        assert int(message["first_attested_round"]) == round_number - 255


# ------------------------------------------------------------------ the real claim


def test_two_intervals_verify_from_one_pinned_checkpoint(tmp_path):
    """The chaining claim: one anchor carries more than one interval."""
    result = _walk(_copy(tmp_path))
    assert result.ok, result.failure
    assert result.links_verified == 2
    assert result.target_round == TARGET
    # The derived value is the authenticated input the target round is signed
    # against -- the middle interval's message, not the target's own forward-looking
    # set. That is the documented contract (see test_anchor.py) and it is what
    # `verify --voters-commitment` needs for a receipt at the target round.
    expected = _bundle(MIDDLE)["state_proof_message"]
    assert result.voters_commitment_b64 == expected["voters_commitment_b64"]
    assert result.ln_proven_weight == int(expected["ln_proven_weight"])


def test_the_walk_names_its_trust_basis_and_does_not_overclaim(tmp_path):
    result = _walk(_copy(tmp_path))
    assert result.ok, result.failure
    basis = result.to_dict()["trust_basis"]
    assert "pinned checkpoint" in basis
    assert "independence" not in basis.lower()


def test_a_single_hop_still_works_from_the_middle_interval(tmp_path):
    """Proves the two-link result is not an artefact of three captures being present."""
    result = _walk(_copy(tmp_path), anchor=MIDDLE)
    assert result.ok, result.failure
    assert result.links_verified == 1


# ------------------------------------------------------------- refusals, not crashes


def test_a_wrong_anchor_commitment_fails_immediately(tmp_path):
    result = _walk(_copy(tmp_path), voters_commitment_b64=base64.b64encode(b"\x11" * 64).decode())
    assert not result.ok
    assert result.links_verified == 0


def test_a_missing_middle_interval_fails_and_names_the_round(tmp_path):
    directory = _copy(tmp_path)
    (directory / f"{MIDDLE}.json.gz").unlink()
    result = _walk(directory)
    assert not result.ok
    assert str(MIDDLE) in (result.failure or "")


def test_a_corrupted_state_proof_is_refused_not_crashed(tmp_path):
    """Flip one byte inside the middle interval's proof and require a refusal."""
    directory = _copy(tmp_path)
    path = directory / f"{MIDDLE}.json.gz"
    bundle = json.loads(gzip.decompress(path.read_bytes()))
    proof = bytearray(base64.b64decode(bundle["state_proof_msgpack_b64"]))
    proof[len(proof) // 2] ^= 0xFF
    bundle["state_proof_msgpack_b64"] = base64.b64encode(bytes(proof)).decode()
    path.write_bytes(gzip.compress(json.dumps(bundle).encode(), 9))

    result = _walk(directory)
    assert not result.ok
    assert result.links_verified == 0


def test_a_mislabelled_capture_is_refused(tmp_path):
    """The filename must be the round the proof attests, or the walk is walking fiction."""
    directory = _copy(tmp_path)
    (directory / f"{MIDDLE + 256}.json.gz").write_bytes(
        (directory / f"{MIDDLE}.json.gz").read_bytes())
    with pytest.raises(MeshError, match="attests round"):
        links_from_directory(directory, base64.b64decode(_provenance()["genesis_hash_b64"]))
