"""Anchor walks: a pinned checkpoint, every interval verified forward from it."""
import base64
import gzip
import json
import pathlib
import shutil
import tempfile

import pytest

import _assets
from avm_mesh import MeshError
from avm_mesh.anchor import links_from_directory, walk

GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
TARGET = 66457600
ANCHOR = 66457344          # the previous interval's last attested round
BUNDLE = _assets.fixture_bundle()


def _bundle() -> dict:
    _assets.require(BUNDLE, "fixture")
    with gzip.open(BUNDLE, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def _capture(bundle: dict | None = None, name: int | None = None) -> pathlib.Path:
    """Write a bundle into a fresh capture directory named for its round."""
    directory = pathlib.Path(tempfile.mkdtemp(prefix="anchor-"))
    with gzip.open(directory / f"{name if name is not None else TARGET}.json.gz",
                   "wt", encoding="utf-8") as handle:
        json.dump(bundle if bundle is not None else _bundle(), handle)
    return directory


@pytest.fixture
def bundles() -> pathlib.Path:
    _assets.require(BUNDLE, "fixture")
    directory = pathlib.Path(tempfile.mkdtemp(prefix="anchor-"))
    shutil.copy(BUNDLE, directory / f"{TARGET}.json.gz")
    return directory


def _walk(bundle, directory, **overrides):
    prev = bundle["previous_state_proof_message"]
    kwargs = dict(
        genesis_hash_b64=GENESIS,
        anchor_round=ANCHOR,
        voters_commitment_b64=prev["voters_commitment_b64"],
        ln_proven_weight=int(prev["ln_proven_weight"]),
        target_round=TARGET,
        bundles=directory,
    )
    kwargs.update(overrides)
    return walk(**kwargs)


# ---------------------------------------------------------------- real walk

def test_one_hop_walk_authenticates_the_real_interval():
    bundle = _bundle()
    result = _walk(bundle, _capture())
    assert result.ok, result.failure
    assert result.links_verified == 1
    assert result.target_round == TARGET


def test_the_walk_derives_the_anchor_the_verifier_needs():
    """The derived value must be usable as `verify --voters-commitment`.

    This is the point of the feature: the anchor comes from a pinned checkpoint and
    a verified walk, not from the bundle being checked.
    """
    bundle = _bundle()
    result = _walk(bundle, _capture())
    assert result.ok, result.failure
    assert len(base64.b64decode(result.voters_commitment_b64)) == 64
    assert result.ln_proven_weight > 0
    # It is the previous interval's authenticated inputs, which is what the proof at
    # the target round is signed against.
    assert result.voters_commitment_b64 == bundle["previous_state_proof_message"]["voters_commitment_b64"]


def test_walk_reports_its_trust_basis():
    """A walk must never read as absolute trust: it is anchored in one checkpoint."""
    payload = _walk(_bundle(), _capture()).to_dict()
    assert payload["ok"] is True
    assert "pinned checkpoint" in payload["trust_basis"]


# ------------------------------------------------------------- wrong inputs

def test_a_wrong_checkpoint_fails_the_walk():
    bundle = _bundle()
    result = _walk(bundle, _capture(),
                   ln_proven_weight=int(bundle["previous_state_proof_message"]["ln_proven_weight"]) + 1)
    assert not result.ok
    assert result.failure


def test_a_checkpoint_from_another_chain_fails():
    result = _walk(_bundle(), _capture(),
                   voters_commitment_b64=base64.b64encode(b"\x01" * 64).decode())
    assert not result.ok


def test_a_missing_interval_fails_and_names_the_round():
    """Walk one interval further than the capture reaches: the gap must be named."""
    result = _walk(_bundle(), _capture(), target_round=TARGET + 256)
    assert not result.ok
    assert str(TARGET + 256) in (result.failure or "")


# ----------------------------------------------------------------- refusals

def test_genesis_must_be_the_right_length():
    with pytest.raises(MeshError, match="32 bytes"):
        _walk(_bundle(), _capture(), genesis_hash_b64=base64.b64encode(b"x" * 8).decode())


def test_base64_is_validated():
    with pytest.raises(MeshError, match="not valid base64"):
        _walk(_bundle(), _capture(), genesis_hash_b64="!!!!")


def test_target_must_be_beyond_the_anchor():
    with pytest.raises(MeshError, match="beyond the anchor"):
        _walk(_bundle(), _capture(), target_round=ANCHOR)


def test_target_must_sit_on_the_interval_grid():
    with pytest.raises(MeshError, match="interval grid"):
        _walk(_bundle(), _capture(), target_round=TARGET + 1)


def test_bad_types_are_refused_not_coerced():
    bundle = _bundle()
    directory = _capture()
    for field, value in (("anchor_round", "66457344"), ("target_round", "66457600"),
                         ("ln_proven_weight", "2230418"), ("interval", 0)):
        with pytest.raises(MeshError):
            _walk(bundle, directory, **{field: value})


def test_a_missing_directory_is_refused(tmp_path):
    with pytest.raises(MeshError, match="does not exist"):
        links_from_directory(tmp_path / "absent", base64.b64decode(GENESIS))


def test_a_file_where_a_directory_belongs_is_refused(tmp_path):
    path = tmp_path / "not-a-dir"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(MeshError, match="not a directory"):
        links_from_directory(path, base64.b64decode(GENESIS))


def test_a_mislabelled_capture_is_refused():
    with pytest.raises(MeshError, match="attests round"):
        links_from_directory(_capture(name=TARGET + 256), base64.b64decode(GENESIS))


def test_a_file_that_is_not_a_bundle_is_refused(tmp_path):
    directory = tmp_path / "b"
    directory.mkdir()
    (directory / f"{TARGET}.json").write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(MeshError, match="missing state_proof"):
        links_from_directory(directory, base64.b64decode(GENESIS))


def test_invalid_json_is_refused(tmp_path):
    directory = tmp_path / "b"
    directory.mkdir()
    (directory / f"{TARGET}.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(MeshError, match="not valid JSON"):
        links_from_directory(directory, base64.b64decode(GENESIS))


def test_an_empty_directory_is_refused(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(MeshError, match="no bundles"):
        links_from_directory(empty, base64.b64decode(GENESIS))


def test_unparseable_filenames_are_refused(tmp_path):
    directory = tmp_path / "b"
    directory.mkdir()
    (directory / "bundle.json").write_text("{}", encoding="utf-8")
    with pytest.raises(MeshError, match="filename must be the attested round"):
        links_from_directory(directory, base64.b64decode(GENESIS))
