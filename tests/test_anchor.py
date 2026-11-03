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
from avm_mesh import anchor as anchor_module
from avm_mesh.anchor import links_from_directory, load_bundle, walk

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


# ------------------------------------------------------------ size and bombs

def test_an_oversized_capture_is_refused_before_reading(tmp_path, monkeypatch):
    """Cheap check first: a huge plain file never gets opened."""
    monkeypatch.setattr(anchor_module, "MAX_BUNDLE_BYTES", 512)
    big = tmp_path / "66457600.json"
    big.write_text("x" * 4096, encoding="utf-8")
    with pytest.raises(MeshError, match="on disk, over the"):
        load_bundle(big)


def test_a_gzip_bomb_is_refused(tmp_path, monkeypatch):
    """Compressed size says nothing about expansion, so the read itself is capped.

    This is the case a stat() check cannot catch: 5 KB on disk, megabytes in memory.
    """
    monkeypatch.setattr(anchor_module, "MAX_BUNDLE_BYTES", 1024)
    bomb = tmp_path / "66457600.json.gz"
    with gzip.open(bomb, "wt", encoding="utf-8") as handle:
        handle.write(" " * 200_000)
    on_disk = bomb.stat().st_size
    assert on_disk < 1024, f"test needs a small compressed file, got {on_disk} bytes"
    with pytest.raises(MeshError, match="expands past"):
        load_bundle(bomb)


def test_a_normal_bundle_still_loads(tmp_path):
    path = tmp_path / "b.json"
    path.write_text('{"a": 1}', encoding="utf-8")
    assert load_bundle(path) == {"a": 1}


def test_a_corrupt_gzip_is_refused_not_crashed(tmp_path):
    """Named .gz but not gzip data: refused, and the message names the mismatch.

    The refusal still comes from the loader rather than from the JSON parser, because
    "Expecting value" tells a caller nothing about a file they believe is compressed.
    """
    path = tmp_path / "b.json.gz"
    path.write_bytes(b"not a gzip stream")
    with pytest.raises(MeshError, match="named .gz but does not begin with gzip data"):
        load_bundle(path)


def test_deeply_nested_json_is_refused_not_crashed(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(MeshError):
        load_bundle(path)


# ------------------------------------------- malformed input stays inside MeshError

def test_a_truncated_gzip_is_refused_not_raised_as_eof(tmp_path):
    """A missing gzip trailer raises EOFError, which is not an OSError."""
    path = tmp_path / "66457600.json.gz"
    good = tmp_path / "good.gz"
    with gzip.open(good, "wt", encoding="utf-8") as handle:
        json.dump({"a": "b" * 200}, handle)
    path.write_bytes(good.read_bytes()[:-5])
    with pytest.raises(MeshError, match="cannot read"):
        load_bundle(path)


def test_a_non_ascii_digit_filename_is_refused(tmp_path):
    """"\u00b2".isdigit() is True, int() then raises ValueError."""
    directory = tmp_path / "b"
    directory.mkdir()
    (directory / "\u00b2.json").write_text("{}", encoding="utf-8")
    with pytest.raises(MeshError, match="ASCII decimal digits"):
        links_from_directory(directory, base64.b64decode(GENESIS))


def test_a_stray_file_is_ignored_when_the_walk_does_not_need_it(tmp_path):
    """Capture directories collect junk; only the rounds in range matter."""
    directory = tmp_path / "b"
    directory.mkdir()
    (directory / "notes.txt").write_text("ignore me", encoding="utf-8")
    with gzip.open(directory / f"{TARGET}.json.gz", "wt", encoding="utf-8") as handle:
        json.dump(_bundle(), handle)
    links = links_from_directory(directory, base64.b64decode(GENESIS), rounds={TARGET})
    assert set(links) == {TARGET}


# --------------------------------------------- only the needed rounds are loaded

def test_a_walk_does_not_parse_captures_it_does_not_need():
    """Per-file caps bound each capture; only the round filter bounds the total.

    The unneeded files here are deliberately unparseable. If the walk loads them it
    fails; if it loads only what it needs, it succeeds.
    """
    directory = _capture()
    for extra in (TARGET + 256, TARGET + 512, TARGET - 256):
        (directory / f"{extra}.json").write_text("{ not json at all", encoding="utf-8")
    result = _walk(_bundle(), directory)
    assert result.ok, result.failure
    assert result.links_verified == 1


def test_a_walk_that_needs_absent_rounds_says_so():
    result = _walk(_bundle(), _capture(), target_round=TARGET + 512)
    assert not result.ok
    # The first needed round is present; the second is not, and the walk names it.
    assert "missing link" in (result.failure or "")


def test_an_absurd_interval_count_is_refused():
    with pytest.raises(MeshError, match="over the .* limit"):
        links_from_directory(_capture(), base64.b64decode(GENESIS),
                             rounds=set(range(0, 5000 * 256, 256)))


# ---------------------------------------------------- capture directory hygiene
#
# Three defects named in the handover, each closed here: a symlink inside a capture
# directory was followed, the gzip decision came from the filename rather than the
# bytes, and the directory cap was applied only after every entry had been listed.


def test_load_bundle_refuses_a_symlinked_capture(tmp_path):
    """A capture is a file placed here, not a pointer to somewhere else.

    `is_file()` follows symlinks, so without this refusal a link named for a round
    would be read from outside the directory the operator was asked to trust, and its
    bytes would become evidence.
    """
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps({"not": "a capture"}), encoding="utf-8")
    link = tmp_path / "66457600.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")

    with pytest.raises(MeshError, match="symlink"):
        load_bundle(link)


def test_links_from_directory_refuses_a_symlinked_capture(tmp_path):
    """The refusal names the file, and happens before any decoding."""
    target = tmp_path / "real.json"
    target.write_text(json.dumps(_bundle()), encoding="utf-8")
    link = tmp_path / f"{TARGET}.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")

    with pytest.raises(MeshError, match="symlink"):
        links_from_directory(tmp_path, base64.b64decode(GENESIS))


def test_gzip_is_detected_from_the_bytes_not_the_name(tmp_path):
    """A `.json` file that is really gzip loads: the bytes decide the decoder.

    This is the accident worth tolerating -- a capture compressed and left with its
    plain name. The reverse is refused rather than tolerated: a `.gz` name over bytes
    that are not gzip means the file is not what the operator believes it is, and in a
    trust path a name/content mismatch is a reason to stop, not to guess.
    """
    body = json.dumps(_bundle()).encode()
    compressed = tmp_path / "66457600.json"
    with gzip.open(compressed, "wb") as handle:
        handle.write(body)
    assert compressed.suffix == ".json"
    assert load_bundle(compressed) == _bundle()

    mislabelled = tmp_path / "66457728.json.gz"
    mislabelled.write_bytes(body)
    assert mislabelled.suffix == ".gz"
    with pytest.raises(MeshError, match="named .gz but does not begin with gzip data"):
        load_bundle(mislabelled)


GZIP_HEADER_TRUNCATED = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + b"\x00" * 8


def test_a_truncated_gzip_is_refused_whatever_it_is_called(tmp_path):
    """Sniffing by magic must not lose the error handling the suffix path had."""
    truncated = tmp_path / "66457600.json"
    truncated.write_bytes(GZIP_HEADER_TRUNCATED)
    with pytest.raises(MeshError, match="cannot read"):
        load_bundle(truncated)


def test_the_directory_cap_applies_while_scanning(tmp_path, monkeypatch):
    """The cap must bite during enumeration, not after it.

    Every entry is listed before the loop can look at any of them, so a limit checked
    inside the loop bounds loading but not the listing. Lowered here so the test does
    not have to create ten thousand files.
    """
    monkeypatch.setattr(anchor_module, "MAX_DIRECTORY_ENTRIES", 4)
    for i in range(6):
        (tmp_path / f"stray-{i}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(MeshError, match="more than 4 entries"):
        links_from_directory(tmp_path, base64.b64decode(GENESIS))


def test_a_directory_within_the_cap_is_walked_normally():
    """The cap must not refuse an ordinary single-capture directory."""
    result = _walk(_bundle(), _capture())
    assert result.ok, result.failure
