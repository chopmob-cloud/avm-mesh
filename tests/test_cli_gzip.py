"""The CLI resolver reads a proofpack correctly, including a gzipped one.

Two defects lived here and neither was caught, because the only shipped proofpack was
plain JSON:

1. **Text-mode reads on Windows.** `os.open(path, os.O_RDONLY)` on Windows gives a
   text-mode descriptor, and `os.read` then stops at the first `0x1A` byte — EOF to the
   C runtime. A gzip stream contains `0x1A` early (the Voi fixture has one at offset 100
   of 110,773), so the file was silently truncated to 100 bytes and then failed to
   decompress with "Compressed file ended before the end-of-stream marker". Plain JSON
   never contains `0x1A`, which is why the Algorand example passed and hid it.

2. **Gzip was not supported at all.** The Voi example ships as `.json.gz` and the
   resolver decoded bytes as UTF-8 regardless, so `avm-mesh verify` could not read it.

The byte-level read is exposed as `cli.read_bounded_bytes` precisely so it can be tested
without a JSON layer in the way. Routing the 0x1A case through the resolver meant the
JSON parser rejected the fixture whether or not the read truncated — three fixture
attempts failed for the wrong reason before the seam was added.
"""
import gzip
import json
import pathlib

import pytest

from avm_mesh import cli as cli_module


def _resolver(tmp_path, **kwargs):
    root = tmp_path / "evidence"
    root.mkdir(exist_ok=True)
    return root, cli_module._file_resolver(root, **kwargs)


# ---------------------------------------------------------------- the byte reader


def test_the_reader_returns_every_byte_including_a_0x1a(tmp_path):
    """The exact Windows defect: a descriptor without O_BINARY stops at 0x1A.

    The file has a 0x1A at offset 100 and 20,000 bytes after it, so a truncating reader
    returns 100 and a correct one returns the lot.
    """
    path = tmp_path / "payload.bin"
    body = b"a" * 100 + b"\x1a" + b"b" * 20_000
    path.write_bytes(body)

    got = cli_module.read_bounded_bytes(path, max_bytes=1_000_000)
    assert len(got) == len(body), f"truncated at 0x1A: got {len(got)} of {len(body)}"
    assert got[-1:] == b"b"


def test_the_reader_returns_a_binary_gzip_envelope_intact(tmp_path):
    """A realistic case: gzip output, which contains 0x1A freely."""
    path = tmp_path / "envelope.bin"
    envelope = gzip.compress(bytes(range(256)) * 40, 0, mtime=0)
    path.write_bytes(envelope)
    assert 0 < envelope.find(b"\x1a") < 400

    got = cli_module.read_bounded_bytes(path, max_bytes=1_000_000)
    assert got == envelope


def test_the_reader_refuses_a_file_over_the_cap(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 5000)
    with pytest.raises(ValueError, match="byte cap"):
        cli_module.read_bounded_bytes(path, max_bytes=1000)


def test_the_reader_refuses_a_symlink(tmp_path):
    target = tmp_path / "real.bin"
    target.write_bytes(b"data")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")
    with pytest.raises(FileNotFoundError):
        cli_module.read_bounded_bytes(link, max_bytes=1000)


# ------------------------------------------------------------- the resolver


def test_a_gzipped_proofpack_is_read(tmp_path):
    """`.json.gz` is a supported proofpack form, so the resolver must read it."""
    root, resolve = _resolver(tmp_path)
    payload = {"settlement": {"tx_id": "GZ-1"}, "pad": "y" * 4000}
    (root / "bundle.json.gz").write_bytes(
        gzip.compress(json.dumps(payload).encode(), 9, mtime=0))

    assert resolve("bundle.json.gz") == payload


def test_gzip_is_detected_from_the_bytes_not_the_name(tmp_path):
    """A gzip capture left with a `.json` name is a real accident and should still load."""
    root, resolve = _resolver(tmp_path)
    payload = {"ok": True}
    (root / "mislabelled.json").write_bytes(
        gzip.compress(json.dumps(payload).encode(), 9, mtime=0))

    assert resolve("mislabelled.json") == payload


def test_a_gz_name_over_plain_bytes_is_refused(tmp_path):
    """The reverse is refused: a name that lies about its contents is a reason to stop."""
    root, resolve = _resolver(tmp_path)
    (root / "lies.json.gz").write_text(json.dumps({"ok": True}), encoding="utf-8")

    with pytest.raises(ValueError, match="named .gz but does not begin with gzip data"):
        resolve("lies.json.gz")


def test_a_truncated_gzip_is_refused_with_a_clear_message(tmp_path):
    root, resolve = _resolver(tmp_path)
    whole = gzip.compress(b'{"ok": true}', 9, mtime=0)
    (root / "cut.json.gz").write_bytes(whole[: len(whole) // 2])

    with pytest.raises(ValueError, match="not a readable gzip stream"):
        resolve("cut.json.gz")


def test_a_gzip_bomb_past_the_cap_is_refused(tmp_path):
    """The cap applies to the DECOMPRESSED bytes: a small file can expand enormously."""
    root, resolve = _resolver(tmp_path, max_bytes=1024)
    (root / "bomb.json.gz").write_bytes(
        gzip.compress(b'{"pad": "' + b"z" * 50000 + b'"}', 9, mtime=0))

    with pytest.raises(ValueError, match="expands past the .* byte cap"):
        resolve("bomb.json.gz")


def test_the_shipped_voi_example_resolves_through_the_cli():
    """The end-to-end case this was found by: the example must be readable by a user."""
    examples = pathlib.Path(__file__).resolve().parents[1] / "examples"
    bundle = examples / "voi-proofpack-24213754.json.gz"
    if not bundle.exists():
        pytest.skip("Voi example absent")

    got = cli_module._file_resolver(examples)(bundle.name)
    assert got["chain"]["genesis_id"] == "voimain-v1.0"
    assert got["transaction"]["round"] == 24213754
