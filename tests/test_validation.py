"""Every input path refuses bad input with the module's own error type.

The rule the package promises: callers see ``MeshError`` (or a clean exit code from
the CLI), never ``TypeError``, ``KeyError``, ``RecursionError`` or an unbounded read.
These tests attack the inputs added in 0.6.0 — directories, corroboration arguments,
service configuration — because new surface is where validation is usually thinnest.
"""
import json
import pathlib

import pytest

from avm_mesh import MeshError
from avm_mesh.corroborate import collect
from avm_mesh.directory import (
    DIRECTORY_VERSION,
    MAX_DIRECTORY_BYTES,
    MAX_WITNESSES,
    load_directory,
    parse_directory,
)
from avm_mesh.service import Store, WitnessInfo, make_server, run_in_thread

# ---------------------------------------------------------------- directories


def test_oversized_directory_is_refused_before_parsing(tmp_path):
    path = tmp_path / "big.json"
    path.write_text(" " * (MAX_DIRECTORY_BYTES + 1), encoding="utf-8")
    with pytest.raises(MeshError, match="too large"):
        load_directory(str(path))


def test_oversized_body_without_content_length_is_refused(monkeypatch):
    """Pin the post-read length check, not the Content-Length or stat shortcut.

    A server is free to omit Content-Length and stream a body far larger than it
    declared, so the guard that matters is the one on the bytes actually read.
    """
    class FakeResponse:
        status = 200
        headers: dict = {}

        def read(self, size: int = -1) -> bytes:
            return b" " * (MAX_DIRECTORY_BYTES + 1)

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> bool:
            return False

    class FakeOpener:
        def open(self, url, timeout=None):
            return FakeResponse()

    # The fetch now goes through the address guard, so stub that too -- otherwise the
    # test measures DNS resolution of a .invalid host instead of the size cap.
    monkeypatch.setattr("avm_mesh.net._check_url", lambda *a, **k: None)
    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: FakeOpener())
    with pytest.raises(MeshError, match="too large|more than the"):
        load_directory("https://example.invalid/dir.json")


def test_deeply_nested_json_is_refused_not_crashed(tmp_path):
    """json.loads raises RecursionError on deep nesting; that must not escape."""
    path = tmp_path / "deep.json"
    path.write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
    with pytest.raises(MeshError):
        load_directory(str(path))


def test_directory_that_is_not_an_object_is_refused():
    for bad in ([], "string", 42, None):
        with pytest.raises(MeshError, match="JSON object"):
            parse_directory(bad)


def test_witnesses_must_be_a_non_empty_list():
    for bad in (None, {}, "", 3, []):
        with pytest.raises(MeshError, match="at least one witness"):
            parse_directory({"version": DIRECTORY_VERSION, "witnesses": bad})


def test_too_many_witnesses_is_refused():
    """A directory is a lead; it is not allowed to make a client fan out forever."""
    entries = [{"url": f"https://w{i}.example"} for i in range(MAX_WITNESSES + 1)]
    with pytest.raises(MeshError, match="more than"):
        parse_directory({"version": DIRECTORY_VERSION, "witnesses": entries})


def test_entry_must_be_an_object():
    with pytest.raises(MeshError, match="must be an object"):
        parse_directory({"version": DIRECTORY_VERSION, "witnesses": ["https://w1.example"]})


def test_url_types_are_enforced():
    for bad in (None, 42, ["https://a"], {"u": "x"}):
        with pytest.raises(MeshError, match="url must be"):
            parse_directory({"version": DIRECTORY_VERSION, "witnesses": [{"url": bad}]})


def test_non_string_metadata_fields_are_refused():
    with pytest.raises(MeshError, match="operator_id must be a string"):
        parse_directory({"version": DIRECTORY_VERSION,
                         "witnesses": [{"url": "https://w1.example", "operator_id": 7}]})


def test_version_must_be_an_int_and_supported():
    for bad in (None, "1", 2, 1.0):
        with pytest.raises(MeshError, match="unsupported directory version"):
            parse_directory({"version": bad, "witnesses": [{"url": "https://w1.example"}]})


def test_directory_source_type_is_checked():
    for bad in (None, 5, [], ""):
        with pytest.raises(MeshError, match="non-empty string"):
            load_directory(bad)


# ------------------------------------------------------------ corroboration


def test_collect_argument_types_are_enforced():
    with pytest.raises(MeshError, match="txid must be a non-empty string"):
        collect(42, ["https://w.example"])
    with pytest.raises(MeshError, match="txid must be a non-empty string"):
        collect("", ["https://w.example"])
    with pytest.raises(MeshError, match="at least one witness"):
        collect("TX", [])
    with pytest.raises(MeshError, match="min_operators"):
        collect("TX", ["https://w.example"], min_operators=0)
    with pytest.raises(MeshError, match="min_operators"):
        collect("TX", ["https://w.example"], min_operators="2")
    with pytest.raises(MeshError, match="timeout"):
        collect("TX", ["https://w.example"], timeout=0)
    with pytest.raises(MeshError, match="timeout"):
        collect("TX", ["https://w.example"], timeout="5")


def test_collect_rejects_non_dict_hints():
    with pytest.raises(MeshError, match="hints"):
        collect("TX", ["https://w.example"], hints=["nope"])


def test_witness_urls_must_be_strings():
    with pytest.raises(MeshError, match="witness URL"):
        collect("TX", [42])


# ------------------------------------------------------------------ service


def test_store_refuses_a_meaningless_size_limit(tmp_path):
    for bad in (0, -1):
        with pytest.raises(MeshError, match="max_proofpack_bytes"):
            Store(tmp_path / "s", max_proofpack_bytes=bad)


def test_server_refuses_a_meaningless_rate_limit(tmp_path):
    store = Store(tmp_path / "s")
    for bad in (0, -5):
        with pytest.raises(MeshError, match="rate_limit"):
            make_server(store, port=0, rate_limit=bad)
    for bad in (0, -1.0):
        with pytest.raises(MeshError, match="rate_window"):
            make_server(store, port=0, rate_window_s=bad)


def test_witness_info_fields_are_validated():
    base = dict(witness_id="w", operator_id="op", chain="c", escrow_txid="e",
                anchor_voters_commitment_b64="A" * 44, anchor_ln_proven_weight=1)
    for field in ("witness_id", "operator_id", "chain", "escrow_txid"):
        broken = dict(base, **{field: ""})
        with pytest.raises(MeshError, match=field):
            WitnessInfo(**broken)


# ---------------------------------------------------------------------- CLI


def _cli(*args):
    import subprocess, sys
    return subprocess.run([sys.executable, "-m", "avm_mesh", *args],
                          capture_output=True, text=True)


def test_cli_verify_on_malformed_json_is_a_clean_failure(tmp_path):
    bad = tmp_path / "receipt.json"
    bad.write_text("{not json", encoding="utf-8")
    proc = _cli("verify", str(bad), "--evidence", str(tmp_path))
    assert proc.returncode in (2, 3)
    assert "Traceback" not in proc.stderr


def test_cli_verify_on_a_receipt_missing_fields_is_a_clean_failure(tmp_path):
    bad = tmp_path / "receipt.json"
    bad.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    proc = _cli("verify", str(bad), "--evidence", str(tmp_path))
    assert proc.returncode in (2, 3)
    assert "Traceback" not in proc.stderr


def test_cli_corroborate_with_a_missing_directory_is_a_clean_failure(tmp_path):
    proc = _cli("corroborate", "--txid", "TX", "--directory", str(tmp_path / "nope.json"))
    assert proc.returncode == 3
    assert "Traceback" not in proc.stderr


def test_cli_serve_with_a_bad_rate_limit_is_a_clean_failure(tmp_path):
    store = tmp_path / "store"
    Store(str(store))
    proc = _cli("serve", "--root", str(store), "--port", "0", "--rate-limit", "0",
                "--max-proofpack-bytes", "1024")
    assert proc.returncode == 3
    assert "Traceback" not in proc.stderr
