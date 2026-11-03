"""Hardening for `_file_resolver` (cli.py) — §6.1 of the external validation.

These tests target a local filesystem resolver, so they are filesystem-only rather
than proofpack-specific. Symlink cases cannot be planted on Windows without
developer mode; they skip there exactly as the symlink tests in test_anchor.py do.
"""
import json
import pathlib

import pytest

from avm_mesh import cli as cli_module


def _resolver(tmp_path, **kwargs):
    root = tmp_path / "evidence"
    root.mkdir()
    return root, cli_module._file_resolver(root, **kwargs)


def test_a_normal_file_resolves_to_its_json(tmp_path):
    root, resolve = _resolver(tmp_path)
    (root / "receipt.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
    assert resolve("receipt.json") == {"ok": True}


def test_a_uri_with_a_directory_prefix_uses_only_the_last_component(tmp_path):
    root, resolve = _resolver(tmp_path)
    (root / "receipt.json").write_text(json.dumps({"ok": 1}), encoding="utf-8")
    assert resolve("proofs/v3/receipt.json") == {"ok": 1}


def test_a_missing_name_raises_file_not_found(tmp_path):
    root, resolve = _resolver(tmp_path)
    with pytest.raises(FileNotFoundError):
        resolve("nothing-here.json")


def test_a_name_outside_the_safe_regex_raises(tmp_path):
    root, resolve = _resolver(tmp_path)
    with pytest.raises(FileNotFoundError):
        resolve("bad name with space.json")
    with pytest.raises(FileNotFoundError):
        resolve("../escape.json")


def test_oversized_file_is_refused(tmp_path):
    root, resolve = _resolver(tmp_path, max_bytes=2)
    (root / "big.json").write_text(json.dumps({"pad": "xx" * 2}), encoding="utf-8")
    with pytest.raises(ValueError, match="over the .* byte cap"):
        resolve("big.json")


def test_invalid_json_is_refused_with_a_useful_message(tmp_path):
    root, resolve = _resolver(tmp_path)
    (root / "broken.json").write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError, match="Expecting"):
        resolve("broken.json")


def test_a_symlinked_entry_inside_the_evidence_root_is_refused(tmp_path):
    root, resolve = _resolver(tmp_path)
    outside = tmp_path / "secret.json"
    outside.write_text(json.dumps({"leaked": True}), encoding="utf-8")
    link = root / "digest.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")
    with pytest.raises(FileNotFoundError):
        resolve("digest.json")


def test_a_dangling_symlink_inside_the_evidence_root_is_refused(tmp_path):
    root, resolve = _resolver(tmp_path)
    link = root / "missing.json"
    try:
        link.symlink_to(tmp_path / "does-not-exist.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")
    with pytest.raises(FileNotFoundError):
        resolve("missing.json")
