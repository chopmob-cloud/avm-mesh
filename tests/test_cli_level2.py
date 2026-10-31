"""LEVEL 2 through the real CLI entry points.

The defect these exist for: the parser accepted `--operator-pubkey-b64`, the docs told
operators it checks LEVEL 2, and `main()` never passed a verifier to `verify_sealed`.
A requested check silently did not run, and the command exited 0.

Every test here drives the entry point, not the helper, because the bug lived in the
gap between them.
"""
import base64
import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

import _assets
from avm_mesh.cli import _make_signature_verifier


def _kat() -> dict:
    path = _assets.require(_assets.falcon_kat(), "Falcon KAT file")
    return json.loads(path.read_text(encoding="utf-8"))["vectors"][0]


def _receipt(tmp_path, *, with_signature: bool) -> pathlib.Path:
    content = json.dumps({"settlement": {"tx_id": "LEVEL2", "chain": "voi"}},
                         sort_keys=True, separators=(",", ":")).encode()
    sealed = {"canonical_bytes_b64": base64.b64encode(content).decode(),
              "content_hash": hashlib.sha256(content).hexdigest(),
              "evidence_uri": "file://proofpack.json"}
    if with_signature:
        kat = _kat()
        sealed["signature"] = {"sig_b64": base64.b64encode(
            bytes.fromhex(kat["signature_hex"])).decode()}
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(sealed), encoding="utf-8")
    return path


def _cli(*args, module="avm_mesh"):
    return subprocess.run([sys.executable, "-m", module, *args],
                          capture_output=True, text=True)


# ---------------------------------------------------------------- conventions

def test_mesh_convention_signs_the_raw_digest(monkeypatch):
    seen = {}
    import avm_proofpack.consensus.falcon as falcon
    monkeypatch.setattr(falcon, "falcon1024_verify",
                        lambda pk, msg, sig: seen.setdefault("message", msg) and True or True)
    verify = _make_signature_verifier(base64.b64encode(b"k").decode())
    verify(b"content", {"sig_b64": base64.b64encode(b"s").decode()})
    assert len(seen["message"]) == 32


def test_rails_convention_signs_the_hex_digest(monkeypatch):
    """The two conventions are not interchangeable; this pins the rails one."""
    seen = {}
    import avm_proofpack.consensus.falcon as falcon
    monkeypatch.setattr(falcon, "falcon1024_verify",
                        lambda pk, msg, sig: seen.setdefault("message", msg) and True or True)
    verify = _make_signature_verifier(base64.b64encode(b"k").decode(), hex_digest=True)
    verify(b"content", {"sig_b64": base64.b64encode(b"s").decode()})
    assert len(seen["message"]) == 64
    bytes.fromhex(seen["message"].decode())      # it is ASCII hex, decodable as such


# ------------------------------------------------------------ fail closed

def test_a_supplied_key_with_no_signature_is_refused(tmp_path):
    """Asking for LEVEL 2 and getting 'present-unverified' with exit 0 is the bug."""
    receipt = _receipt(tmp_path, with_signature=False)
    key = base64.b64encode(bytes.fromhex(_kat()["public_key_hex"])).decode()
    proc = _cli("verify", str(receipt), "--evidence", str(tmp_path),
                "--operator-pubkey-b64", key)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "no signature to check" in proc.stderr


def test_a_malformed_key_is_a_usage_error(tmp_path):
    receipt = _receipt(tmp_path, with_signature=True)
    proc = _cli("verify", str(receipt), "--evidence", str(tmp_path),
                "--operator-pubkey-b64", "!!!not base64!!!")
    assert proc.returncode == 3
    assert "operator-pubkey-b64" in proc.stderr


def test_a_genuine_signature_over_a_different_message_is_rejected(tmp_path):
    """Positive control on the primitive: the key and signature are real.

    They are real, and the signature is over the KAT message -- so verification
    against this receipt must FAIL. If this passes, the check is not running.
    """
    receipt = _receipt(tmp_path, with_signature=True)
    key = base64.b64encode(bytes.fromhex(_kat()["public_key_hex"])).decode()
    proc = _cli("verify", str(receipt), "--evidence", str(tmp_path),
                "--operator-pubkey-b64", key)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "signature does not verify" in (proc.stderr + proc.stdout)


def test_without_a_key_the_signature_is_reported_unverified_and_still_exits_zero(tmp_path):
    """No key requested means no LEVEL 2 claim -- and the output says so."""
    receipt = _receipt(tmp_path, with_signature=True)
    proc = _cli("verify", str(receipt), "--evidence", str(tmp_path), "--json")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["levels"]["signature"] == "present-unverified"


# ------------------------------------------------------------- rails entry

def test_rails_entry_refuses_a_supplied_key_with_no_signature(tmp_path):
    receipt = _receipt(tmp_path, with_signature=False)
    key = base64.b64encode(bytes.fromhex(_kat()["public_key_hex"])).decode()
    proc = _cli("verify", str(receipt), "--evidence", str(tmp_path),
                "--operator-pubkey-b64", key, module="avm_mesh.rails")
    assert proc.returncode == 1, proc.stdout + proc.stderr     # rails code for "not verified"
