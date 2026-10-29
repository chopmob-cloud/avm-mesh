"""Sealed receipt tests: wire format, binding, and the offline CLI."""
import base64
import copy
import gzip
import json
import os
import pathlib
import subprocess
import sys

import pytest

from avm_mesh import MeshError, seal, verify_sealed
from avm_mesh.cli import main as cli_main

DEFAULT_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "avm-proofpack" / "tests" / "fixtures"
    / "stake_attested_algorand_66457600.json.gz"
)
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="


def _resolver(b):
    return lambda uri: copy.deepcopy(b)


def _content(bundle):
    return {
        "settlement": {
            "chain": "mainnet-v1.0",
            "txid": bundle["transaction"]["txid"],
            "round": bundle["transaction"]["round"],
            "amount_microalgo": 1,
        },
        "issuer": "AlgoVoi",
    }


def test_seal_puts_the_attestation_inside_the_hashed_bytes(bundle, anchor):
    sealed = seal(_content(bundle), bundle, "file://proofpack.json", trusted_voters=anchor)
    cb = base64.b64decode(sealed["canonical_bytes_b64"])
    raw = json.loads(cb)
    assert "consensus_attestation" in raw
    assert sealed["content_hash"] == __import__("hashlib").sha256(cb).hexdigest()


def test_sealed_receipt_verifies_end_to_end(bundle, anchor):
    sealed = seal(_content(bundle), bundle, "file://proofpack.json", trusted_voters=anchor)
    out = verify_sealed(sealed, _resolver(bundle), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS)
    assert out["trust_root"] == "stake_attested"
    assert out["levels"]["integrity"] is True
    assert out["levels"]["consensus"] == "stake_attested"


def test_tampering_the_attestation_breaks_integrity(bundle, anchor):
    """LEVEL 3 is inside the hashed bytes: editing it must fail LEVEL 1."""
    sealed = seal(_content(bundle), bundle, "file://proofpack.json", trusted_voters=anchor)
    raw = json.loads(base64.b64decode(sealed["canonical_bytes_b64"]))
    raw["consensus_attestation"]["txid"] = "A" * 52
    tampered = dict(sealed)
    tampered["canonical_bytes_b64"] = base64.b64encode(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    with pytest.raises(MeshError, match="content hash mismatch"):
        verify_sealed(tampered, _resolver(bundle), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS)


def test_swapping_evidence_behind_the_pointer_is_refused(bundle, anchor):
    sealed = seal(_content(bundle), bundle, "file://proofpack.json", trusted_voters=anchor)
    other = copy.deepcopy(bundle)
    other["state_proof_message"]["ln_proven_weight"] += 1
    with pytest.raises(MeshError, match="evidence digest mismatch"):
        verify_sealed(sealed, _resolver(other), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS)


def test_receipt_without_attestation_is_structural_not_attested(bundle, anchor):
    content = _content(bundle)
    cb = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    sealed = {
        "version": 1,
        "canonical_bytes_b64": base64.b64encode(cb).decode(),
        "content_hash": __import__("hashlib").sha256(cb).hexdigest(),
    }
    out = verify_sealed(sealed, _resolver(bundle), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS)
    assert out["trust_root"] == "structural"
    assert out["levels"]["consensus"] == "absent"


def test_seal_refuses_double_attestation(bundle, anchor):
    content = _content(bundle)
    content["consensus_attestation"] = {"scheme": "x"}
    with pytest.raises(MeshError, match="already carries"):
        seal(content, bundle, "file://proofpack.json", trusted_voters=anchor)


def test_optional_operator_signature_is_checked_when_supplied(bundle, anchor):
    sealed = seal(_content(bundle), bundle, "file://proofpack.json", trusted_voters=anchor,
                  sign=lambda digest: {"sig_b64": "AAAA", "algorithm": "falcon-1024"})
    out = verify_sealed(sealed, _resolver(bundle), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS,
                        verify_signature=lambda cb, sig: True)
    assert out["levels"]["signature"] is True

    with pytest.raises(MeshError, match="signature does not verify"):
        verify_sealed(sealed, _resolver(bundle), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS,
                      verify_signature=lambda cb, sig: False)


def test_cli_verifies_offline_with_sockets_blocked(bundle, anchor, tmp_path, monkeypatch):
    """The whole point: no network, from a file, with a pinned genesis."""
    evidence = tmp_path / "proofpack.json"
    evidence.write_text(json.dumps(bundle), encoding="utf-8")
    sealed = seal(_content(bundle), bundle, "file://proofpack.json", trusted_voters=anchor)
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(sealed), encoding="utf-8")

    import socket

    class Blocked(socket.socket):
        def __init__(self, *a, **k):
            raise OSError("NETWORK DISABLED")

    monkeypatch.setattr(socket, "socket", Blocked)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("NETWORK DISABLED")))

    import base64 as _b64

    rc = cli_main(["verify", str(receipt), "--evidence", str(tmp_path), "--genesis", GENESIS,
                   "--voters-commitment", _b64.b64encode(anchor.voters_commitment).decode(),
                   "--ln-proven-weight", str(anchor.ln_proven_weight)])
    assert rc == 0


def test_cli_fails_closed_on_bad_receipt(tmp_path, capsys):
    bad = tmp_path / "receipt.json"
    bad.write_text(json.dumps({"version": 1, "canonical_bytes_b64": "!!!",
                               "content_hash": "00"}), encoding="utf-8")
    assert cli_main(["verify", str(bad)]) == 2
    assert "FAILED" in capsys.readouterr().err
