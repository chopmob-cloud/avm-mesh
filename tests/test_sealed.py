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


def _content(bundle, amount="1"):
    # The canonical settlement schema the producer writes (see
    # produce.settlement_from_bundle): amount is a base-unit string, asset names
    # the unit. The fixture is a 1-microalgo payment, so the truthful amount is
    # "1"; the binding test below shows any other figure is refused.
    return {
        "settlement": {
            "chain_txid": bundle["transaction"]["txid"],
            "round": bundle["transaction"]["round"],
            "amount": amount,
            "asset": "microalgo",
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
    # The 1-microalgo amount is bound to the authenticated transaction.
    assert out["levels"]["amount"] == "bound"


def test_sealed_receipt_with_a_false_amount_is_refused(bundle, anchor):
    """Verifier-side #1 close: a sealed receipt is honestly integrity- and
    consensus-sound, but states an amount the transaction never moved. verify_sealed
    must refuse it rather than return a stake_attested verdict beside a false figure.

    Guard evidence: remove the verify_settlement_amount() call in verify_sealed()
    and this returns trust_root 'stake_attested' with amount 1,000,000 accepted --
    the defect. Restored, it raises here.
    """
    sealed = seal(_content(bundle, amount="1000000"), bundle, "file://proofpack.json",
                  trusted_voters=anchor)
    with pytest.raises(MeshError, match="does not match the on-chain transfer"):
        verify_sealed(sealed, _resolver(bundle), trusted_voters=anchor,
                      expected_genesis_hash_b64=GENESIS)


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
    # No attestation means no authenticated transaction to bind against, so the
    # amount is reported present-but-unbound rather than silently trusted.
    assert out["levels"]["amount"] == "present-unbound"


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
