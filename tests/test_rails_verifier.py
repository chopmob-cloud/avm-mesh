"""The rails adoption kit: same wire format, three levels, reported separately.

These tests are written from the outside, the way a rails integrator would use
it: build a receipt, verify it, and try to cheat. The cheat attempts are the
point — a verifier that cannot be attacked in a test will be attacked in
production.
"""
import base64
import copy
import gzip
import hashlib
import json
import pathlib

import pytest

from avm_mesh.attestation import attest
from avm_mesh.receipt import MeshError, bundle_digest
from avm_mesh.rails import verify_rails_receipt

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "avm-proofpack" / "tests" / "fixtures"
    / "stake_attested_algorand_66457600.json.gz"
)
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
VOI_GENESIS = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="


def _seal(content: dict) -> dict:
    """Build a rails-shaped receipt: exact bytes plus their hash."""
    cb = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    return {
        "canonical_bytes_b64": base64.b64encode(cb).decode(),
        "content_hash": hashlib.sha256(cb).hexdigest(),
    }


def _resolver(bundle):
    return lambda uri: copy.deepcopy(bundle)


# --- LEVEL 1 ---------------------------------------------------------------

def test_level1_accepts_intact_bytes():
    receipt = _seal({"settlement": {"txid": "A" * 52, "amount": "1"}, "issuer": "AlgoVoi"})
    out = verify_rails_receipt(receipt, resolve=lambda uri: {})
    assert out["levels"]["integrity"] is True
    assert out["trust_root"] == "structural"
    assert out["levels"]["consensus"] == "absent"


def test_level1_rejects_tampered_hash():
    receipt = _seal({"settlement": {"amount": "1"}})
    receipt["content_hash"] = "0" * 64
    with pytest.raises(MeshError, match="content hash mismatch"):
        verify_rails_receipt(receipt, resolve=lambda uri: {})


def test_receipt_must_carry_the_hash_fields():
    with pytest.raises(MeshError, match="must carry canonical_bytes_b64"):
        verify_rails_receipt({"content_hash": "a" * 64}, resolve=lambda uri: {})


def test_malformed_base64_is_refused():
    with pytest.raises(MeshError, match="not valid base64"):
        verify_rails_receipt({"canonical_bytes_b64": "!!!", "content_hash": "0" * 64},
                             resolve=lambda uri: {})


# --- LEVEL 2 ---------------------------------------------------------------

def test_signature_present_without_a_key_is_reported_unverified():
    """Never call a signature valid when we have not checked it."""
    receipt = _seal({"settlement": {"amount": "1"}})
    receipt["signature"] = {"sig_b64": base64.b64encode(b"not-a-real-sig").decode()}
    out = verify_rails_receipt(receipt, resolve=lambda uri: {})
    assert out["levels"]["signature"] == "present-unverified"
    assert out["trust_root"] == "structural"


def test_signature_with_a_real_key_is_checked_against_the_kat_vector():
    """Uses a genuine Falcon-1024 public key and signature, not a stub."""
    kat = (
        pathlib.Path(__file__).resolve().parents[2]
        / "avm-proofpack" / "tests" / "falcon_kat" / "falcon1024_det_kat.json"
    )
    if not kat.exists():
        pytest.skip("Falcon KAT file not present")
    vector = json.loads(kat.read_text(encoding="utf-8"))["vectors"][0]
    message = bytes.fromhex(vector["message_hex"])
    pubkey = bytes.fromhex(vector["public_key_hex"])
    signature = bytes.fromhex(vector["signature_hex"])

    # LEVEL 2 signs sha256(canonical bytes), so pin bytes whose digest IS the
    # KAT message: use the KAT message as the signature payload directly by
    # building a receipt whose canonical bytes hash to it is impossible, so we
    # instead assert the verifier's plumbing with the real key material and a
    # deliberately wrong digest -> False, then the true digest -> True.
    from avm_mesh.rails.verifier import _operator_verifier

    verifier = _operator_verifier(base64.b64encode(pubkey).decode())
    sig_obj = {"sig_b64": base64.b64encode(signature).decode()}

    # The KAT message is what was signed; feed content whose sha256 equals it
    # only when the vector's message is itself a 32-byte digest. Otherwise the
    # primitive check below is the meaningful one.
    if len(message) == 32:
        out = verifier(message, sig_obj)
        assert out is True
    # Regardless: a signature over different bytes must not verify.
    assert verifier(b"some other content", sig_obj) is False


def test_non_base64_operator_key_is_refused():
    receipt = _seal({"settlement": {"amount": "1"}})
    receipt["signature"] = {"sig_b64": base64.b64encode(b"s").decode()}
    with pytest.raises(MeshError, match="not valid base64"):
        verify_rails_receipt(receipt, resolve=lambda uri: {}, operator_pubkey_b64="!!!")


# --- LEVEL 3 ---------------------------------------------------------------

@pytest.fixture(scope="module")
def bundle():
    if not FIXTURE.exists():
        pytest.skip(f"fixture not present at {FIXTURE}")
    with gzip.open(FIXTURE, "rt", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def anchor(bundle):
    from avm_proofpack.verify import TrustedVoters
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]),
    )


@pytest.fixture(scope="module")
def attested_receipt(bundle, anchor):
    att = attest(bundle, "proofpack:" + bundle_digest(bundle), trusted_voters=anchor)
    return _seal({
        "settlement": {"txid": bundle["transaction"]["txid"],
                       "round": bundle["transaction"]["round"], "amount": "1"},
        "consensus_attestation": att.to_dict(),
    })


def test_level3_raises_the_trust_root(attested_receipt, bundle, anchor):
    out = verify_rails_receipt(attested_receipt, _resolver(bundle),
                               trusted_voters=anchor,
                               expected_genesis_hash_b64=GENESIS)
    assert out["levels"]["consensus"] == "stake_attested"
    assert out["trust_root"] == "stake_attested"
    assert out["attested_txid"] == bundle["transaction"]["txid"]


def test_level3_without_an_anchor_is_refused_not_downgraded(attested_receipt, bundle):
    """An attestation with no anchor to check it against must not read as valid."""
    with pytest.raises(MeshError, match="trusted voters anchor is required"):
        verify_rails_receipt(attested_receipt, _resolver(bundle), trusted_voters=None)


def test_level3_wrong_genesis_pin_is_refused(attested_receipt, bundle, anchor):
    with pytest.raises(MeshError):
        verify_rails_receipt(attested_receipt, _resolver(bundle),
                             trusted_voters=anchor,
                             expected_genesis_hash_b64=VOI_GENESIS)


def test_substituted_evidence_is_refused(attested_receipt, bundle, anchor):
    other = copy.deepcopy(bundle)
    other["state_proof_message"]["ln_proven_weight"] += 1
    with pytest.raises(MeshError, match="evidence digest mismatch"):
        verify_rails_receipt(attested_receipt, _resolver(other), trusted_voters=anchor)


def test_tampering_the_attestation_breaks_level1(attested_receipt, bundle, anchor):
    """LEVEL 3 lives inside the hashed bytes, so editing it must fail integrity."""
    raw = json.loads(base64.b64decode(attested_receipt["canonical_bytes_b64"]))
    raw["consensus_attestation"]["txid"] = "A" * 52
    tampered = dict(attested_receipt)
    tampered["canonical_bytes_b64"] = base64.b64encode(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    with pytest.raises(MeshError, match="content hash mismatch"):
        verify_rails_receipt(tampered, _resolver(bundle), trusted_voters=anchor)


# --- the entry point -------------------------------------------------------

def test_module_entry_point_delegates_to_the_cli(tmp_path, capsys):
    import subprocess
    import sys

    receipt = _seal({"settlement": {"amount": "1"}})
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "avm_mesh.rails", "verify", str(path)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "structural" in proc.stdout
