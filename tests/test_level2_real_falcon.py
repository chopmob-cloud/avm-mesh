"""LEVEL 2: the Falcon-1024 primitive, and the verifier plumbing.

The review request listed "LEVEL 2 has never seen a real key" as my second
largest doubt. The honest resolution has three parts, and the third is a
limitation rather than a result:

  1. The PRIMITIVE is proven against genuine KAT vectors -- real public keys and
     real signatures from the reference implementation. Not stubs.
  2. The PLUMBING is proven by substitution: the underlying verifier is replaced
     with a recorder, so the test fails if the code stops hashing what it claims
     to hash, or stops checking the returned bool.
  3. UNPROVEN, and recorded as such: an operator key signing a real receipt end
     to end. No Falcon-1024 *signer* is installable in this environment --
     pqcrypto 1.0.0 dropped Falcon entirely and no 0.9.x build exists for this
     platform -- so it cannot be closed here without inventing a signature.
     An operator signing with their own toolchain is the only honest way to
     close it, and that belongs in their acceptance test.

Also pinned: pqcrypto 1.0.0 no longer ships Falcon (its sign subpackage lists
ML-KEM, ML-DSA, SLH-DSA, McEliece, HQC and SNTRUP), so LEVEL 2 must not depend
on it. That is a live break for any verifier still importing
``pqcrypto.sign.falcon_1024`` -- including the AlgoVoi rails bundle's
``verify_settlement_receipt.py``.
"""
import base64
import hashlib
import json
import pathlib

import pytest

import _assets

from avm_mesh.cli import _make_signature_verifier

KAT = (
    _assets.falcon_kat()
)


@pytest.fixture(scope="module")
def kat_vectors():
    _assets.require(KAT, "Falcon KAT file")
    data = json.loads(KAT.read_text(encoding="utf-8"))
    return [
        (
            bytes.fromhex(v["public_key_hex"]),
            bytes.fromhex(v["message_hex"]),
            bytes.fromhex(v["signature_hex"]),
        )
        for v in data["vectors"]
    ]


# --- 1. the primitive, on genuine keys -------------------------------------

def test_real_kat_signature_verifies(kat_vectors):
    from avm_proofpack.consensus.falcon import falcon1024_verify

    assert kat_vectors, "KAT file contained no vectors"
    for pubkey, message, signature in kat_vectors:
        assert falcon1024_verify(pubkey, message, signature) is True


def test_real_kat_signature_rejected_when_message_changes(kat_vectors):
    from avm_proofpack.consensus.falcon import falcon1024_verify

    pubkey, message, signature = kat_vectors[0]
    tampered = (message + b"\x00") if message else b"\x01"
    assert falcon1024_verify(pubkey, tampered, signature) is False


def test_real_kat_signature_rejected_under_a_different_key(kat_vectors):
    from avm_proofpack.consensus.falcon import falcon1024_verify

    if len(kat_vectors) < 2:
        pytest.skip("need two vectors to cross keys")
    (pk_a, msg_a, sig_a), (pk_b, _m, _s) = kat_vectors[0], kat_vectors[1]
    assert pk_a != pk_b
    assert falcon1024_verify(pk_b, msg_a, sig_a) is False


# --- 2. the plumbing, by substitution -------------------------------------

def test_verifier_hashes_the_content_it_is_given(monkeypatch):
    """If the code stopped hashing -- or hashed something else -- this fails."""
    import avm_proofpack.consensus.falcon as falcon

    seen = {}

    def recorder(pubkey, message, signature):
        seen["message"] = message
        return True

    monkeypatch.setattr(falcon, "falcon1024_verify", recorder)
    verifier = _make_signature_verifier(base64.b64encode(bytes(range(32))).decode())

    content = b'{"settlement":{"amount":"1"}}'
    assert verifier(content, {"sig_b64": base64.b64encode(b"sig").decode()}) is True
    assert seen["message"] == hashlib.sha256(content).digest()


def test_verifier_returns_false_when_the_primitive_says_no(monkeypatch):
    """The returned bool must be checked: a truthy object would read as a pass."""
    import avm_proofpack.consensus.falcon as falcon

    monkeypatch.setattr(falcon, "falcon1024_verify", lambda *a, **k: False)
    verifier = _make_signature_verifier(base64.b64encode(bytes(32)).decode())
    assert verifier(b"content", {"sig_b64": base64.b64encode(b"s").decode()}) is False


def test_verifier_rejects_a_signature_object_without_sig():
    verifier = _make_signature_verifier(base64.b64encode(bytes(32)).decode())
    with pytest.raises(ValueError, match="no sig_b64"):
        verifier(b"content", {"wrong": "shape"})


def test_verifier_rejects_a_non_base64_key():
    with pytest.raises(ValueError, match="not valid base64"):
        _make_signature_verifier("!!!not base64!!!")


# --- 3. the dependency decision -------------------------------------------

def test_no_module_imports_pqcrypto():
    """pqcrypto 1.0.0 dropped Falcon; any import of it is a latent break.

    Scans every module, not just cli: a future caller reaching for
    ``pqcrypto.sign.falcon_1024`` would fail on import for anyone who installed
    pqcrypto today. See docs/PQC-FALCON.md.
    """
    import avm_mesh

    pkg = pathlib.Path(avm_mesh.__file__).parent
    offenders = []
    for path in sorted(pkg.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        if "import pqcrypto" in source or "from pqcrypto" in source:
            offenders.append(path.name)
    assert not offenders, f"modules importing the broken dependency: {offenders}"


def test_the_pqc_decision_is_documented():
    """The reasoning must live in the repo, not in a chat log."""
    doc = pkg_docs = pathlib.Path(__file__).resolve().parents[1] / "docs" / "PQC-FALCON.md"
    assert doc.exists(), "docs/PQC-FALCON.md is missing"
    text = doc.read_text(encoding="utf-8")
    for required in ("PQClean", "FN-DSA", "avm_proofpack.consensus.falcon", "unaudited"):
        assert required in text, f"PQC note no longer covers {required!r}"
