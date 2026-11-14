"""Interop with the real AC2 stack: base64url encoding and JCS canonicalisation.

Every other test in this suite encodes with Python's standard base64 and decodes
with the same alphabet, so it cannot see an alphabet mismatch. AC2's reference
implementation emits **base64url** (Node's `.toString('base64url')`), and a
`b64decode(..., validate=True)` rejects `-` and `_`. That defect was live until
this file existed: a genuine AC2 signature was refused as "not valid base64".

The fixtures are produced by `tests/interop/interop_emit.mjs`, which uses the real
AC2 SDK's conventions and Node's JCS encoder -- the same one the reference
implementation uses. Regenerate with::

    node tests/interop/interop_emit.mjs tests/interop/ac2_interop.json

If node is unavailable the test skips with a message saying so; it does not pass
vacuously, because a skip here would hide exactly the seam it guards.
"""
import base64
import gzip
import json
import pathlib
import shutil
import subprocess

import pytest

from avm_mesh.ac2 import consent_digest, verify_consent
from avm_mesh import MeshError, sealed
from avm_proofpack.verify import TrustedVoters

HERE = pathlib.Path(__file__).resolve().parent
INTEROP_DIR = HERE / "interop"
FIXTURE = INTEROP_DIR / "ac2_interop.json"
EMITTER = INTEROP_DIR / "interop_emit.mjs"
# avm-mesh already ships this capture in examples/; do not duplicate it here.
VOI_CAPTURE = HERE.parents[0] / "examples" / "voi-proofpack-24213754.json.gz"


def _bundle():
    return json.load(gzip.open(VOI_CAPTURE, "rt"))


def _anchor():
    prev = _bundle()["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(prev["voters_commitment_b64"]),
                         int(prev["ln_proven_weight"]))


def _seal(settlement, consent):
    return sealed.seal({"version": 1, "settlement": settlement,
                        "ac2_consent": consent},
                       _bundle(), "mem://interop", trusted_voters=_anchor())


def _fixture() -> dict:
    """The committed interop fixture, regenerated if it is missing and node exists."""
    if not FIXTURE.exists():
        if shutil.which("node") is None:
            pytest.skip("no committed interop fixture and node is unavailable")
        subprocess.run(["node", str(EMITTER), str(FIXTURE)], check=True,
                       capture_output=True)
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_the_fixture_exercises_the_url_alphabet():
    """The guard is only meaningful if the bytes actually contain - or _.

    A base64url string can happen to contain neither character, in which case this
    whole file would pass against a broken decoder. Assert the case is present.
    """
    data = _fixture()
    blobs = [data["consent"]["signature"], data["consent"]["public_key"]]
    assert any(("-" in b) or ("_" in b) for b in blobs), (
        "the interop fixture contains no base64url-only characters, so it cannot "
        "distinguish the url alphabet from the standard one"
    )


def test_a_real_ac2_base64url_consent_verifies():
    """The end-to-end seam: bytes emitted by the AC2 stack, verified here."""
    data = _fixture()
    envelope = _seal(data["settlement"], data["consent"])
    out = verify_consent(envelope)
    assert out["level"] == "consent_present", out
    assert out["sig_hint"] == "raw-ed25519"


def test_node_and_python_agree_on_the_canonical_payload():
    """JCS: an independent implementation must produce the same digest.

    The reference implementation canonicalises with its own JCS encoder. If the two
    drift, a signature made on one side is refused on the other -- and a
    same-language round trip would never show it.
    """
    data = _fixture()
    assert consent_digest(data["settlement"]) == data["consent"]["signed_payload_sha256"]
    # And the bytes themselves, not just the digest.
    import avm_mesh.ac2 as _ac2
    assert _ac2.consent_payload(data["settlement"]).decode("utf-8") == data["payload_utf8"]


def test_standard_base64_still_works():
    """Widening the decoder must not break the alphabet the existing tests use."""
    data = _fixture()
    consent = dict(data["consent"])
    sig = base64.b64decode(consent["signature"].replace("-", "+").replace("_", "/")
                           + "=" * (-len(consent["signature"]) % 4))
    pk = base64.b64decode(consent["public_key"].replace("-", "+").replace("_", "/")
                          + "=" * (-len(consent["public_key"]) % 4))
    consent["signature"] = base64.b64encode(sig).decode()
    consent["public_key"] = base64.b64encode(pk).decode()
    out = verify_consent(_seal(data["settlement"], consent))
    assert out["level"] == "consent_present"


@pytest.mark.parametrize("field", ["signature", "public_key"])
def test_a_tampered_url_signature_is_still_refused(field):
    """Accepting base64url must not mean accepting anything."""
    data = _fixture()
    consent = dict(data["consent"])
    # Flip one character to another valid one in the same alphabet.
    blob = consent[field]
    swapped = ("B" if blob[0] != "B" else "C") + blob[1:]
    consent[field] = swapped
    with pytest.raises(MeshError):
        verify_consent(_seal(data["settlement"], consent))


def test_characters_outside_both_alphabets_are_refused():
    """A permissive decoder is as dangerous as a too-strict one."""
    data = _fixture()
    consent = dict(data["consent"])
    consent["signature"] = consent["signature"][:8] + "!!" + consent["signature"][8:]
    with pytest.raises(MeshError) as exc:
        verify_consent(_seal(data["settlement"], consent))
    assert "outside base64/base64url" in str(exc.value)
