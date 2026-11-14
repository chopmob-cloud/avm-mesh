"""AC2 consent binding, proved on REAL bundles for BOTH chains.

Every test here drives the public entry points over the captures checked into
``examples/``:

* Algorand mainnet -- ``examples/proofpack-66457600.json`` (a ``pay``)
* Voi mainnet      -- ``examples/voi-proofpack-24213754.json.gz`` (an ``axfer``)

The fixtures are pinned by SHA-256 so a capture cannot drift underneath a green
run, and the ed25519 keys are generated per test rather than stored, so nothing
here depends on a key that exists only in a repository.

Both chains are exercised for the same reason ``tests/test_voi_chain.py`` exists:
a ``chain="voimain-v1.0"`` argument passed to a helper proves nothing about
whether a genuine Voi receipt binds. These tests read the sender out of each
chain's own authenticated STIB and require the binding to hold there.
"""
import base64
import gzip
import hashlib
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from avm_mesh import MeshError
from avm_mesh import ac2, sealed
from avm_mesh.receipt import _verify_bundle_dict
from avm_proofpack.verify import TrustedVoters

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
ALGORAND_BUNDLE = EXAMPLES / "proofpack-66457600.json"
VOI_BUNDLE = EXAMPLES / "voi-proofpack-24213754.json.gz"

ALGORAND_GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
VOI_GENESIS = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="


def _load(path: pathlib.Path) -> dict:
    if not path.exists():
        pytest.skip(f"fixture absent at {path}")
    raw = path.read_bytes()
    if path.suffix == ".gz":
        text = gzip.decompress(raw).decode("utf-8")
    else:
        text = raw.decode("utf-8")
    return json.loads(text)


def _anchor(bundle: dict) -> TrustedVoters:
    """The anchor an operator supplies: the previous interval's message.

    Identical in shape to the shipped suites. It demonstrates the code path; it
    is not independently derived, and no claim of independence is made here.
    """
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(prev["voters_commitment_b64"]),
                         int(prev["ln_proven_weight"]))


@pytest.fixture(scope="module")
def algorand():
    bundle = _load(ALGORAND_BUNDLE)
    report = _verify_bundle_dict(bundle, _anchor(bundle),
                                 base64.b64decode(ALGORAND_GENESIS))
    assert report.trust_root == "stake_attested", report
    return bundle, report


@pytest.fixture(scope="module")
def voi():
    bundle = _load(VOI_BUNDLE)
    report = _verify_bundle_dict(bundle, _anchor(bundle), base64.b64decode(VOI_GENESIS))
    assert report.trust_root == "stake_attested", report
    return bundle, report


def _settlement_for(report) -> dict:
    return {
        "chain": report.genesis_id,
        "txid": report.txid,
        "round": report.round,
        "amount": "0",
        "asset": 586896,
    }


def _keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk


def _sign(sk, message: bytes) -> str:
    return base64.b64encode(sk.sign(message)).decode()


def _sealed_with_consent(settlement: dict, bundle: dict, uri: str,
                         *, signer=None, sender=None) -> tuple[dict, dict]:
    """Build a real sealed receipt carrying an AC2 consent block.

    Uses the shipped ``sealed.seal`` so the attestation goes into the content
    before hashing, exactly as in production. ``signer`` signs the consent
    payload; ``sender`` overrides the public key recorded in the block so a
    mismatched-key case can be built.
    """
    sk, pk = _keypair()
    signer = signer or sk
    public_key = sender if sender is not None else pk
    consent = ac2.build_consent(
        did="did:key:z6MkTestController",
        sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(public_key).decode(),
        signature_b64=_sign(signer, ac2.consent_payload(settlement)),
        settlement=settlement,
        request_id="ac2-request-1",
        response_id="ac2-response-1",
    )
    # The consent block is placed BEFORE sealing, so it lands inside the bytes
    # that content_hash covers. Placing it after would make it forgeable and the
    # tamper test below would rightly fail.
    content = {"version": 1, "settlement": settlement, "ac2_consent": consent}
    envelope = sealed.seal(content, bundle, uri, trusted_voters=_anchor(bundle))
    return envelope, consent


# --------------------------------------------------------------- both chains

@pytest.mark.parametrize("chain_fixture", ["algorand", "voi"])
def test_the_payer_is_read_from_authenticated_bytes_on_both_chains(chain_fixture, request):
    """The binding input is a fact about the chain, not a field a producer chose.

    An Algorand/Voi address IS the 32-byte Ed25519 public key, so this is also the
    key a verifier must compare a consent against. What this test cannot do is
    sign as that account: the mainnet private keys are not ours to hold, and
    pretending otherwise would be the whole defect this module avoids. The
    positive end-to-end 'the payer approved' path needs a real AC2 wallet
    approving for an account it controls, which is an integration step this
    suite does not have.
    """
    bundle, report = request.getfixturevalue(chain_fixture)
    sender = ac2.sender_from_bundle(bundle, report.genesis_id)

    assert isinstance(sender, bytes) and len(sender) == 32
    # The chain under test is the chain whose genesis we pinned, not just a label
    # passed to a helper.
    expected_chain = {"algorand": "mainnet-v1.0", "voi": "voimain-v1.0"}[chain_fixture]
    assert report.genesis_id == expected_chain
    # The sender is 32 raw bytes: an AVM address, which is also the Ed25519 key.
    assert sender != b"\x00" * 32


def test_sender_binding_positive_path_with_a_key_we_hold(algorand):
    """The pass path, using a keypair this test owns rather than a mainnet account.

    Synthetic by necessity (see the test above), but it exercises the real code:
    the consent key and the sender input are the same key, so the level reaches
    ``sender_bound``. This is what an AC2 wallet would produce for an account
    whose key it holds.
    """
    bundle, report = algorand
    settlement = _settlement_for(report)
    sk, pk = _keypair()

    envelope, _ = _sealed_with_consent(settlement, bundle, "mem://bundle",
                                       signer=sk, sender=pk)
    out = ac2.verify_consent(envelope, expected_sender=pk)
    assert out["level"] == "sender_bound", out
    assert "cannot be swapped" in out["reason"]


def test_consensus_bound_requires_both_halves(algorand):
    """stake_attested + sender_bound together, which is the strongest claim."""
    bundle, report = algorand
    settlement = _settlement_for(report)
    sk, pk = _keypair()

    envelope, _ = _sealed_with_consent(settlement, bundle, "mem://bundle",
                                       signer=sk, sender=pk)
    out = ac2.consent_level(envelope, report, expected_sender=pk)
    assert out["level"] == "consensus_bound", out


@pytest.mark.parametrize("chain_fixture", ["algorand", "voi"])
def test_a_consent_from_a_different_key_is_refused(chain_fixture, request):
    """An approval by someone who did not pay must not pass as sender-bound."""
    bundle, report = request.getfixturevalue(chain_fixture)
    settlement = _settlement_for(report)

    # Sign with a fresh key while recording it honestly in the block: the
    # signature is valid, but it is not the payer.
    envelope, _ = _sealed_with_consent(settlement, bundle, "mem://bundle")
    out = ac2.verify_consent(envelope)
    assert out["level"] == "consent_present"

    sender = ac2.sender_from_bundle(bundle, report.genesis_id)
    with pytest.raises(MeshError) as exc:
        ac2.verify_consent(envelope, expected_sender=sender)
    assert "not the key that authorised this transaction" in str(exc.value)


@pytest.mark.parametrize("chain_fixture", ["algorand", "voi"])
def test_consent_for_one_settlement_cannot_be_replayed_onto_another(chain_fixture, request):
    """The signed payload digest is what stops a consent being lifted."""
    bundle, report = request.getfixturevalue(chain_fixture)
    settlement = _settlement_for(report)
    envelope, consent = _sealed_with_consent(settlement, bundle, "mem://bundle")

    # Same consent block, different settlement (amount changed).
    tampered = dict(settlement)
    tampered["amount"] = "999999999"
    content = {"version": 1, "settlement": tampered, "ac2_consent": consent}
    forged = sealed.seal(content, bundle, "mem://bundle", trusted_voters=_anchor(bundle))

    with pytest.raises(MeshError) as exc:
        ac2.verify_consent(forged)
    assert "different settlement payload" in str(exc.value)


def test_editing_the_consent_breaks_the_content_hash(algorand):
    """The block is inside the hashed bytes, so it cannot be swapped silently."""
    bundle, report = algorand
    settlement = _settlement_for(report)
    envelope, _ = _sealed_with_consent(settlement, bundle, "mem://bundle")

    content = json.loads(base64.b64decode(envelope["canonical_bytes_b64"]))
    content["ac2_consent"]["did"] = "did:key:z6MkAttacker"
    envelope["canonical_bytes_b64"] = base64.b64encode(
        ac2.canonical_bytes(content)).decode()

    with pytest.raises(MeshError) as exc:
        ac2.verify_consent(envelope)
    assert "content hash mismatch" in str(exc.value)


def test_a_bad_signature_is_refused_not_waved_through(algorand):
    bundle, report = algorand
    settlement = _settlement_for(report)
    sk, pk = _keypair()

    consent = ac2.build_consent(
        did="did:key:z6MkTestController",
        sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(b"\x00" * 64).decode(),
        settlement=settlement,
    )
    envelope = sealed.seal({"version": 1, "settlement": settlement, "ac2_consent": consent},
                           bundle, "mem://bundle", trusted_voters=_anchor(bundle))
    with pytest.raises(MeshError) as exc:
        ac2.verify_consent(envelope)
    assert "does not verify" in str(exc.value)


def test_no_consent_is_reported_as_none_and_never_as_a_pass(algorand):
    """Absence must be visible. 'Nothing found' is not 'verified'."""
    bundle, report = algorand
    settlement = _settlement_for(report)
    envelope = sealed.seal({"version": 1, "settlement": settlement},
                           bundle, "mem://bundle", trusted_voters=_anchor(bundle))

    out = ac2.verify_consent(envelope)
    assert out["level"] == "none"
    assert "no ac2_consent" in out["reason"]

    # And a caller that requires one gets a refusal.
    with pytest.raises(MeshError):
        ac2.verify_consent(envelope, require=True)


def test_unknown_consent_version_is_refused_by_name(algorand):
    """Reinterpreting an old artefact under new semantics reopens the hole."""
    data = {
        "version": 99, "did": "did:key:x", "sig_hint": "raw-ed25519",
        "public_key": "AA==", "signature": "AA==",
        "signed_payload_sha256": "0" * 64,
    }
    with pytest.raises(MeshError) as exc:
        ac2.ConsentAttestation.from_dict(data)
    assert "unsupported ac2_consent version 99" in str(exc.value)


def test_canonical_encoder_agrees_with_the_sealed_module():
    """Two 'canonical' encoders drifting apart is how a check starts passing.

    If these ever disagree, ``seal`` hashes one set of bytes while consent
    verification hashes another, and a valid consent would be refused (or worse,
    a mismatched one accepted).
    """
    sample = {"b": [1, 2, {"z": None, "a": "x"}], "a": "\u00e9", "c": True}
    assert ac2.canonical_bytes(sample) == sealed.canonical_bytes(sample)


@pytest.mark.parametrize("path,expected", [
    # SHA-256 of the uncompressed bundle. The Voi value is the same one
    # tests/test_voi_chain.py pins, so the two suites agree on the capture.
    (ALGORAND_BUNDLE, "2f1dfad4286362d5294beacfcc8304233f9f177804852b261b207e2f0e3cdfe9"),
    (VOI_BUNDLE, "5ba9ffb8a97da8ea477a5c22e929bc89af954479ad306b003b09375c84a8fc57"),
])
def test_fixtures_are_the_ones_this_suite_was_written_against(path, expected):
    """Pin the captures by digest so a swapped fixture cannot go unnoticed.

    A test that only asserts ``len(digest) == 64`` proves nothing; it is the
    expected value that constrains the fixture.
    """
    if not path.exists():
        pytest.skip(f"fixture absent at {path}")
    raw = path.read_bytes()
    uncompressed = gzip.decompress(raw) if path.suffix == ".gz" else raw
    assert hashlib.sha256(uncompressed).hexdigest() == expected
