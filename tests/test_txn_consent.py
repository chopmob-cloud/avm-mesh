"""Transaction-bound consent, proved against the bundle's OWN txid on both chains.

The load-bearing assertion in this file is that
:func:`avm_mesh.txn_consent.preimage_digest` reproduces the transaction id the
bundle itself carries. That is not decoration: the first version of this module
re-encoded the STIB's ``txn`` map directly, which omits the genesis fields that
consensus strips when *encoding* and restores when *decoding*. It produced a
plausible 52-character base32 string that was simply the wrong transaction. The
txid equality is what distinguishes a correct preimage from a convincing one, so it
is asserted first and on both chains.
"""
import base64
import gzip
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from avm_mesh import (
    TXN_CONSENT_KEY,
    build_txn_consent,
    preimage_digest,
    signing_preimage,
    verify_txn_consent,
)
from avm_mesh import MeshError, sealed
from avm_proofpack.verify import TrustedVoters

HERE = pathlib.Path(__file__).resolve().parent
CAPTURES = HERE.parent / "examples"

ALGORAND_GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
VOI_GENESIS = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="

CHAINS = [
    ("algorand", "proofpack-66457600.json", ALGORAND_GENESIS, "mainnet-v1.0"),
    ("voi", "voi-proofpack-24213754.json.gz", VOI_GENESIS, "voimain-v1.0"),
]


def _bundle(name: str) -> dict:
    path = CAPTURES / name
    if not path.exists():
        pytest.skip(f"capture absent at {path}")
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw).decode() if name.endswith(".gz")
                      else raw.decode())


def _anchor(bundle: dict) -> TrustedVoters:
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(prev["voters_commitment_b64"]),
                         int(prev["ln_proven_weight"]))


# ---------------------------------------------------------------- the preimage

@pytest.mark.parametrize("label,name,genesis,_chain", CHAINS)
def test_the_preimage_reproduces_the_bundles_own_txid(label, name, genesis, _chain):
    """The one assertion that makes every other test here meaningful.

    A wrong preimage still signs and still verifies against itself; only checking
    it against the transaction id the chain committed to tells them apart.
    """
    bundle = _bundle(name)
    assert preimage_digest(bundle, _chain) == bundle["transaction"]["txid"]


@pytest.mark.parametrize("label,name,genesis,chain", CHAINS)
def test_the_preimage_starts_with_the_transaction_domain(label, name, genesis, chain):
    """``"TX"`` is the domain separator Algorand signs with, not an implementation detail."""
    preimage = signing_preimage(_bundle(name), chain)
    assert preimage[:2] == b"TX"
    assert len(preimage) > 2


def test_a_wrong_chain_is_refused_not_silently_wrong():
    """Deriving for the wrong chain must fail loudly, never return a plausible id."""
    bundle = _bundle("voi-proofpack-24213754.json.gz")
    with pytest.raises(MeshError):
        signing_preimage(bundle, "voimain-v1.0WRONG")


# ------------------------------------------------------------- round trip

def _seal_txn_consent(bundle, chain, *, sk=None, pk=None):
    """Build a transaction-bound consent signed by a keypair we control.

    The real payer's private key is not ours; what this proves is the machinery
    around the signature. The preimage itself is the chain's, verified above.
    """
    sk = sk or Ed25519PrivateKey.generate()
    pk = pk or sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    preimage = signing_preimage(bundle, chain)
    block = build_txn_consent(
        did="did:key:z6MkTxnController",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(preimage)).decode(),
        bundle=bundle, genesis_id=chain,
        request_id="ac2-txn-request",
    )
    envelope = sealed.seal(
        {"version": 1,
         "settlement": {"chain": chain, "txid": bundle["transaction"]["txid"],
                        "round": bundle["transaction"]["round"],
                        "amount": "0", "asset": 586896},
         TXN_CONSENT_KEY: block},
        bundle, "mem://txn", trusted_voters=_anchor(bundle))
    return envelope, block, pk


@pytest.mark.parametrize("label,name,genesis,chain", CHAINS)
def test_a_transaction_signature_binds_consent_on_both_chains(label, name, genesis, chain):
    envelope, _block, pk = _seal_txn_consent(_bundle(name), chain)
    out = verify_txn_consent(envelope, _bundle(name), chain)
    assert out["level"] == "sender_bound", out
    assert out["txid"] == _bundle(name)["transaction"]["txid"]
    assert out["public_key_b64"] == base64.b64encode(pk).decode()


@pytest.mark.parametrize("label,name,genesis,chain", CHAINS)
def test_a_consent_naming_another_transaction_is_refused(label, name, genesis, chain):
    """Consent is pinned to the transaction it was produced for."""
    bundle = _bundle(name)
    envelope, block, _pk = _seal_txn_consent(bundle, chain)

    other = dict(block)
    other["txid"] = "A" * 52
    forged = sealed.seal({"version": 1, "settlement": {"amount": "0"},
                          TXN_CONSENT_KEY: other},
                         bundle, "mem://txn", trusted_voters=_anchor(bundle))
    with pytest.raises(MeshError) as exc:
        verify_txn_consent(forged, bundle, chain)
    assert "different transaction" in str(exc.value)


def test_a_signature_over_the_wrong_bytes_is_refused():
    """A well-formed 64-byte signature that is not over this preimage must fail."""
    bundle = _bundle("voi-proofpack-24213754.json.gz")
    chain = "voimain-v1.0"
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    block = build_txn_consent(
        did="did:key:z6MkX", public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(b"not the preimage")).decode(),
        bundle=bundle, genesis_id=chain)
    envelope = sealed.seal({"version": 1, "settlement": {"amount": "0"},
                            TXN_CONSENT_KEY: block},
                           bundle, "mem://txn", trusted_voters=_anchor(bundle))
    with pytest.raises(MeshError) as exc:
        verify_txn_consent(envelope, bundle, chain)
    assert "does not verify" in str(exc.value)


def test_absent_txn_consent_is_none_and_never_a_pass():
    bundle = _bundle("proofpack-66457600.json")
    chain = "mainnet-v1.0"
    envelope = sealed.seal({"version": 1, "settlement": {"amount": "0"}},
                           bundle, "mem://txn", trusted_voters=_anchor(bundle))
    assert verify_txn_consent(envelope, bundle, chain)["level"] == "none"
    with pytest.raises(MeshError):
        verify_txn_consent(envelope, bundle, chain, require=True)


def test_unknown_version_is_refused_by_name():
    bundle = _bundle("proofpack-66457600.json")
    chain = "mainnet-v1.0"
    envelope = sealed.seal({"version": 1, "settlement": {"amount": "0"},
                            TXN_CONSENT_KEY: {"version": 99}},
                           bundle, "mem://txn", trusted_voters=_anchor(bundle))
    with pytest.raises(MeshError) as exc:
        verify_txn_consent(envelope, bundle, chain)
    assert "unsupported ac2_txn_consent version 99" in str(exc.value)


def test_editing_the_block_breaks_the_content_hash():
    from avm_mesh.sealed import canonical_bytes

    bundle = _bundle("voi-proofpack-24213754.json.gz")
    chain = "voimain-v1.0"
    envelope, _block, _pk = _seal_txn_consent(bundle, chain)
    content = json.loads(base64.b64decode(envelope["canonical_bytes_b64"]))
    content[TXN_CONSENT_KEY]["did"] = "did:key:z6MkAttacker"
    envelope["canonical_bytes_b64"] = base64.b64encode(canonical_bytes(content)).decode()
    with pytest.raises(MeshError) as exc:
        verify_txn_consent(envelope, bundle, chain)
    assert "content hash mismatch" in str(exc.value)


def test_the_preimage_carries_gen_and_a_gen_less_form_is_a_different_transaction():
    """``gen`` is load-bearing, measured rather than assumed.

    ``bytesForSigning.transaction`` in algokit-utils omits ``gen`` (the genesis id
    string) while keeping ``gh`` (the hash), because the constructor path relies on
    the node to fill it back in. A payload built that way is NOT the transaction the
    chain committed to: dropping ``gen`` from a real Voi preimage changes the txid.
    That is the same defect class as re-encoding the STIB's ``txn`` map, so it is
    pinned here instead of left as a comment.
    """
    import hashlib

    from avm_proofpack import mpack

    bundle = _bundle("voi-proofpack-24213754.json.gz")
    preimage = signing_preimage(bundle, "voimain-v1.0")
    assert preimage[:2] == b"TX"

    body = mpack.decode(preimage[2:])
    assert "gen" in body, "the real preimage must carry the genesis id string"

    def txid(raw: bytes) -> str:
        digest = hashlib.new("sha512_256")
        digest.update(raw)
        return base64.b32encode(digest.digest()).decode().rstrip("=")

    assert txid(preimage) == bundle["transaction"]["txid"]

    without_gen = b"TX" + mpack.encode_canonical(
        {k: v for k, v in body.items() if k != "gen"})
    assert txid(without_gen) != bundle["transaction"]["txid"], (
        "if dropping gen still reproduced the txid, gen would be optional and this "
        "test's premise would be wrong"
    )
