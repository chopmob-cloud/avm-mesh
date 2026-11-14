"""Transaction-bound consent: the signature the wallet already produces.

Why this exists
---------------
The canonical-payload path in :mod:`avm_mesh.ac2` asks a controller to sign
``{"type": "algovoi/settlement-consent/v1", ...}``. AC2's service and SDK permit
that (``agent.request`` is verb-agnostic), but whether the *shipped mobile wallet*
approves a payload it does not recognise as a transaction is a product policy
inside the app — not something the protocol, the SDK or any test here can settle.

This module removes that dependency. It carries the consent over the **transaction
signature the wallet already makes** when it approves a payment
(``sig_hint: "transaction-algorand"``), so nothing new is asked of the wallet.

The preimage, verified rather than assumed
------------------------------------------
An Algorand/Voi address is the Ed25519 public key of its account, and a transaction
signature is Ed25519 over::

    "TX" + canonically-encoded(Transaction)

where the Transaction is the standalone form with the genesis fields restored —
blocks store transactions with ``gen``/``gh`` stripped (``EncodeSignedTxn``), and
the id is computed over the restored form (``DecodeSignedTxn``).

That is not a guess: :func:`signing_preimage` derives it through
``avm_proofpack.avm.transaction_from_stib`` and its digest is asserted equal to the
bundle's own ``txid`` in the tests, on both chains. If the derivation were wrong,
the txid would not match and every test here would fail loudly.

What this buys
--------------
``sender_bound`` by construction: the key that signed IS the account that sent the
transaction, so there is no separate "is the consent key the payer" comparison to
get wrong. And no arbitrary-payload approval is needed from the wallet.

What it does not buy
--------------------
The signature proves *the payer authorised this transaction*. It says nothing about
what the transaction was **for** — a settlement receipt's commercial meaning is an
interpretation, which is why the receipt keeps ``amount`` distinct from the
evidence. So a transaction-bound consent binds consent to a payment, not to an
invoice.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from avm_mesh.receipt import MeshError

#: Marker so a verifier can tell which consent flavour it was handed. Versioned
#: separately from the canonical-payload block: different preimage, different
#: guarantees, and conflating them would let the weaker one be read as the stronger.
TXN_CONSENT_KEY = "ac2_txn_consent"
TXN_CONSENT_VERSION = 1


def signing_preimage(bundle: dict, genesis_id: str) -> bytes:
    """``"TX" + canonical(restored transaction)`` — what an AVM account signs.

    Derived with the proof library's own reconstruction so the genesis fields are
    restored exactly as consensus does; a hand-rolled re-encode of the STIB's txn
    map omits ``gen``/``gh`` and produces a different, wrong digest. That mistake
    was made and caught here: the txid check in the tests is what distinguishes the
    two.
    """
    import avm_proofpack.avm as avm
    import avm_proofpack.mpack as mpack
    from avm_proofpack.bundle import Bundle
    from avm_proofpack.hashes import DOMAIN_TRANSACTION

    try:
        b = Bundle.from_dict(bundle)
    except Exception as exc:
        raise MeshError(f"cannot read evidence to build the signing preimage: {exc}") from exc

    try:
        stib = mpack.decode(b.stib_bytes)
        header = mpack.decode(b.block_header_bytes)
        txn = avm.transaction_from_stib(stib, header)
    except MeshError:
        raise
    except Exception as exc:
        raise MeshError(f"cannot rebuild the signed transaction: {exc}") from exc

    # The chain argument is not decorative: the preimage is identical in SHAPE on
    # both chains, so a caller that passes the wrong genesis would otherwise get
    # a valid-looking preimage for a transaction that is not the one it thinks.
    # Cross-check against the bundle's own declared chain and refuse a mismatch.
    if b.genesis_id != genesis_id:
        raise MeshError(
            f"evidence is for chain {b.genesis_id!r} but the caller asked for "
            f"{genesis_id!r}; refusing to build a signing preimage for the wrong chain"
        )
    return DOMAIN_TRANSACTION + mpack.encode_canonical(txn)


def preimage_digest(bundle: dict, genesis_id: str) -> str:
    """Hex SHA-512/256 of the signing preimage — the transaction id."""
    import avm_proofpack.hashes as hashes

    return hashes.txid_from_bytes(hashes.sha512_256(signing_preimage(bundle, genesis_id)))


def build_txn_consent(*, did: str, public_key_b64: str, signature_b64: str,
                      bundle: dict, genesis_id: str,
                      sig_hint: str = "transaction-algorand",
                      request_id: str | None = None,
                      response_id: str | None = None) -> dict:
    """Assemble ``ac2_txn_consent`` from a wallet's transaction signature.

    ``signature_b64`` is whatever the wallet returned for the payment — the same
    signature that authorises the transaction on chain. ``public_key_b64`` is the
    payer's address/key. The recorded digest pins *which* transaction was approved,
    so the block cannot be lifted onto a different payment.
    """
    return {
        "version": TXN_CONSENT_VERSION,
        "did": did,
        "sig_hint": sig_hint,
        "public_key": public_key_b64,
        "signature": signature_b64,
        "signed_preimage_sha256": hashlib.sha256(
            signing_preimage(bundle, genesis_id)).hexdigest(),
        "txid": preimage_digest(bundle, genesis_id),
        **({"request_id": request_id} if request_id else {}),
        **({"response_id": response_id} if response_id else {}),
    }


def _b64d(value: object, field: str) -> bytes:
    """base64 or base64url, strictly — the same rule as the canonical-payload path."""
    from .ac2 import _b64d as canonical_b64d

    return canonical_b64d(value, field)


def verify_txn_consent(sealed: dict, bundle: dict, genesis_id: str, *,
                       require: bool = False) -> dict:
    """Verify a transaction-bound consent against the bundle it names.

    Returns the same shape as :func:`avm_mesh.ac2.verify_consent` so a caller can
    treat the two interchangeably, but the level it can reach is different and is
    reported as such: this binds consent to a **transaction**, and reaches
    ``sender_bound`` because the signing key is by construction the sender.
    """
    from .ac2 import _open_sealed

    content = _open_sealed(sealed)
    block = content.get(TXN_CONSENT_KEY)

    if block is None:
        if require:
            raise MeshError("sealed receipt carries no ac2_txn_consent block")
        return {"level": "none", "reason": "no ac2_txn_consent block in the sealed content",
                "did": None, "sig_hint": None, "public_key_b64": None}

    if not isinstance(block, dict):
        raise MeshError("ac2_txn_consent must be an object")
    version = block.get("version")
    if version != TXN_CONSENT_VERSION:
        raise MeshError(
            f"unsupported ac2_txn_consent version {version!r}: this verifier "
            f"implements version {TXN_CONSENT_VERSION} only"
        )
    for field in ("did", "sig_hint", "public_key", "signature",
                  "signed_preimage_sha256", "txid"):
        if field not in block:
            raise MeshError(f"ac2_txn_consent missing field {field!r}")

    # The consent must name THIS bundle's transaction, re-derived not trusted.
    actual_txid = preimage_digest(bundle, genesis_id)
    if block["txid"] != actual_txid:
        raise MeshError(
            "the transaction-bound consent names a different transaction: consent "
            f"says {str(block['txid'])[:16]}..., this evidence settles {actual_txid[:16]}..."
        )

    preimage = signing_preimage(bundle, genesis_id)
    actual_digest = hashlib.sha256(preimage).hexdigest()
    if block["signed_preimage_sha256"] != actual_digest:
        raise MeshError(
            "the consent's preimage digest does not match this settlement's signed bytes"
        )

    public_key = _b64d(block["public_key"], "public_key")
    signature = _b64d(block["signature"], "signature")
    if len(public_key) != 32:
        raise MeshError("ac2_txn_consent.public_key is not a 32-byte Ed25519 key")
    if len(signature) != 64:
        raise MeshError("ac2_txn_consent.signature is not a 64-byte Ed25519 signature")

    from .ac2 import _ed25519_verify

    if not _ed25519_verify(public_key, preimage, signature):
        raise MeshError(
            "the transaction signature does not verify over this settlement's "
            "signing preimage"
        )

    return {
        "level": "sender_bound",
        "reason": (
            "the payer's transaction signature verifies over this settlement's "
            "signed bytes, so consent is bound to the payment by construction: the "
            "signing key IS the sending account. This proves the payer authorised "
            "this transaction; it does not establish what the payment was for, and "
            "it still says nothing about whether a hardware passkey was used."
        ),
        "did": block["did"],
        "sig_hint": block["sig_hint"],
        "public_key_b64": block["public_key"],
        "txid": actual_txid,
    }
