"""Producer path: from a captured bundle to a receipt a merchant can verify.

This is the settler's side. It ties the three pieces together:

    capture (avm-proofpack) -> validate everything -> persist evidence -> receipt

The ordering is deliberate. The content address is derived from the bundle up
front, so the receipt commits to it, and EVERYTHING is validated -- tier, digest,
and that the stated amount matches what the transaction actually moved -- BEFORE
anything is written. Only then is the proofpack persisted, and only then the
receipt that points at it, with the stored digest asserted equal to the one the
receipt commits to. A produce() call therefore either publishes evidence and a
receipt together or writes nothing at all: a refusal leaves no orphaned blob, and
a receipt never names bytes that failed to land.
"""
from __future__ import annotations

import json
from typing import Any

from .effects import verify_settlement_amount
from .receipt import MeshError, SettlementReceipt, bundle_digest, create_receipt
from .sealed import seal
from .service import Store


def settlement_from_bundle(bundle: dict, amount: str, asset: str = "microalgo",
                           issuer: str | None = None) -> dict:
    """Describe a settlement using the bundle's own verified values.

    `amount` is supplied by the caller because the bundle proves which transaction
    settled, not what it meant commercially. Keep the two apart: evidence is a
    fact, an invoice is an interpretation.
    """
    from avm_proofpack.bundle import Bundle

    b = Bundle.from_dict(bundle)
    settlement = {
        "chain_txid": b.txid,
        "round": b.round,
        "amount": amount,
        "asset": asset,
    }
    if issuer:
        settlement["issuer"] = issuer
    return settlement


def produce(bundle: dict, store: Store, *, trusted_voters: Any, amount: str,
            asset: str = "microalgo", issuer: str | None = None,
            corroboration: tuple[str, ...] = (),
            sign=None) -> tuple[SettlementReceipt, dict | None]:
    """Store the evidence, then return a receipt and (optionally) a sealed envelope.

    Returns ``(receipt, sealed_or_None)``. The envelope is only produced when a
    signer is supplied, because LEVEL 2 is a claim by the operator and inventing
    one without a key would misrepresent who is speaking.
    """
    if not isinstance(store, Store):
        raise MeshError("produce() needs a Store to persist the evidence")

    # Derive the content address from the bundle itself; nothing is written yet,
    # so a receipt we end up refusing leaves no orphaned proofpack behind.
    digest = bundle_digest(bundle)
    uri = store.uri_for(digest)

    receipt = create_receipt(bundle, uri, corroboration=corroboration,
                             trusted_voters=trusted_voters)

    # Refuse rather than downgrade. An "unattested" receipt looks like evidence
    # and is not: a merchant reading trust_root would have to know to check it.
    # If the evidence cannot carry the tier, nothing is published.
    if receipt.trust_root != "stake_attested":
        raise MeshError(
            f"evidence earns {receipt.trust_root!r}, not stake_attested; "
            "capture the previous state-proof interval and supply the anchor"
        )

    # The receipt must reference the content address we derived.
    if receipt.pointer.digest != digest:
        raise MeshError(
            "proofpack digest disagrees with the receipt; refusing to publish"
        )

    # Bind the stated amount to what the transaction actually did, against the
    # STIB the receipt's own evidence just authenticated. produce() will not
    # issue a receipt whose amount the evidence does not bear out -- an honest
    # fat-finger and a hostile over-statement fail the same way, here, before
    # anything is published.
    verify_settlement_amount(bundle, {"amount": amount, "asset": asset},
                             receipt.chain)

    # Everything checked: persist the evidence, then the receipt that points at
    # it, and confirm the bytes that landed hash to what the receipt commits to.
    stored = store.put_proofpack(bundle)
    if stored != digest:
        raise MeshError(
            "stored proofpack digest disagrees with the receipt; refusing to publish"
        )
    store.put_receipt(receipt)

    sealed = None
    if sign is not None:
        content = {
            "version": 1,
            "settlement": settlement_from_bundle(bundle, amount, asset, issuer),
            "receipt_txid": receipt.txid,
            "trust_root": receipt.trust_root,
        }
        sealed = seal(content, bundle, uri, trusted_voters=trusted_voters, sign=sign)
    return receipt, sealed


def load_settlement(path: str) -> dict:
    """Read a settlement description from disk (the caller's own record)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise MeshError("settlement file must contain an object")
    return data
