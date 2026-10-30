"""Producer path: from a captured bundle to a receipt a merchant can verify.

This is the settler's side. It ties the three pieces together:

    capture (avm-proofpack) -> store the proofpack -> seal a receipt

The ordering is deliberate. The proofpack is stored BEFORE the receipt is
sealed, so the receipt can carry the store's own canonical URI and the digest of
the bytes actually on disk -- not of bytes that were about to be written. A
receipt that points at evidence which failed to persist is worse than no receipt.
"""
from __future__ import annotations

import json
from typing import Any

from .receipt import MeshError, SettlementReceipt, create_receipt
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

    digest = store.put_proofpack(bundle)
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

    # The receipt must reference the bytes we actually stored.
    if receipt.pointer.digest != digest:
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
