"""Bind a receipt's stated amount to what the transaction actually did.

A settlement receipt carries an ``amount`` the producer supplied. The proofpack
proves *which* transaction settled and in *which* round, but on its own it says
nothing about *how much* moved -- so an operator (or a tampered sealed receipt)
can assert any figure while the transaction moved something else entirely. A
merchant reading ``stake_attested`` next to that figure would reasonably, and
wrongly, read the amount as attested too.

This module closes that gap by reading the amount out of the AUTHENTICATED
``SignedTxnInBlock``. Once :func:`avm_proofpack.verify.verify_bundle` has passed,
``bundle.stib_bytes`` is not a claim: it was canonical-checked, its transaction
id was re-derived from it, and its hash was proven into the block's transaction
commitment. ``avm_effectproof.decode_stib`` reads the real transfer out of those
same bytes, so comparing the stated amount against it turns the figure from an
interpretation into a fact -- or refuses it.

Fail-closed by construction: any settlement shape whose amount cannot be mapped
unambiguously to a single on-chain transfer (an app call, a key registration, a
close-remainder that moves funds the ``amount`` does not name, an asset the
transaction did not move) is REFUSED, never accepted. A receipt gets to assert
an amount only when the evidence proves that exact amount moved.
"""
from __future__ import annotations

from typing import Any

from .receipt import MeshError

# genesis_id -> the effectproof ChainProfile for that chain. Only chains whose
# block/transaction encoding this binding understands appear here; anything else
# is refused rather than guessed at.
_CHAIN_PROFILES = {
    "mainnet-v1.0": "ALGORAND_MAINNET",
    "voimain-v1.0": "VOI_MAINNET",
}

# Strings that name a chain's native unit rather than an ASA id. An ``asset``
# that is not one of these must be a non-negative integer asset id, or it is
# refused -- a typo cannot quietly fall through to the native path.
_NATIVE_UNITS = {"microalgo", "algo", "microvoi", "voi"}


def _profile(genesis_id: str):
    import avm_effectproof

    name = _CHAIN_PROFILES.get(genesis_id)
    if name is None:
        raise MeshError(
            f"cannot bind a settlement amount on chain {genesis_id!r}: "
            "no effect profile for it"
        )
    return getattr(avm_effectproof, name)


def _effects(bundle: dict, genesis_id: str):
    """Decode the authenticated STIB of ``bundle`` into its proven effects.

    ``bundle`` must be one that ``verify_bundle`` has already accepted for this
    chain; the caller is responsible for that, exactly as effectproof's own
    contract requires. Here it is always called after the consensus attestation
    has verified against the same bytes.
    """
    from avm_effectproof import decode_stib
    from avm_proofpack.bundle import Bundle

    try:
        b = Bundle.from_dict(bundle)
    except Exception as exc:
        raise MeshError(f"cannot read evidence to bind the amount: {exc}") from exc
    try:
        return decode_stib(b.stib_bytes, chain=_profile(genesis_id))
    except MeshError:
        raise
    except Exception as exc:
        raise MeshError(f"cannot decode the settled transaction's effects: {exc}") from exc


def _claimed_amount(settlement: dict) -> int:
    raw = settlement["amount"]
    try:
        value = int(str(raw))
    except (TypeError, ValueError) as exc:
        raise MeshError(
            f"settlement amount {raw!r} is not an integer base-unit value"
        ) from exc
    if value < 0:
        raise MeshError("settlement amount cannot be negative")
    return value


def verify_settlement_amount(bundle: dict, settlement: Any, genesis_id: str) -> None:
    """Refuse unless the settlement's amount equals the on-chain transfer.

    ``settlement`` carries ``amount`` (base units, as a string or int) and an
    optional ``asset`` (``"microalgo"``/native, the default, or a decimal ASA
    id). The amount is checked against the authenticated transaction:

    * native unit -> the top-level transaction must be a ``pay`` moving exactly
      that many microalgo, with no close-remainder;
    * an asset id -> the top-level transaction must be an ``axfer`` of exactly
      that asset and amount, with no asset close.

    Any other shape is refused. Raises :class:`MeshError` on any mismatch; returns
    ``None`` when the amount is proven.
    """
    if not isinstance(settlement, dict):
        raise MeshError("settlement must be an object to bind its amount")
    if "amount" not in settlement:
        raise MeshError("settlement has no amount to bind")

    claimed = _claimed_amount(settlement)
    asset = settlement.get("asset", "microalgo")
    eff = _effects(bundle, genesis_id)

    is_native = isinstance(asset, str) and asset.lower() in _NATIVE_UNITS
    if is_native:
        if eff.txn_type != "pay":
            raise MeshError(
                f"settlement claims a native-unit amount but the settled "
                f"transaction is a {eff.txn_type!r}, not a payment"
            )
        if eff.closing_amount:
            raise MeshError(
                "settled transaction closes its account (close-remainder-to); "
                "the stated amount is not the whole movement, so it cannot be bound"
            )
        if eff.amount != claimed:
            raise MeshError(
                f"settlement amount {claimed} does not match the on-chain "
                f"transfer of {eff.amount} microalgo"
            )
        return

    try:
        asset_id = int(str(asset))
    except (TypeError, ValueError) as exc:
        raise MeshError(
            f"settlement asset {asset!r} is neither a native unit nor an asset id"
        ) from exc
    if asset_id < 1:
        raise MeshError(f"settlement asset id {asset_id} is not a valid ASA id")
    if eff.txn_type != "axfer":
        raise MeshError(
            f"settlement claims asset {asset_id} but the settled transaction is a "
            f"{eff.txn_type!r}, not an asset transfer"
        )
    if eff.asset_closing_amount:
        raise MeshError(
            "settled transaction closes its asset holding; the stated amount is "
            "not the whole movement, so it cannot be bound"
        )
    if eff.asset_id != asset_id:
        raise MeshError(
            f"settlement names asset {asset_id} but the transaction moved "
            f"asset {eff.asset_id}"
        )
    if eff.asset_amount != claimed:
        raise MeshError(
            f"settlement amount {claimed} does not match the on-chain transfer "
            f"of {eff.asset_amount} units of asset {eff.asset_id}"
        )
