"""Witness bonding: why a witness would tell the truth.

A state proof answers "what did the chain do". A witness answers "here is the
proof". Without a bond, a witness can withhold, delay or selectively serve
evidence at zero cost, and "decentralised because node operators run it" is a
centralised service with a bigger logo. The bond is the only thing that makes
a false or withholding attestation cost money.

TWO DISTINCT CLAIMS, kept apart on purpose:

  bond      -- economic stake that can be slashed. Verifiable on-chain.
  operator  -- who runs the witness. NOT a trust source; only used to decide
               independence, because two endpoints of one operator are one
               witness wearing two hats.

A witness can be perfectly bonded and still be irrelevant to corroboration if
it shares an operator with the rest of the quorum.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

MIN_BOND_MICROALGO = 1_000_000


class BondError(Exception):
    """Raised when a witness set cannot support the claim being made."""


@dataclass(frozen=True)
class Witness:
    witness_id: str
    operator_id: str
    chain: str
    bond_microalgo: int
    escrow_txid: str
    active: bool = True

    def __post_init__(self) -> None:
        # Type, not truthiness: 42 is truthy and would become a "witness id" that
        # no other record could ever match.
        for name, value in (("witness_id", self.witness_id),
                            ("operator_id", self.operator_id),
                            ("chain", self.chain),
                            ("escrow_txid", self.escrow_txid)):
            if not isinstance(value, str) or not value:
                raise BondError(f"{name} must be a non-empty string")
        if not isinstance(self.bond_microalgo, int) or isinstance(self.bond_microalgo, bool):
            raise BondError("bond_microalgo must be an integer")
        if self.bond_microalgo < 0:
            raise BondError("bond cannot be negative")

    @property
    def bonded(self) -> bool:
        return self.active and self.bond_microalgo >= MIN_BOND_MICROALGO

@dataclass(frozen=True)
class WitnessSet:
    witnesses: tuple[Witness, ...]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for w in self.witnesses:
            if w.witness_id in seen:
                raise BondError(f"duplicate witness_id {w.witness_id!r}")
            seen.add(w.witness_id)

    def bonded(self) -> tuple[Witness, ...]:
        return tuple(w for w in self.witnesses if w.bonded)

    def independent_corroborators(self, chain: str) -> tuple[Witness, ...]:
        """Bonded witnesses on `chain`, at most ONE per operator and per escrow.

        Two endpoints of the same operator are not a quorum, and neither are
        two witnesses pointing at one escrow -- that is one bond counted
        twice, which is the cheapest way to fake corroboration.
        """
        chosen: list[Witness] = []
        seen_operators: set[str] = set()
        seen_escrows: set[str] = set()
        for w in sorted(self.bonded(), key=lambda x: (-x.bond_microalgo, x.witness_id)):
            if w.chain != chain:
                continue
            if w.operator_id in seen_operators or w.escrow_txid in seen_escrows:
                continue
            seen_operators.add(w.operator_id)
            seen_escrows.add(w.escrow_txid)
            chosen.append(w)
        return tuple(chosen)

    def require_corroboration(self, chain: str, threshold: int) -> tuple[Witness, ...]:
        """Return the independent corroborators, or refuse.

        Refusing is the point: a caller that cannot reach the threshold must
        not be handed a shorter list and left to interpret it.
        """
        if threshold < 1:
            raise BondError("threshold must be at least 1")
        got = self.independent_corroborators(chain)
        if len(got) < threshold:
            raise BondError(
                f"insufficient independent corroboration on {chain}: "
                f"{len(got)} of {threshold} required "
                f"({len(self.bonded())} bonded, "
                f"{len({w.operator_id for w in self.bonded()})} distinct operators)"
            )
        return got[:threshold]

    def slashable_stake(self, chain: str) -> int:
        """Total microalgo a false attestation could put at risk.

        Counted over independent operators only, because that is the amount
        that could actually be taken for one lie.
        """
        return sum(w.bond_microalgo for w in self.independent_corroborators(chain))


def witnesses(*items: Witness | dict) -> WitnessSet:
    """Convenience constructor, tolerating dicts from config or JSON."""
    out = []
    for item in items:
        if isinstance(item, Witness):
            out.append(item)
        elif isinstance(item, dict):
            try:
                out.append(Witness(**item))
            except TypeError as exc:
                raise BondError(f"unusable witness record: {exc}") from exc
        else:
            raise BondError(f"unusable witness entry: {item!r}")
    return WitnessSet(tuple(out))

def validate_corroboration(claimed, witness_set: "WitnessSet", chain: str,
                           threshold: int) -> tuple["Witness", ...]:
    """Check a receipt's claimed corroboration against the bonded witness set.

    A receipt records who observed the capture. That claim is worthless unless it
    is checked against bonds, so this refuses on four distinct failures:

      unknown      a witness id nobody has a bond record for
      unbonded     a real witness whose stake is absent, inactive or too small
      duplicated   the same operator or the same escrow counted twice
      insufficient fewer independent corroborators than the threshold demands

    Returning a short list would let a caller read a failed quorum as a pass.
    """
    if threshold < 1:
        raise BondError("threshold must be at least 1")
    if claimed is None:
        claimed = ()
    if not isinstance(claimed, (list, tuple)):
        raise BondError("corroboration must be a list of witness ids")

    by_id = {w.witness_id: w for w in witness_set.witnesses}
    chosen: list[Witness] = []
    seen_operators: set[str] = set()
    seen_escrows: set[str] = set()

    for wid in claimed:
        if not isinstance(wid, str) or not wid:
            raise BondError(f"corroboration entries must be witness ids, got {wid!r}")
        w = by_id.get(wid)
        if w is None:
            raise BondError(f"claimed corroborator {wid!r} has no bond record")
        if not w.bonded:
            raise BondError(f"claimed corroborator {wid!r} is not bonded")
        if w.chain != chain:
            raise BondError(f"claimed corroborator {wid!r} is bonded on {w.chain!r}, not {chain!r}")
        if w.operator_id in seen_operators:
            raise BondError(
                f"claimed corroborators share operator {w.operator_id!r}: "
                "one operator is one witness"
            )
        if w.escrow_txid in seen_escrows:
            raise BondError(
                f"claimed corroborators share escrow {w.escrow_txid!r}: "
                "one bond is one witness"
            )
        seen_operators.add(w.operator_id)
        seen_escrows.add(w.escrow_txid)
        chosen.append(w)

    if len(chosen) < threshold:
        raise BondError(
            f"insufficient corroboration on {chain}: claimed {len(chosen)} independent "
            f"witnesses, threshold is {threshold}"
        )
    return tuple(chosen)
