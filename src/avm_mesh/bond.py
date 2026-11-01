"""Witness bonding: why a witness would tell the truth.

A state proof answers "what did the chain do". A witness answers "here is the
proof". Without a bond, a witness can withhold, delay or selectively serve
evidence at zero cost, and "decentralised because node operators run it" is a
centralised service with a bigger logo. The bond is the only thing that makes
a false or withholding attestation cost money.

TWO DISTINCT CLAIMS, kept apart on purpose:

  bond      -- an economic stake that can be slashed. IMPORTANT: this module
               reasons over DECLARED bond values (escrow_txid, bond_microalgo,
               active); it does NOT read the chain. "bonded" here means "claims
               a stake at or above the floor", not "a stake proven on-chain to
               exist, be unspent and be active". On-chain verification of the
               escrow is deliberately out of scope (Track 3, decisions pending),
               so until it lands everything downstream of a bond is a model, not
               a guarantee. The economic argument below is the design intent, not
               something this code enforces.
  operator  -- who runs the witness. NOT a trust source; only used to decide
               independence, because two endpoints of one operator are one
               witness wearing two hats.

A witness can be perfectly bonded and still be irrelevant to corroboration if
it shares an operator with the rest of the quorum.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Iterable

MIN_BOND_MICROALGO = 1_000_000


class BondError(Exception):
    """Raised when a witness set cannot support the claim being made."""


@dataclass(frozen=True)
class BondPolicy:
    """Tunable bonding parameters for a deployment.

    This is CONFIGURATION, not enforcement. The module reasons over DECLARED
    bonds (see the module docstring), so a policy only parameterises the declared
    arithmetic: the floor a declared bond must clear, and the fraction a
    proven-false attestation would forfeit. Nothing here reads a chain or moves a
    coin.

    The lasting values are a community decision, not a product default
    (`docs/BONDING-DECISIONS.md`). The defaults below are the dev / proof-of-concept
    placeholders, deliberately low, and are superseded by whatever an ecosystem
    ratifies.
    """
    min_bond_microalgo: int = MIN_BOND_MICROALGO
    # A proven-false attestation forfeits this fraction of the declared bond.
    # Accepts a float, an int, a string like "1/3", or a Fraction (see _fraction).
    slash_fraction: "float | int | str | Fraction" = 1.0

    def __post_init__(self) -> None:
        if not isinstance(self.min_bond_microalgo, int) or isinstance(self.min_bond_microalgo, bool) \
                or self.min_bond_microalgo < 0:
            raise BondError("min_bond_microalgo must be a non-negative integer")
        frac = self._fraction()  # validates the type and parse
        if not (0 <= frac <= 1):
            raise BondError("slash_fraction must be between 0.0 and 1.0")

    def _fraction(self) -> Fraction:
        """The slash fraction as an exact rational.

        A float is read at its exact binary value via its shortest decimal
        (``Fraction(str(x))``), so a decimal literal like 0.29 is 29/100 and does
        not drift. A fraction with no finite decimal (1/3) must be passed exactly,
        as the string "1/3" or a Fraction; a float 1/3 is only as exact as the
        float, which is the caller's choice to make.
        """
        x = self.slash_fraction
        if isinstance(x, bool):
            raise BondError("slash_fraction must be a number, string or Fraction, not a bool")
        if isinstance(x, float):
            import math
            if not math.isfinite(x):
                raise BondError("slash_fraction must be a finite number")
            return Fraction(str(x))
        if isinstance(x, (int, str, Fraction)):
            try:
                return Fraction(x)
            except (ValueError, ZeroDivisionError) as exc:
                raise BondError(f"slash_fraction is not a valid fraction: {exc}") from exc
        raise BondError("slash_fraction must be a number, string or Fraction")

    def slash_amount(self, bond_microalgo: int) -> int:
        """Declared microalgo a proven-false attestation forfeits under this policy.

        Illustrative arithmetic over a declared figure, not an amount this code can
        take: there is no escrow to take it from until on-chain bonding is built.

        Computed in exact rational arithmetic and floored, never in binary float:
        ``int(100 * 0.29)`` is 28, not 29, and a forfeiture figure must not drift on
        a representation artefact.
        """
        if not isinstance(bond_microalgo, int) or isinstance(bond_microalgo, bool) or bond_microalgo < 0:
            raise BondError("bond_microalgo must be a non-negative integer")
        return int(bond_microalgo * self._fraction())


#: The dev / PoC default policy. Equal to the historical module behaviour (1 ALGO
#: floor, whole-bond forfeit) so callers that pass no policy are unchanged.
DEFAULT_POLICY = BondPolicy()


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
        return self.is_bonded(DEFAULT_POLICY)

    def is_bonded(self, policy: "BondPolicy | None" = None) -> bool:
        """Active, and declaring a stake at or above the policy floor."""
        policy = policy or DEFAULT_POLICY
        return self.active and self.bond_microalgo >= policy.min_bond_microalgo

@dataclass(frozen=True)
class WitnessSet:
    witnesses: tuple[Witness, ...]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for w in self.witnesses:
            if w.witness_id in seen:
                raise BondError(f"duplicate witness_id {w.witness_id!r}")
            seen.add(w.witness_id)

    def bonded(self, policy: "BondPolicy | None" = None) -> tuple[Witness, ...]:
        return tuple(w for w in self.witnesses if w.is_bonded(policy))

    def independent_corroborators(self, chain: str,
                                  policy: "BondPolicy | None" = None) -> tuple[Witness, ...]:
        """Bonded witnesses on `chain`, at most ONE per operator and per escrow.

        Two endpoints of the same operator are not a quorum, and neither are
        two witnesses pointing at one escrow -- that is one bond counted
        twice, which is the cheapest way to fake corroboration.
        """
        chosen: list[Witness] = []
        seen_operators: set[str] = set()
        seen_escrows: set[str] = set()
        for w in sorted(self.bonded(policy), key=lambda x: (-x.bond_microalgo, x.witness_id)):
            if w.chain != chain:
                continue
            if w.operator_id in seen_operators or w.escrow_txid in seen_escrows:
                continue
            seen_operators.add(w.operator_id)
            seen_escrows.add(w.escrow_txid)
            chosen.append(w)
        return tuple(chosen)

    def require_corroboration(self, chain: str, threshold: int,
                              policy: "BondPolicy | None" = None) -> tuple[Witness, ...]:
        """Return the independent corroborators, or refuse.

        Refusing is the point: a caller that cannot reach the threshold must
        not be handed a shorter list and left to interpret it.
        """
        if threshold < 1:
            raise BondError("threshold must be at least 1")
        got = self.independent_corroborators(chain, policy)
        if len(got) < threshold:
            bonded = self.bonded(policy)
            raise BondError(
                f"insufficient independent corroboration on {chain}: "
                f"{len(got)} of {threshold} required "
                f"({len(bonded)} bonded, "
                f"{len({w.operator_id for w in bonded})} distinct operators)"
            )
        return got[:threshold]

    def slashable_stake(self, chain: str, policy: "BondPolicy | None" = None) -> int:
        """Total DECLARED microalgo a false attestation could put at risk.

        Counted over independent operators only, because that is the amount
        that could actually be taken for one lie, and under the policy's slash
        fraction rather than the gross bond: with a 100% fraction (the default)
        this is the sum of the bonds, but a lesser fraction puts less at risk and
        this figure must say so. Arithmetic over the declared bond figures, not a
        chain-verified sum: it is only as real as the bonds themselves, which this
        module does not verify on-chain.
        """
        policy = policy or DEFAULT_POLICY
        return sum(policy.slash_amount(w.bond_microalgo)
                   for w in self.independent_corroborators(chain, policy))


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
                           threshold: int,
                           policy: "BondPolicy | None" = None) -> tuple["Witness", ...]:
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
    policy = policy or DEFAULT_POLICY
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
        if not w.is_bonded(policy):
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
