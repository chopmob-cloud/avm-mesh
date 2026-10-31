"""BondPolicy: the tunable floor and slash fraction, and that the default
reproduces the historical behaviour exactly so no existing caller is moved."""
import pytest

from avm_mesh.bond import (
    BondError,
    BondPolicy,
    DEFAULT_POLICY,
    MIN_BOND_MICROALGO,
    Witness,
    WitnessSet,
    validate_corroboration,
    witnesses,
)

CHAIN = "mainnet-v1.0"


def w(wid, op, bond_amount=1_000_000, escrow=None, chain=CHAIN, active=True):
    return Witness(witness_id=wid, operator_id=op, chain=chain,
                   bond_microalgo=bond_amount,
                   escrow_txid=escrow or f"ESCROW-{wid}", active=active)


def test_default_policy_matches_historical_constants():
    assert DEFAULT_POLICY.min_bond_microalgo == MIN_BOND_MICROALGO
    assert DEFAULT_POLICY.slash_fraction == 1.0


def test_default_bonded_property_still_uses_the_floor():
    assert w("a", "op-1", bond_amount=MIN_BOND_MICROALGO).bonded is True
    assert w("a", "op-1", bond_amount=MIN_BOND_MICROALGO - 1).bonded is False


def test_a_higher_floor_unbonds_a_witness_that_the_default_accepts():
    witness = w("a", "op-1", bond_amount=MIN_BOND_MICROALGO)
    strict = BondPolicy(min_bond_microalgo=MIN_BOND_MICROALGO * 1000)
    assert witness.is_bonded() is True            # default floor
    assert witness.is_bonded(strict) is False     # raised floor


def test_policy_threads_through_the_witness_set():
    ws = witnesses(w("a", "op-1"), w("b", "op-2"))
    strict = BondPolicy(min_bond_microalgo=10_000_000)
    assert len(ws.bonded()) == 2
    assert len(ws.bonded(strict)) == 0
    assert ws.slashable_stake(CHAIN) == 2_000_000
    assert ws.slashable_stake(CHAIN, strict) == 0
    with pytest.raises(BondError, match="insufficient independent corroboration"):
        ws.require_corroboration(CHAIN, 1, strict)


def test_slash_amount_is_the_fraction_of_the_declared_bond():
    assert DEFAULT_POLICY.slash_amount(1_000_000) == 1_000_000
    assert BondPolicy(slash_fraction=0.5).slash_amount(1_000_000) == 500_000
    assert BondPolicy(slash_fraction=0.0).slash_amount(1_000_000) == 0


def test_slash_amount_uses_exact_arithmetic_not_binary_float():
    # int(100 * 0.29) is 28 in binary float; a forfeiture must not drift like that.
    assert BondPolicy(slash_fraction=0.29).slash_amount(100) == 29


def test_an_exact_ratio_can_be_passed_as_a_string_or_fraction():
    from fractions import Fraction
    # 1/3 has no finite decimal; a float would floor 3*0.3333.. to 0.
    assert BondPolicy(slash_fraction="1/3").slash_amount(3) == 1
    assert BondPolicy(slash_fraction=Fraction(1, 3)).slash_amount(3) == 1
    with pytest.raises(BondError, match="slash_fraction"):
        BondPolicy(slash_fraction="not-a-fraction")


def test_a_non_finite_fraction_is_refused_as_bonderror():
    # inf/nan must come back as BondError, not leak a raw ValueError.
    with pytest.raises(BondError, match="finite"):
        BondPolicy(slash_fraction=float("inf"))
    with pytest.raises(BondError, match="finite"):
        BondPolicy(slash_fraction=float("nan"))


def test_slashable_stake_reflects_the_slash_fraction():
    ws = witnesses(w("a", "op-1", bond_amount=4_000_000),
                   w("b", "op-2", bond_amount=2_000_000))
    assert ws.slashable_stake(CHAIN) == 6_000_000                               # default 100%
    assert ws.slashable_stake(CHAIN, BondPolicy(slash_fraction=0.5)) == 3_000_000


def test_validate_corroboration_honours_a_custom_policy():
    ws = WitnessSet((w("a", "op-1", bond_amount=1_000_000),))
    strict = BondPolicy(min_bond_microalgo=10_000_000)
    validate_corroboration(["a"], ws, CHAIN, 1)                 # default floor: valid
    with pytest.raises(BondError, match="not bonded"):
        validate_corroboration(["a"], ws, CHAIN, 1, strict)     # raised floor: unbonded


def test_a_bad_policy_is_refused_at_construction():
    with pytest.raises(BondError, match="min_bond_microalgo"):
        BondPolicy(min_bond_microalgo=-1)
    with pytest.raises(BondError, match="slash_fraction"):
        BondPolicy(slash_fraction=1.5)
    with pytest.raises(BondError, match="slash_fraction"):
        BondPolicy(slash_fraction=True)  # a bool is not a fraction
