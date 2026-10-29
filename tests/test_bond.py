"""Witness bonding tests.

Each test is an attempt to manufacture corroboration cheaply, which is the
attack this module exists to price.
"""
import pytest

from avm_mesh import bond
from avm_mesh.bond import BondError, Witness, WitnessSet, witnesses

CHAIN = "mainnet-v1.0"


def w(wid, op, bond_amount=1_000_000, escrow=None, chain=CHAIN, active=True):
    return Witness(witness_id=wid, operator_id=op, chain=chain,
                   bond_microalgo=bond_amount,
                   escrow_txid=escrow or f"ESCROW-{wid}", active=active)


def test_healthy_set_corroborates():
    ws = witnesses(w("a", "op-1"), w("b", "op-2"), w("c", "op-3"))
    got = ws.require_corroboration(CHAIN, 2)
    assert len(got) == 2
    assert len({x.operator_id for x in got}) == 2


def test_two_endpoints_of_one_operator_are_one_witness():
    """The rule from the brief: same operator twice is not a quorum."""
    ws = witnesses(w("a", "op-1"), w("b", "op-1"))
    assert len(ws.independent_corroborators(CHAIN)) == 1
    with pytest.raises(BondError, match="insufficient independent corroboration"):
        ws.require_corroboration(CHAIN, 2)


def test_one_bond_cannot_be_counted_twice_via_two_witnesses():
    """Distinct operators and ids, one escrow: that is one bond."""
    ws = witnesses(w("a", "op-1", escrow="SAME"), w("b", "op-2", escrow="SAME"))
    assert len(ws.independent_corroborators(CHAIN)) == 1


def test_unbonded_witness_is_irrelevant():
    ws = witnesses(w("a", "op-1"), w("b", "op-2", bond_amount=10))
    assert len(ws.independent_corroborators(CHAIN)) == 1


def test_inactive_witness_is_irrelevant():
    ws = witnesses(w("a", "op-1"), w("b", "op-2", active=False))
    assert len(ws.independent_corroborators(CHAIN)) == 1


def test_other_chain_witnesses_do_not_corroborate():
    ws = witnesses(w("a", "op-1"), w("b", "op-2", chain="voimain-v1.0"))
    assert len(ws.independent_corroborators(CHAIN)) == 1


def test_same_witness_id_twice_is_refused():
    with pytest.raises(BondError, match="duplicate witness_id"):
        WitnessSet((w("a", "op-1"), w("a", "op-2")))


def test_bond_without_escrow_is_refused():
    with pytest.raises(BondError, match="escrow_txid"):
        Witness(witness_id="a", operator_id="op-1", chain=CHAIN,
                bond_microalgo=1_000_000, escrow_txid="")


def test_anonymous_operator_is_refused():
    """Otherwise each endpoint becomes its own identity."""
    with pytest.raises(BondError, match="operator_id"):
        Witness(witness_id="a", operator_id="", chain=CHAIN,
                bond_microalgo=1_000_000, escrow_txid="E")


def test_threshold_refuses_rather_than_returns_a_short_list():
    ws = witnesses(w("a", "op-1"), w("b", "op-1"))
    with pytest.raises(BondError):
        ws.require_corroboration(CHAIN, 2)


def test_dictionary_config_is_accepted():
    ws = witnesses({"witness_id": "a", "operator_id": "op-1", "chain": CHAIN,
                    "bond_microalgo": 1_000_000, "escrow_txid": "E1"})
    assert len(ws.bonded()) == 1
    with pytest.raises(BondError, match="unusable witness record"):
        witnesses({"witness_id": "b"})


def test_slashable_stake_counts_independent_operators_only():
    ws = witnesses(w("a", "op-1", bond_amount=5_000_000),
                   w("b", "op-1", bond_amount=5_000_000),
                   w("c", "op-2", bond_amount=2_000_000))
    assert ws.slashable_stake(CHAIN) == 7_000_000
