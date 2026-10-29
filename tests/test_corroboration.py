"""Corroboration claims validated against bonds.

A receipt's corroboration list used to be recorded evidence. These tests are
about making it established evidence -- or refusing.
"""
import copy
import gzip
import json
import os
import pathlib

import pytest

from avm_mesh import MeshError
from avm_mesh.bond import BondError, Witness, witnesses, validate_corroboration
from avm_mesh.receipt import create_receipt, verify_receipt

DEFAULT_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "avm-proofpack" / "tests" / "fixtures"
    / "stake_attested_algorand_66457600.json.gz"
)
CHAIN = "mainnet-v1.0"


def w(wid, op, escrow=None, bond_amount=1_000_000, chain=CHAIN, active=True):
    return Witness(witness_id=wid, operator_id=op, chain=chain,
                   bond_microalgo=bond_amount,
                   escrow_txid=escrow or f"E-{wid}", active=active)


def _resolver(b):
    return lambda uri: copy.deepcopy(b)


def test_valid_independent_claim_passes(bundle, anchor):
    ws = witnesses(w("w1", "op-1"), w("w2", "op-2"))
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1", "w2"), trusted_voters=anchor)
    verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, witness_set=ws, corroboration_threshold=2)


def test_same_operator_cannot_be_claimed_twice(bundle, anchor):
    ws = witnesses(w("w1", "op-1"), w("w2", "op-1"))
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1", "w2"), trusted_voters=anchor)
    with pytest.raises(MeshError, match="share operator"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, witness_set=ws, corroboration_threshold=2)


def test_same_escrow_cannot_be_claimed_twice(bundle, anchor):
    ws = witnesses(w("w1", "op-1", escrow="SAME"), w("w2", "op-2", escrow="SAME"))
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1", "w2"), trusted_voters=anchor)
    with pytest.raises(MeshError, match="share escrow"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, witness_set=ws, corroboration_threshold=2)


def test_unbonded_claimed_witness_is_refused(bundle, anchor):
    ws = witnesses(w("w1", "op-1"), w("w2", "op-2", bond_amount=1))
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1", "w2"), trusted_voters=anchor)
    with pytest.raises(MeshError, match="not bonded"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, witness_set=ws, corroboration_threshold=2)


def test_unknown_claimed_witness_is_refused(bundle, anchor):
    ws = witnesses(w("w1", "op-1"))
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1", "ghost"), trusted_voters=anchor)
    with pytest.raises(MeshError, match="no bond record"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, witness_set=ws, corroboration_threshold=2)


def test_threshold_higher_than_claim_is_refused(bundle, anchor):
    ws = witnesses(w("w1", "op-1"), w("w2", "op-2"), w("w3", "op-3"))
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1",), trusted_voters=anchor)
    with pytest.raises(MeshError, match="insufficient corroboration"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, witness_set=ws, corroboration_threshold=2)


def test_empty_claim_cannot_satisfy_a_threshold(bundle, anchor):
    ws = witnesses(w("w1", "op-1"), w("w2", "op-2"))
    receipt = create_receipt(bundle, "file://pp.json", trusted_voters=anchor)
    with pytest.raises(MeshError, match="insufficient corroboration"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, witness_set=ws, corroboration_threshold=1)


def test_threshold_without_a_witness_set_is_refused(bundle, anchor):
    """A threshold with nothing to check it against must not pass silently."""
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1",), trusted_voters=anchor)
    with pytest.raises(MeshError, match="no witness_set"):
        verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor, corroboration_threshold=1)


def test_no_bond_arguments_keeps_previous_behaviour(bundle, anchor):
    """Existing callers are unaffected: the claim stays recorded, not counted."""
    receipt = create_receipt(bundle, "file://pp.json", corroboration=("w1",), trusted_voters=anchor)
    report = verify_receipt(receipt, _resolver(bundle), trusted_voters=anchor)
    assert report.trust_root == "stake_attested"


def test_wrong_chain_witness_is_refused():
    ws = witnesses(w("w1", "op-1", chain="voimain-v1.0"))
    with pytest.raises(BondError, match="not 'mainnet-v1.0'"):
        validate_corroboration(("w1",), ws, CHAIN, 1)
