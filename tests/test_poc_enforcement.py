"""PoC administrative enforcement.

These exercise the whole challenge -> remove -> audit flow against the real
mainnet bundle and an anchor, the same assets the attestation tests use. They
assert what the PoC genuinely does (detect a non-verifying attestation, remove
the witness, record a tamper-evident line, drop it from corroboration) and are
careful not to assert on-chain slashing, which the PoC does not do.
"""
import copy
import json

import pytest

from avm_mesh import attest
from avm_mesh.attestation import ConsensusAttestation
from avm_mesh.bond import BondError, BondPolicy, Witness, WitnessSet
from avm_mesh.poc import (
    REMOVED, UPHELD, EnforcementLedger, verify_ledger, _entry_hash, _GENESIS, _write_head,
)
from avm_mesh.receipt import MeshError

CHAIN = "mainnet-v1.0"
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="


def _resolver(b):
    return lambda uri: copy.deepcopy(b)


def _witness(wid, op, bond_amount=1_000_000):
    return Witness(witness_id=wid, operator_id=op, chain=CHAIN,
                   bond_microalgo=bond_amount, escrow_txid=f"ESCROW-{wid}")


def _set():
    return WitnessSet((_witness("w1", "op-a"), _witness("w2", "op-b")))


def test_an_honest_attestation_is_upheld_and_nothing_changes(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    ledger = EnforcementLedger(_set(), tmp_path / "ledger.jsonl")

    result = ledger.challenge("w1", att, _resolver(bundle), trusted_voters=anchor,
                              expected_genesis_hash_b64=GENESIS)

    assert result.verdict == UPHELD
    assert result.declared_slash_microalgo == 0
    active = {w.witness_id for w in ledger.active_witnesses().witnesses if w.active}
    assert active == {"w1", "w2"}


def test_a_non_verifying_attestation_removes_the_witness(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    ledger = EnforcementLedger(_set(), tmp_path / "ledger.jsonl")

    result = ledger.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor,
                              expected_genesis_hash_b64=GENESIS)

    assert result.verdict == REMOVED
    assert "different settlement" in result.reason
    # declared forfeit is the whole bond under the default (100%) policy
    assert result.declared_slash_microalgo == 1_000_000
    live = ledger.active_witnesses()
    assert {w.witness_id for w in live.witnesses if w.active} == {"w1"}


def test_a_removed_witness_drops_out_of_corroboration(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    ledger = EnforcementLedger(_set(), tmp_path / "ledger.jsonl")

    # two independent operators corroborate before the challenge
    assert len(ledger.active_witnesses().independent_corroborators(CHAIN)) == 2
    ledger.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor)
    # after removal the quorum of two can no longer be formed
    assert len(ledger.active_witnesses().independent_corroborators(CHAIN)) == 1
    with pytest.raises(BondError):
        ledger.active_witnesses().require_corroboration(CHAIN, 2)


def test_slash_fraction_policy_is_recorded(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    ledger = EnforcementLedger(_set(), tmp_path / "ledger.jsonl",
                               policy=BondPolicy(slash_fraction=0.25))
    result = ledger.challenge("w1", forged, _resolver(bundle), trusted_voters=anchor)
    assert result.declared_slash_microalgo == 250_000


def test_challenging_an_unknown_witness_is_refused(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    ledger = EnforcementLedger(_set(), tmp_path / "ledger.jsonl")
    with pytest.raises(BondError, match="no witness record"):
        ledger.challenge("ghost", att, _resolver(bundle), trusted_voters=anchor)


def test_the_ledger_catches_in_place_edits_via_the_hash_chain(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    path = tmp_path / "ledger.jsonl"
    ledger = EnforcementLedger(_set(), path)
    ledger.challenge("w1", att, _resolver(bundle), trusted_voters=anchor)
    ledger.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor)
    assert verify_ledger(path) == 2

    lines = path.read_text(encoding="utf-8").splitlines()
    # Flip the first entry's verdict in place: its recomputed hash no longer
    # matches the stored one, and the chain breaks at that line.
    tampered = lines[0].replace('"upheld"', '"removed"')
    path.write_text(tampered + "\n" + lines[1] + "\n", encoding="utf-8")
    with pytest.raises(MeshError, match="entry_hash does not match"):
        verify_ledger(path)


def test_the_ledger_catches_truncation_via_the_head_sidecar(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    path = tmp_path / "ledger.jsonl"
    ledger = EnforcementLedger(_set(), path)
    ledger.challenge("w1", att, _resolver(bundle), trusted_voters=anchor)
    ledger.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor)

    lines = path.read_text(encoding="utf-8").splitlines()
    # Drop the trailing (removal) line, leaving the head sidecar saying seq 2.
    # An append-only log alone could not notice; the head makes it evident.
    path.write_text(lines[0] + "\n", encoding="utf-8")
    with pytest.raises(MeshError, match="truncation detected"):
        verify_ledger(path)
    # And a resume refuses it rather than silently resurrecting the removed witness.
    with pytest.raises(MeshError, match="truncation detected"):
        EnforcementLedger(_set(), path)


def test_a_deleted_log_with_a_surviving_head_is_refused(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    path = tmp_path / "ledger.jsonl"
    ledger = EnforcementLedger(_set(), path)
    ledger.challenge("w1", att, _resolver(bundle), trusted_voters=anchor)
    ledger.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor)

    # Delete the whole log but leave the .head sidecar: a naive "file absent ->
    # start fresh" would resurrect the removed witness. Both paths must refuse.
    path.unlink()
    with pytest.raises(MeshError, match="the log was deleted"):
        EnforcementLedger(_set(), path)
    with pytest.raises(MeshError, match="the log was deleted"):
        verify_ledger(path)


def test_rewriting_the_checkpointed_prefix_and_appending_is_rejected(tmp_path, bundle, anchor):
    """A longer-than-head log is only accepted if the head is still a prefix.

    Otherwise an attacker could flip a recorded removal to 'upheld', recompute the
    chain and append one line so the log is longer than the stale head, laundering
    the rewrite. The checkpoint-prefix check must catch that.
    """
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    path = tmp_path / "ledger.jsonl"
    ledger = EnforcementLedger(_set(), path)
    ledger.challenge("w1", att, _resolver(bundle), trusted_voters=anchor)    # seq 1 upheld
    ledger.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor)  # seq 2 removed; head=seq2

    entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    # Flip seq 2 from removed -> upheld and recompute its hash (prev_hash unchanged).
    e2 = entries[1]
    body2 = {k: e2[k] for k in e2 if k != "entry_hash"}
    body2.update(verdict="upheld", reason="attestation verified", declared_slash_microalgo=0)
    h2 = _entry_hash(body2)
    e2_new = {**body2, "entry_hash": h2}
    # Append a seq 3 chained from the rewritten seq 2, making the log longer than head.
    body3 = {"seq": 3, "witness_id": "w1", "operator_id": "op-a", "verdict": "upheld",
             "reason": "x", "declared_slash_microalgo": 0,
             "ts": "2026-01-01T00:00:00+00:00", "prev_hash": h2}
    e3 = {**body3, "entry_hash": _entry_hash(body3)}
    new_log = "\n".join(json.dumps(x, sort_keys=True, separators=(",", ":"))
                        for x in [entries[0], e2_new, e3]) + "\n"
    path.write_text(new_log, encoding="utf-8")  # head sidecar still records the original seq 2 hash

    with pytest.raises(MeshError, match="checkpoint sequence"):
        verify_ledger(path)
    with pytest.raises(MeshError, match="checkpoint sequence"):
        EnforcementLedger(_set(), path)


def _write_single_entry(path, seq):
    body = {"seq": seq, "witness_id": "w1", "operator_id": "op-a", "verdict": "upheld",
            "reason": "x", "declared_slash_microalgo": 0,
            "ts": "2026-01-01T00:00:00+00:00", "prev_hash": _GENESIS}
    rec = {**body, "entry_hash": _entry_hash(body)}
    path.write_text(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def test_a_headless_log_with_a_zero_sequence_cannot_pass(tmp_path):
    """The seq field is not trusted: a rebuilt headless log ending at seq 0 must
    not slip past the 'entries exist -> need a head' check."""
    path = tmp_path / "ledger.jsonl"
    _write_single_entry(path, 0)  # no head sidecar written
    with pytest.raises(MeshError, match="consecutive"):
        verify_ledger(path)
    with pytest.raises(MeshError, match="consecutive"):
        EnforcementLedger(_set(), path)


def test_a_non_integer_or_nonconsecutive_sequence_is_rejected(tmp_path):
    path = tmp_path / "ledger.jsonl"
    for bad in (True, "1", 1.0):
        _write_single_entry(path, bad)
        with pytest.raises(MeshError, match="not an integer"):
            verify_ledger(path)
    _write_single_entry(path, 2)  # first entry must be seq 1, not 2
    with pytest.raises(MeshError, match="consecutive"):
        verify_ledger(path)


def test_uncheckpointed_tail_rollback_needs_an_external_hash(tmp_path, bundle, anchor):
    """The documented honest limit: if a head write fails (crash), the single
    uncheckpointed tail entry can be rolled back touching only the log, and the
    sidecar cannot tell. Only an externally retained post-removal hash catches it.
    """
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    path = tmp_path / "ledger.jsonl"
    ledger = EnforcementLedger(_set(), path)
    ledger.challenge("w1", att, _resolver(bundle), trusted_voters=anchor)       # seq 1
    removal = ledger.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor)  # seq 2
    retained = removal.entry_hash  # an external observer kept the post-removal hash

    lines = path.read_text(encoding="utf-8").splitlines()
    # Simulate a FAILED head write at seq 2: roll the sidecar back to seq 1.
    _write_head(path, 1, json.loads(lines[0])["entry_hash"])
    # Attacker truncates the log back to seq 1, dropping the removal.
    path.write_text(lines[0] + "\n", encoding="utf-8")

    # The local check cannot tell -- this is the acknowledged gap.
    assert verify_ledger(path) == 1
    # The externally retained post-removal hash does catch it.
    with pytest.raises(MeshError, match="externally retained hash"):
        verify_ledger(path, expected_head_hash=retained)


def test_the_ledger_resumes_without_resurrecting_a_removed_witness(tmp_path, bundle, anchor):
    att = attest(bundle, "file://proofpack.json", trusted_voters=anchor)
    forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
    path = tmp_path / "ledger.jsonl"
    first = EnforcementLedger(_set(), path)
    first.challenge("w2", forged, _resolver(bundle), trusted_voters=anchor)

    # a fresh ledger over the same file sees w2 already removed and keeps the chain
    resumed = EnforcementLedger(_set(), path)
    assert {w.witness_id for w in resumed.active_witnesses().witnesses if w.active} == {"w1"}
    resumed.challenge("w1", att, _resolver(bundle), trusted_voters=anchor)
    assert verify_ledger(path) == 2
