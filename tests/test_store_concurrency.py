"""Append-only receipt storage must hold under concurrent writers.

The defect this pins: put_receipt() checked is_file(), then wrote a shared
"<txid>.tmp" and replaced the target. Two callers racing could both pass the check
and both return success, with the second silently replacing the first — the exact
equivocation the append-only rule exists to prevent.

The winner is not deterministic; that there is exactly one winner is.
"""
import threading

import pytest

from avm_mesh import MeshError
from avm_mesh.receipt import ProofpackPointer, SettlementReceipt
from avm_mesh.service import Store

DIGEST = "a" * 64


def _receipt(tier: str) -> SettlementReceipt:
    return SettlementReceipt(
        version=1, chain="mainnet-v1.0", txid="RACE", round=66457600, trust_root=tier,
        pointer=ProofpackPointer(uri="proofpack:" + DIGEST, digest=DIGEST,
                                 first_attested_round=66457344,
                                 last_attested_round=66457600))


TIERS = ["structural", "corroborated", "stake_attested"]   # every VALID_TIERS value


def test_concurrent_conflicting_writers_produce_exactly_one_receipt(tmp_path):
    store = Store(tmp_path / "s")
    writers = len(TIERS) * 4
    barrier = threading.Barrier(writers)
    outcomes: list[tuple[str, str]] = []
    lock = threading.Lock()

    def attempt(index: int) -> None:
        try:
            receipt = _receipt(TIERS[index % len(TIERS)])
            # A thread that fails BEFORE the barrier would leave the others waiting
            # forever; the timeout makes the test fail rather than hang. (An invalid
            # tier did exactly that on the first version of this test.)
            barrier.wait(timeout=10)
            store.put_receipt(receipt)
            with lock:
                outcomes.append((receipt.trust_root, "ok"))
        except MeshError:
            with lock:
                outcomes.append((receipt.trust_root, "refused"))
        except threading.BrokenBarrierError:
            with lock:
                outcomes.append(("<none>", "barrier-broken"))

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "a writer thread did not finish"

    assert len(outcomes) == writers
    # Writers sending IDENTICAL content are idempotent by design, so several of them
    # legitimately succeed. What must not happen is two DIFFERENT receipts both being
    # accepted -- that is the equivocation this rule exists to prevent.
    accepted_tiers = {tier for tier, result in outcomes if result == "ok"}
    assert len(accepted_tiers) == 1, f"multiple distinct receipts accepted: {outcomes}"
    winner = accepted_tiers.pop()
    assert sum(1 for _, r in outcomes if r == "ok") == writers // len(TIERS)
    assert sum(1 for _, r in outcomes if r == "refused") == writers - writers // len(TIERS)

    # And the survivor is one complete receipt, not a torn write from a loser.
    served = store.get_receipt("RACE")
    assert served["txid"] == "RACE"
    assert served["trust_root"] == winner, "the stored receipt is not the one that won"


def test_an_identical_rewrite_is_still_idempotent(tmp_path):
    store = Store(tmp_path / "s")
    assert store.put_receipt(_receipt("structural")) == "RACE"
    assert store.put_receipt(_receipt("structural")) == "RACE"


def test_no_temporary_files_are_left_behind(tmp_path):
    store = Store(tmp_path / "s")
    store.put_receipt(_receipt("structural"))
    leftovers = [p.name for p in store.receipts.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []
