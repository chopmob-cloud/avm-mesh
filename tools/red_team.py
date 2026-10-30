#!/usr/bin/env python3
"""Red-team the installed package: attempt the forgeries, expect every refusal.

Each case is an attack a real adversary would try against a settlement receipt.
The script prints PASS only when the attack is *refused*; any accepted attack
exits non-zero. Run it against the installed wheel, not the source tree:

    python tools/red_team.py --fixture /path/to/bundle.json.gz

A refusal is only meaningful if the honest path works, so the first case is a
positive control: if genuine evidence fails to verify, everything after it is
vacuous and the run aborts.
"""
from __future__ import annotations

import argparse
import base64
import copy
import gzip
import json
import pathlib
import sys
import tempfile


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", required=True)
    args = ap.parse_args(argv)

    path = pathlib.Path(args.fixture)
    if not path.exists():
        print(f"ABORT: fixture not found at {path}")
        return 3
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        bundle = json.load(f)

    from avm_proofpack.verify import TrustedVoters

    from avm_mesh.produce import produce
    from avm_mesh.receipt import MeshError, SettlementReceipt, verify_receipt
    from avm_mesh.service import Store
    from avm_mesh.trust import TrustPolicy, verify_with_policy

    prev = bundle["previous_state_proof_message"]
    anchor = TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]),
    )
    policy = TrustPolicy.from_dict({
        "chain": "mainnet-v1.0",
        "genesis_hash_b64": bundle["chain"]["genesis_hash_b64"],
        "anchor_voters_commitment_b64": prev["voters_commitment_b64"],
        "anchor_ln_proven_weight": int(prev["ln_proven_weight"]),
        "witnesses": [],
        "corroboration_threshold": 0,
    })

    store = Store(tempfile.mkdtemp())
    receipt, sealed = produce(bundle, store, trusted_voters=anchor, amount="1")
    digest = receipt.pointer.digest

    # ---- positive control -------------------------------------------------
    report = verify_with_policy(receipt, store.resolve, policy)
    if report.trust_root != "stake_attested":
        print("ABORT: honest evidence did not verify; later cases would be vacuous")
        return 3
    print("control  genuine evidence verifies            PASS")

    failures = []

    def expect_refusal(name, fn):
        try:
            fn()
        except MeshError as exc:
            print(f"attack   {name:<38} REFUSED ({str(exc)[:48]})")
            return
        except Exception as exc:  # noqa: BLE001
            print(f"attack   {name:<38} WRONG ERROR ({type(exc).__name__})")
            failures.append(name)
            return
        print(f"attack   {name:<38} ACCEPTED — VULNERABLE")
        failures.append(name)

    # ---- path traversal ---------------------------------------------------
    for hostile in ("../escape", "a/b", "..", ".", "x" * 200, "nul\x00name"):
        expect_refusal(f"store name {hostile[:18]!r}",
                       lambda h=hostile: store.get_receipt(h))

    # ---- substituted evidence --------------------------------------------
    other = copy.deepcopy(bundle)
    other["state_proof_message"]["ln_proven_weight"] += 1

    def swap():
        forged = SettlementReceipt.from_dict(
            {**receipt.to_dict(), "pointer": {**receipt.pointer.to_dict(),
                                              "digest": "0" * 64}})
        verify_receipt(forged, lambda uri: other, trusted_voters=anchor)

    expect_refusal("evidence substituted behind pointer", swap)

    # ---- tier upgrade -----------------------------------------------------
    def upgrade():
        forged = SettlementReceipt.from_dict({**receipt.to_dict(),
                                              "trust_root": "stake_attested"})
        verify_receipt(forged, store.resolve, trusted_voters=None)

    expect_refusal("tier upgraded without an anchor", upgrade)

    # ---- anchor mismatch --------------------------------------------------
    wrong = TrustedVoters(voters_commitment=bytes(64),
                          ln_proven_weight=anchor.ln_proven_weight)

    def wrong_anchor():
        verify_receipt(receipt, store.resolve, trusted_voters=wrong)

    expect_refusal("verifier holds a different anchor", wrong_anchor)

    # ---- wrong chain pin --------------------------------------------------
    voi = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="

    def wrong_genesis():
        verify_receipt(receipt, store.resolve, trusted_voters=anchor,
                       expected_genesis_hash_b64=voi)

    expect_refusal("genesis pin for another chain", wrong_genesis)

    # ---- interval shift ---------------------------------------------------
    def shift_interval():
        pointer = dict(receipt.pointer.to_dict())
        pointer["first_attested_round"] -= 256
        pointer["last_attested_round"] -= 256
        forged = SettlementReceipt.from_dict({**receipt.to_dict(), "pointer": pointer})
        verify_receipt(forged, store.resolve, trusted_voters=anchor)

    expect_refusal("attested interval moved", shift_interval)

    # ---- settlement reuse -------------------------------------------------
    def reuse():
        forged = SettlementReceipt.from_dict({**receipt.to_dict(), "txid": "A" * 52})
        verify_receipt(forged, store.resolve, trusted_voters=anchor)

    expect_refusal("evidence reused for another txid", reuse)

    # ---- policy chain -----------------------------------------------------
    def policy_chain():
        verify_with_policy(receipt, store.resolve,
                           TrustPolicy.from_dict({**policy.to_dict(),
                                                  "chain": "voimain-v1.0"}))

    expect_refusal("evidence under a policy for another chain", policy_chain)

    print()
    if failures:
        print(f"RED TEAM FAILED — {len(failures)} attack(s) succeeded: {failures}")
        return 1
    print("RED TEAM CLEAN — every attack refused")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
