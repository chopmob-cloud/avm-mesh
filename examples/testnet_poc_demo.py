#!/usr/bin/env python3
"""Testnet proof-of-concept demo: the whole witness-bonding flow, end to end.

Runs attest -> verify -> challenge -> remove against REAL Algorand testnet
evidence, so an operator or reviewer can watch the mechanism work before any real
stake or on-chain slashing exists. See docs/POC-RUNBOOK.md for what this proves
and, just as importantly, what it does not.

By default it reads the committed example bundle (offline, repeatable):

    python examples/testnet_poc_demo.py

To pull fresh evidence from a live testnet node instead (the honest "live"
version), capture any confirmed testnet transaction inside a state-proof-attested
interval:

    python examples/testnet_poc_demo.py --capture \
        --node https://testnet-api.algonode.cloud \
        --txid <TXID> --round <ROUND>

HONEST SCOPE. This is testnet, not mainnet; the bonds are DECLARED, not read from
an escrow; and a "removal" is administrative, not an on-chain slash. The declared
forfeit printed below is illustrative arithmetic. None of this moves funds.
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import tempfile

from avm_proofpack.verify import TrustedVoters

from avm_mesh import attest, verify_attestation
from avm_mesh.attestation import ConsensusAttestation
from avm_mesh.bond import BondPolicy, Witness, WitnessSet
from avm_mesh.poc import EnforcementLedger, verify_ledger

HERE = pathlib.Path(__file__).resolve().parent
EXAMPLE_BUNDLE = HERE / "testnet-proofpack-68812906.json"
# Algorand testnet genesis hash, confirmed against a live testnet node.
TESTNET_GENESIS_B64 = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="


def _anchor(bundle: dict) -> TrustedVoters:
    """Anchor from the bundle's previous state-proof message.

    This is the same honest, NON-independent anchor the repo's fixtures use: it
    exercises the tier mechanics against real data but does not prove the walk is
    not one operator's private view. An independent second capture is a separate,
    out-of-scope step (docs/HANDOVER.md).
    """
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]),
    )


def _load_bundle(args: argparse.Namespace) -> dict:
    if args.capture:
        from avm_proofpack.capture import capture
        print(f"[capture] pulling {args.txid} @ {args.round} from {args.node} ...")
        bundle = capture(args.node, args.txid, args.round)
        print("[capture] captured and offline-verified")
        return bundle
    print(f"[load] reading committed example {EXAMPLE_BUNDLE.name}")
    return json.loads(EXAMPLE_BUNDLE.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capture", action="store_true", help="pull live from a testnet node")
    ap.add_argument("--node", default="https://testnet-api.algonode.cloud")
    ap.add_argument("--txid")
    ap.add_argument("--round", type=int)
    ap.add_argument("--genesis", default=TESTNET_GENESIS_B64)
    args = ap.parse_args()
    if args.capture and not (args.txid and args.round):
        ap.error("--capture needs --txid and --round")

    bundle = _load_bundle(args)
    anchor = _anchor(bundle)
    resolve = lambda uri: bundle

    print("\n[1] attest (LEVEL 3 consensus attestation)")
    att = attest(bundle, "proofpack:testnet-demo", trusted_voters=anchor)
    print(f"    tier={att.trust_root}  chain={att.chain}  round={att.round}")

    print("\n[2] verify_attestation (testnet genesis pinned)")
    report = verify_attestation(att, resolve, trusted_voters=anchor,
                                expected_genesis_hash_b64=args.genesis)
    print(f"    tier={report.trust_root}  txid_match={report.txid == att.txid}")

    print("\n[3] witness bonding + administrative enforcement")
    witnesses = WitnessSet((
        Witness("w1", "op-a", att.chain, 1_000_000, "ESCROW-w1"),
        Witness("w2", "op-b", att.chain, 1_000_000, "ESCROW-w2"),
    ))
    print(f"    independent corroborators before: "
          f"{[w.witness_id for w in witnesses.independent_corroborators(att.chain)]}")

    with tempfile.TemporaryDirectory() as tmp:
        ledger = EnforcementLedger(witnesses, pathlib.Path(tmp) / "ledger.jsonl",
                                   policy=BondPolicy())
        upheld = ledger.challenge("w1", att, resolve, trusted_voters=anchor,
                                  expected_genesis_hash_b64=args.genesis)
        print(f"    honest  w1 serves the real attestation -> {upheld.verdict}")

        # w2 serves an attestation for a different settlement: a proven-false lie.
        forged = ConsensusAttestation.from_dict({**att.to_dict(), "txid": "A" * 52})
        removed = ledger.challenge("w2", forged, resolve, trusted_voters=anchor,
                                   expected_genesis_hash_b64=args.genesis)
        print(f"    forged  w2 serves a false attestation -> {removed.verdict}")
        print(f"            reason: {removed.reason}")
        print(f"            declared forfeit (illustrative, NOT on-chain): "
              f"{removed.declared_slash_microalgo} microalgo")

        live = ledger.active_witnesses()
        print(f"    independent corroborators after:  "
              f"{[w.witness_id for w in live.independent_corroborators(att.chain)]}")
        print(f"    audit ledger entries, hash chain verified: "
              f"{verify_ledger(ledger.path)}")

    print("\nDONE. The whole flow ran on real testnet consensus. "
          "Nothing here is mainnet, a real stake, or an on-chain slash.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
