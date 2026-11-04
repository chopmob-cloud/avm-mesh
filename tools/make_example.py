#!/usr/bin/env python3
"""Produce a worked example from real Algorand mainnet evidence.

Outputs two files:

    examples/receipt-66457600.json     the settlement receipt (~1 KB)
    examples/proofpack-66457600.json   the proofpack it points at (~800 KB)

Run:  python tools/make_example.py [fixture.json.gz] [outdir]

WHAT THIS EXAMPLE DOES AND DOES NOT PROVE — read before quoting it
-----------------------------------------------------------------
The receipt reaches ``stake_attested``. The anchor used to get there is derived
from the *same bundle's* previous state-proof message, because that is the only
anchor material available offline in the fixture. The library refuses to treat a
bundle's own message as a trust root, so this is not silently accepted: the anchor
is passed explicitly, and a reader can see exactly what was pinned.

What that means in plain terms:

- the Falcon signatures, reveal membership, signed weight and coin selection over
  the bundle are all genuinely verified, and can be re-verified by anyone;
- whether the *voters commitment* it is checked against is the one Algorand's
  consensus actually had at round 66457600 is NOT independently established here.
  A production verifier obtains that from a pinned genesis bootstrap or a chain
  walk anchored in something it already trusts.

So this is a worked example of the tier's mechanics with real mainnet data, not a
claim of independent attestation. The README says the same thing next to the
command, because a reader who only sees "stake_attested" would reasonably assume
more than this file establishes.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import pathlib
import sys

DEFAULT_FIXTURE = pathlib.Path(
    "C:/algo/avm-proofpack/tests/fixtures/stake_attested_algorand_66457600.json.gz")
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Produce the worked example receipt and proofpack from real mainnet evidence.")
    parser.add_argument("fixture", nargs="?", default=None,
                        help=f"captured proofpack (default: $AVM_MESH_FIXTURE or {DEFAULT_FIXTURE})")
    parser.add_argument("outdir", nargs="?", default="examples",
                        help="directory to write into (default: examples)")
    args = parser.parse_args(argv[1:])

    fixture = pathlib.Path(args.fixture if args.fixture is not None
                           else os.environ.get("AVM_MESH_FIXTURE", str(DEFAULT_FIXTURE)))
    outdir = pathlib.Path(args.outdir)
    if not fixture.exists():
        print(f"fixture not found: {fixture}", file=sys.stderr)
        return 3

    opener = gzip.open if fixture.suffix == ".gz" else open
    with opener(fixture, "rt", encoding="utf-8") as handle:
        bundle = json.load(handle)

    from avm_proofpack.verify import TrustedVoters
    from avm_mesh import seal

    prev = bundle["previous_state_proof_message"]
    anchor = TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]),
    )

    tx = bundle["transaction"]
    receipt = seal({"settlement": {"chain": "mainnet-v1.0", "txid": tx["txid"],
                                   "round": tx["round"]},
                    "issuer_did": "did:example:worked-example"},
                   bundle, "proofpack-66457600.json", trusted_voters=anchor)

    outdir.mkdir(parents=True, exist_ok=True)
    receipt_path = outdir / "receipt-66457600.json"
    bundle_path = outdir / "proofpack-66457600.json"
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    print(f"receipt   {receipt_path}  {receipt_path.stat().st_size} bytes")
    print(f"proofpack {bundle_path}  {bundle_path.stat().st_size} bytes")
    print(f"txid      {tx['txid']} @ round {tx['round']}")
    print(f"content   {receipt.get('content_hash')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
