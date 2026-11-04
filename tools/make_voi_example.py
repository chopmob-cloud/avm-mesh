#!/usr/bin/env python3
"""Build a verifiable example receipt for the Voi chain.

`examples/proofpack-24213754.json.gz` is a genuine Voi capture, but it shipped without a
receipt, so a reader could not exercise `avm-mesh verify` against the second chain at all.
This tool produces the missing piece, the same way `make_example.py` does for Algorand.

    python tools/make_voi_example.py

WHAT THIS EXAMPLE PROVES, AND WHAT IT DOES NOT — read before quoting it
-----------------------------------------------------------------------
The receipt reaches `stake_attested`, and that is a real result: the Voi bundle's Falcon
signatures, reveal membership, signed weight and coin selection are verified against the
anchor below, and anyone can repeat it.

The anchor is derived from the *same bundle's* previous state-proof message, because that
is the only anchor material available offline. It is not an independent anchor: whoever
assembled the bundle chose it. A production verifier obtains the anchor from a pinned
bootstrap or from `avm-mesh anchor` walking from a checkpoint it trusts. The library
refuses to treat a bundle's own message as a trust root silently, which is why the anchor
is passed explicitly here and printed in the output for a reader to see.

Exit codes: 0 written, 1 refused, 3 unable to run (fixture missing).
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = ROOT / "examples" / "voi-proofpack-24213754.json.gz"
DEFAULT_OUT = ROOT / "examples"

VOI_GENESIS = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="
ASSET_ID = 586896


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build the worked Voi example receipt from the committed capture.")
    parser.add_argument("bundle", nargs="?", default=str(DEFAULT_BUNDLE),
                        help="captured Voi proofpack (default: the committed example)")
    parser.add_argument("outdir", nargs="?", default=str(DEFAULT_OUT),
                        help="directory to write into (default: examples/)")
    args = parser.parse_args(argv[1:])

    bundle_path = pathlib.Path(args.bundle)
    outdir = pathlib.Path(args.outdir)
    if not bundle_path.exists():
        print(f"bundle not found: {bundle_path}", file=sys.stderr)
        return 3

    opener = gzip.open if bundle_path.suffix == ".gz" else open
    with opener(bundle_path, "rt", encoding="utf-8") as handle:
        bundle = json.load(handle)

    from avm_proofpack.verify import TrustedVoters
    from avm_mesh import seal

    previous = bundle["previous_state_proof_message"]
    anchor = TrustedVoters(
        voters_commitment=base64.b64decode(previous["voters_commitment_b64"]),
        ln_proven_weight=int(previous["ln_proven_weight"]),
    )

    tx = bundle["transaction"]
    # The captured transaction moved 0 units of asset 586896, so the settlement has to
    # say exactly that. Claiming a convenient number here would produce an example that
    # only verifies because the binding was not actually checked.
    settlement = {
        "chain": "voimain-v1.0",
        "txid": tx["txid"],
        "round": tx["round"],
        "asset": ASSET_ID,
        "amount": "0",
    }
    # `seal` takes no genesis pin: the pin belongs at VERIFY time, where the person
    # checking decides which chain they accept. The receipt records the chain it was
    # built for, and `verify --genesis` is what refuses a mismatch.
    receipt = seal({"settlement": settlement,
                    "issuer_did": "did:example:worked-example-voi"},
                   bundle, "voi-proofpack-24213754.json.gz",
                   trusted_voters=anchor)

    outdir.mkdir(parents=True, exist_ok=True)
    receipt_path = outdir / "receipt-voi-24213754.json"
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    print(f"receipt   {receipt_path}  {receipt_path.stat().st_size} bytes")
    print(f"chain     {bundle['chain']['genesis_id']}")
    print(f"txid      {tx['txid']} @ round {tx['round']}")
    print(f"amount    {settlement['amount']} units of asset {ASSET_ID}")
    # A sealed envelope carries no trust_root: the tier is asserted by the attestation
    # inside the canonical bytes, and re-derived at verify time.
    attestation = json.loads(base64.b64decode(receipt["canonical_bytes_b64"]))["consensus_attestation"]
    print(f"tier      {attestation.get('trust_root')}")
    print()
    print("The anchor used is the bundle's own previous message -- mechanistically real,")
    print("but not independently sourced. Do not quote this as independent attestation.")
    print()
    print("Verify it with:")
    print(f"  avm-mesh verify {receipt_path.name} --evidence {outdir} \\")
    print(f"    --genesis {VOI_GENESIS} \\")
    print(f"    --voters-commitment {previous['voters_commitment_b64']} \\")
    print(f"    --ln-proven-weight {previous['ln_proven_weight']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
