"""Standalone offline verifier for a sealed settlement receipt.

    python -m avm_mesh verify receipt.json --evidence ./proofpacks \
        --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=

Exit codes: 0 verified, 2 failed, 3 usage error.
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys

from .receipt import MeshError
from .sealed import verify_sealed


def _file_resolver(root: pathlib.Path):
    def resolve(uri: str):
        name = uri.rsplit("/", 1)[-1]
        path = root / name
        if not path.is_file():
            raise FileNotFoundError(path)
        return json.loads(path.read_text(encoding="utf-8"))
    return resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="avm-mesh")
    sub = parser.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify a sealed settlement receipt")
    v.add_argument("receipt")
    v.add_argument("--evidence", default=".", help="directory holding proofpacks")
    v.add_argument("--genesis", default=None,
                   help="pinned genesis hash b64 (strongly recommended)")
    v.add_argument("--voters-commitment", default=None,
                   help="trusted voters commitment b64 (required for LEVEL 3)")
    v.add_argument("--ln-proven-weight", type=int, default=None,
                   help="proven-weight bound matching --voters-commitment")
    v.add_argument("--json", action="store_true", help="machine-readable output")

    args = parser.parse_args(argv)
    if args.cmd != "verify":
        parser.print_help()
        return 3

    try:
        sealed = json.loads(pathlib.Path(args.receipt).read_text(encoding="utf-8"))
        anchor = None
        if (args.voters_commitment is None) != (args.ln_proven_weight is None):
            print("--voters-commitment and --ln-proven-weight are required together",
                  file=sys.stderr)
            return 3
        if args.voters_commitment is not None:
            from avm_proofpack.verify import TrustedVoters

            try:
                vc = base64.b64decode(args.voters_commitment, validate=True)
            except Exception:
                print("--voters-commitment is not valid base64", file=sys.stderr)
                return 3
            if len(vc) != 64:
                print("--voters-commitment must decode to 64 bytes", file=sys.stderr)
                return 3
            anchor = TrustedVoters(voters_commitment=vc,
                                   ln_proven_weight=args.ln_proven_weight)

        result = verify_sealed(
            sealed,
            _file_resolver(pathlib.Path(args.evidence)),
            trusted_voters=anchor,
            expected_genesis_hash_b64=args.genesis,
        )
    except MeshError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"FAILED: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"cannot read receipt: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"ok": True, **{k: result[k] for k in
                                        ("levels", "trust_root", "attested_txid",
                                         "attested_round")}}))
    else:
        lv = result["levels"]
        print(f"integrity:   {'PASS' if lv['integrity'] else 'FAIL'}")
        print(f"signature:   {lv['signature']}")
        print(f"consensus:   {lv['consensus']}")
        print(f"trust root:  {result['trust_root']}")
        if result["attested_txid"]:
            print(f"attested:    {result['attested_txid']} @ round {result['attested_round']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
