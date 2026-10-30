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


def _make_signature_verifier(pubkey_b64: str):
    """LEVEL 2: the operator's Falcon-1024 signature over the content hash.

    Uses avm_proofpack's own verifier rather than `pqcrypto`. Two reasons: it is
    stdlib-only, so LEVEL 2 needs no third-party package in the trust base; and
    `pqcrypto` 1.0.0 no longer ships Falcon at all (its sign subpackage lists
    ML-KEM, ML-DSA, SLH-DSA, McEliece, HQC and SNTRUP), so the previously
    documented `pip install pqcrypto` path now fails on import.

    ``falcon1024_verify`` returns a bool rather than raising, so the return value
    must be checked -- an unchecked call reads as success for any signature.
    """
    import base64 as _b64
    import hashlib as _h

    from avm_proofpack.consensus.falcon import falcon1024_verify

    try:
        pubkey = _b64.b64decode(pubkey_b64, validate=True)
    except Exception as exc:
        raise ValueError("operator public key is not valid base64") from exc

    def verify(content_bytes: bytes, signature: dict) -> bool:
        if not isinstance(signature, dict) or "sig_b64" not in signature:
            raise ValueError("signature object has no sig_b64")
        sig = _b64.b64decode(signature["sig_b64"], validate=True)
        # The rails receipt signs the content HASH, not the bytes.
        digest = _h.sha256(content_bytes).digest()
        return bool(falcon1024_verify(pubkey, digest, sig))

    return verify


def _serve(args) -> int:
    """Run the witness service until interrupted.

    The witness card is published only when every field it needs is supplied. A
    partial card would advertise an anchor the witness does not hold, so a
    half-specified witness serves the store and says so rather than guessing.
    """
    from .service import Store, WitnessInfo, serve_forever

    try:
        store = Store(args.root)
    except MeshError as exc:
        print(f"cannot open store at {args.root}: {exc}", file=sys.stderr)
        return 3

    card_fields = {
        "witness_id": args.witness_id,
        "operator_id": args.operator_id,
        "chain": args.chain,
        "escrow_txid": args.escrow_txid,
        "anchor_voters_commitment_b64": args.anchor_voters_commitment_b64,
        "anchor_ln_proven_weight": args.anchor_ln_proven_weight,
    }
    supplied = [k for k, v in card_fields.items() if v is not None]
    info = None
    if supplied and len(supplied) != len(card_fields):
        # Fail closed. Starting a witness whose identity is half-configured is how
        # an operator ends up attesting under a card that is not what they meant;
        # the error is cheap here and expensive later.
        missing = sorted(set(card_fields) - set(supplied))
        print(f"incomplete witness card: missing {', '.join(missing)}", file=sys.stderr)
        return 3
    elif supplied:
        try:
            info = WitnessInfo(**card_fields)
        except MeshError as exc:
            print(f"invalid witness card: {exc}", file=sys.stderr)
            return 3

    print(f"serving store {args.root} on http://{args.host}:{args.port}", file=sys.stderr)
    try:
        serve_forever(store, host=args.host, port=args.port, info=info)
    except OSError as exc:
        print(f"cannot bind {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 0
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """The one place the CLI is defined, so tests can inspect it without running it."""
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
    v.add_argument("--operator-pubkey-b64", default=None,
                   help="operator Falcon-1024 public key, to check LEVEL 2")
    v.add_argument("--json", action="store_true", help="machine-readable output")

    s = sub.add_parser("serve", help="run a witness service over a content-addressed store")
    s.add_argument("--root", required=True, help="directory holding the store")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--witness-id", default=None)
    s.add_argument("--operator-id", default=None)
    s.add_argument("--chain", default=None)
    s.add_argument("--escrow-txid", default=None)
    s.add_argument("--anchor-voters-commitment-b64", default=None)
    s.add_argument("--anchor-ln-proven-weight", type=int, default=None)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        return _serve(args)
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
