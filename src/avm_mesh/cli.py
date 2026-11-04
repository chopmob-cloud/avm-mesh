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


import gzip
import json
import os
import pathlib
import re
import errno
import zlib

#: Anything reachable through `_file_resolver` must collapse to a single path component
#: that is a normal file living directly under the evidence root. The same guard
#: logic as `Store._safe_name`: no traversal, no symlinks, no absurd names.
MAX_PROOF_BYTES_DEFAULT = 8 * 1024 * 1024

#: gzip's two-byte magic, so a compressed proofpack is decoded from its bytes
#: rather than guessed at from its name. Mirrors `anchor.GZIP_MAGIC`.
GZIP_MAGIC = b"\x1f\x8b"

_SAFE_NAME = re.compile(r"\A[A-Za-z0-9_.-]{1,128}\Z")


def read_bounded_bytes(path: pathlib.Path, *, max_bytes: int) -> bytes:
    """Read a file's bytes, refusing a symlink, a non-regular file, or an oversized one.

    Extracted from `_file_resolver` so the read can be tested without a JSON layer in the
    way. That separation matters: the 0x1A truncation bug below could not be reproduced
    through the resolver, because the JSON parser rejected the fixture whether or not the
    read truncated, so every assertion was measuring the parser instead of the reader.

    The `O_BINARY` flag is not decoration. On Windows a descriptor opened without it is in
    text mode, and `os.read` stops at the first 0x1A byte, which is EOF to the C runtime.
    A gzip envelope contains 0x1A early -- the Voi fixture has one at offset 100 of
    110,773 and this function returned exactly 100 bytes -- so a compressed proofpack was
    silently half-read and then failed to decompress with a confusing message. Plain JSON
    never contains 0x1A, so the shipped Algorand example hid the defect completely.
    """
    if path.is_symlink():
        raise FileNotFoundError(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        # Acceptable misses: ENOENT/ENOTDIR/ELOOP/EISDIR/ENAMETOOLONG mean "no readable
        # regular file exists here", and callers catching FileNotFoundError expect that.
        # Permission errors, EMFILE and other I/O failures keep their own type.
        if getattr(exc, "errno", None) in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP,
                                          errno.EISDIR, errno.ENAMETOOLONG):
            raise FileNotFoundError(path)
        raise
    try:
        st = os.fstat(fd)
        if (st.st_mode & 0o170000) != 0o100000:
            raise FileNotFoundError(path)
        if st.st_size > max_bytes:
            raise ValueError(f"{path} is {st.st_size} bytes, over the {max_bytes} byte cap")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(
                f"{path} is at least {len(data)} bytes, over the {max_bytes} byte cap")
        return data
    finally:
        os.close(fd)


def _file_resolver(root: pathlib.Path, *, max_bytes: int | None = None):
    root = pathlib.Path(root).absolute()
    if max_bytes is None:
        max_bytes = MAX_PROOF_BYTES_DEFAULT

    def resolve(uri: str):
        name = uri.rsplit("/", 1)[-1]
        if not _SAFE_NAME.match(name) or name in (".", ".."):
            raise FileNotFoundError(uri)
        path = root / name
        data = read_bounded_bytes(path, max_bytes=max_bytes)

        # A proofpack may be gzipped. The Voi example ships as `.json.gz`, and without
        # this the CLI could not verify it at all: the reader hit a UTF-8 error on the
        # gzip header. The magic bytes decide, not the filename, matching
        # `anchor.load_bundle` -- a capture compressed and left with a `.json` name is a
        # real accident, and the reverse is a name that lies about its contents.
        if data[:2] == GZIP_MAGIC:
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError, zlib.error) as exc:
                raise ValueError(f"{path} is not a readable gzip stream: {exc}")
            if len(data) > max_bytes:
                raise ValueError(
                    f"{path} expands past the {max_bytes} byte cap; refusing to parse it")
        elif path.suffix == ".gz":
            raise ValueError(f"{path} is named .gz but does not begin with gzip data")

        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{path} is not valid UTF-8 JSON: {exc}")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise json.JSONDecodeError(f"{path}: {exc.msg}", exc.doc, exc.pos) from exc
    return resolve


def _make_signature_verifier(pubkey_b64: str, *, hex_digest: bool = False):
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
        try:
            sig = _b64.b64decode(signature["sig_b64"], validate=True)
        except Exception as exc:
            raise ValueError("signature sig_b64 is not valid base64") from exc
        # Two conventions exist in this estate and they are NOT interchangeable:
        # this package seals over the raw 32-byte digest, while the rails bundle
        # signs sha256(...).hexdigest().encode() -- 64 ASCII bytes. Verifying one
        # with the other's convention rejects every genuine artefact, so the
        # entry point chooses rather than the verifier guessing.
        digest = (_h.sha256(content_bytes).hexdigest().encode("utf-8")
                  if hex_digest else _h.sha256(content_bytes).digest())
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
        store = (Store(args.root, max_proofpack_bytes=args.max_proofpack_bytes)
                 if args.max_proofpack_bytes else Store(args.root))
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
    limits = {}
    if args.rate_limit is not None:
        limits["rate_limit"] = args.rate_limit
    if args.rate_window is not None:
        limits["rate_window_s"] = args.rate_window
    if args.max_connections is not None:
        limits["max_connections"] = args.max_connections
    try:
        serve_forever(store, host=args.host, port=args.port, info=info, **limits)
    except MeshError as exc:
        print(f"invalid service configuration: {exc}", file=sys.stderr)
        return 3
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
    s.add_argument("--max-proofpack-bytes", type=int, default=None,
                   help="refuse to store or serve a proofpack larger than this")
    s.add_argument("--rate-limit", type=int, default=None,
                   help="requests per client per window (default 120)")
    s.add_argument("--rate-window", type=float, default=None,
                   help="rate-limit window in seconds (default 10)")
    s.add_argument("--max-connections", type=int, default=None,
                    help="cap on concurrently open connections (default 64)")

    c = sub.add_parser("corroborate",
                       help="ask several witnesses for one receipt and check they agree")
    c.add_argument("--txid", required=True)
    c.add_argument("--witness", action="append", metavar="URL",
                   help="witness base URL; repeat for each witness")
    c.add_argument("--directory", action="append", metavar="URL_OR_PATH",
                   help="mesh directory document, http(s) or a local path; repeatable")
    c.add_argument("--min-operators", type=int, default=2,
                   help="independent operators required (default 2)")
    c.add_argument("--timeout", type=float, default=5.0)
    c.add_argument("--allow-private", action="store_true",
                   help="allow witnesses on private/loopback addresses (local testing only; "
                        "by default a fetched document cannot point you at an internal host)")
    c.add_argument("--json", action="store_true")

    a = sub.add_parser("anchor",
                       help="derive the TrustedVoters anchor by walking state proofs "
                            "forward from a pinned checkpoint")
    a.add_argument("--genesis", required=True, help="pinned genesis hash, base64")
    a.add_argument("--anchor-round", type=int, required=True,
                   help="round whose message you accept as the checkpoint")
    a.add_argument("--anchor-voters-commitment", required=True,
                   help="that interval's voters commitment, base64 (64 bytes)")
    a.add_argument("--anchor-ln-proven-weight", type=int, required=True)
    a.add_argument("--target-round", type=int, required=True)
    a.add_argument("--bundles", required=True,
                   help="directory of <round>.json or <round>.json.gz captures")
    a.add_argument("--interval", type=int, default=256)
    a.add_argument("--json", action="store_true")

    return parser


def _anchor(args) -> int:
    """Walk from the checkpoint to the target and print the anchor it derives."""
    from .anchor import walk

    try:
        result = walk(genesis_hash_b64=args.genesis, anchor_round=args.anchor_round,
                      voters_commitment_b64=args.anchor_voters_commitment,
                      ln_proven_weight=args.anchor_ln_proven_weight,
                      target_round=args.target_round, bundles=args.bundles,
                      interval=args.interval)
    except MeshError as exc:
        print(f"cannot walk the chain: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif result.ok:
        print(f"authenticated {result.links_verified} interval(s) from the checkpoint")
        print(f"target round:        {result.target_round}")
        print(f"--voters-commitment  {result.voters_commitment_b64}")
        print(f"--ln-proven-weight   {result.ln_proven_weight}")
        print("trust basis:         pinned checkpoint; every interval verified forward from it")
    else:
        print(f"NOT AUTHENTICATED: {result.failure}", file=sys.stderr)
    return 0 if result.ok else 2


def _corroborate(args) -> int:
    """Collect from every witness and report agreement, or the reason there is none."""
    from .corroborate import collect
    from .directory import load_directory, urls_from_directories

    urls = list(args.witness or [])
    hints: dict[str, dict] = {}
    try:
        for source in args.directory or []:
            entries = load_directory(source, timeout=args.timeout,
                                     allow_private=args.allow_private)
            for entry in entries:
                url = entry["url"]
                if url not in urls:
                    urls.append(url)
                hints[url] = {k: v for k, v in entry.items() if k != "url"}
        if not urls:
            print("corroborate needs --witness or --directory", file=sys.stderr)
            return 3
        result = collect(args.txid, urls, min_operators=args.min_operators,
                         timeout=args.timeout, hints=hints,
                         allow_private=args.allow_private)
    except MeshError as exc:
        print(f"cannot corroborate: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for view in result.views:
            state = "COUNTED" if view.counts else "not counted"
            detail = view.problem or f"tier={view.trust_root} round={view.round}"
            print(f"  {view.url:<40} {state:<11} {detail}")
        print(f"operators: {', '.join(result.operators) or 'none'} "
              f"(need {result.min_operators})")
        if result.agreed:
            print(f"AGREED on proofpack {result.agreed_digest}")
        else:
            for problem in result.problems:
                print(f"  ! {problem}")
            print("NOT AGREED")

    return 0 if result.agreed else 2


def main(argv: list[str] | None = None, *, signature_style: str = "raw") -> int:
    """Entry point. ``signature_style`` selects the LEVEL 2 signing convention.

    "raw" (default) is this package's own: the operator signs the 32-byte digest.
    "hex" is the rails bundle's: the operator signs the 64-byte hex string. The
    rails entry point passes "hex"; getting this wrong rejects every genuine
    receipt of the other kind, silently and completely.
    """
    if signature_style not in ("raw", "hex"):
        raise ValueError(f"unknown signature_style {signature_style!r}")
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 for a usage error, but this CLI documents 3 and the rails
        # drop-in maps 3 -> 2 to match the tool it replaces. Letting argparse's own 2
        # through made that mapping unreachable: a genuine usage error was
        # indistinguishable from a failed verification in the rails exit space.
        if exc.code == 2:
            return 3
        raise
    if args.cmd == "serve":
        return _serve(args)
    if args.cmd == "corroborate":
        return _corroborate(args)
    if args.cmd == "anchor":
        return _anchor(args)
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

        verify_signature = None
        if args.operator_pubkey_b64 is not None:
            try:
                verify_signature = _make_signature_verifier(
                    args.operator_pubkey_b64, hex_digest=(signature_style == "hex"))
            except ValueError as exc:
                print(f"--operator-pubkey-b64: {exc}", file=sys.stderr)
                return 3
            if not isinstance(sealed.get("signature"), dict):
                # The caller asked for LEVEL 2. Reporting "present-unverified" and
                # exiting 0 would mean the requested check silently did not happen.
                print("--operator-pubkey-b64 was supplied but the receipt carries no "
                      "signature to check", file=sys.stderr)
                return 2

        result = verify_sealed(
            sealed,
            _file_resolver(pathlib.Path(args.evidence)),
            trusted_voters=anchor,
            expected_genesis_hash_b64=args.genesis,
            verify_signature=verify_signature,
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
    except ValueError as exc:
        # json.JSONDecodeError is a ValueError; a malformed file is the caller's
        # problem, so it is a clean usage failure rather than a crash.
        print(f"receipt is not valid JSON: {exc}", file=sys.stderr)
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
