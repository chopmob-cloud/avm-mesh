"""Exercise `avm-mesh serve` end to end against an INSTALLED avm-mesh.

Run this inside a container or venv where avm-mesh came from the index, not from
the source tree: the point is to check the artefact a stranger gets, including
the witness card, receipt round trip, the append-only guard and the
path-traversal refusal.

    python tools/exercise_serve.py [--port 8099] [--root DIR]

Every probe is checked and reported. A run that merely prints is not a test: this
exits non-zero when a probe misbehaves, so it can be used in CI and by a stranger
without them having to eyeball the output.

Exit codes: 0 every probe behaved, 1 a probe did not, 2 could not run.
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_PORT = 8099
FAILURES: list[str] = []


def _check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{('  ' + detail) if detail else ''}")
    if not ok:
        FAILURES.append(label)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Exercise `avm-mesh serve` end to end against an installed package.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port to bind (default {DEFAULT_PORT})")
    parser.add_argument("--root", type=pathlib.Path, default=None,
                        help="store directory (default: a fresh temporary one)")
    args = parser.parse_args(argv)

    root = args.root or pathlib.Path(tempfile.mkdtemp(prefix="serve-rt-"))
    anchor = base64.b64encode(bytes(range(32))).decode()
    # Prefer the installed console script: that is the artefact a stranger gets, and
    # `python -m avm_mesh` would not catch a broken entry point (the 0.4.2 release
    # shipped without one). Fall back to the module only when the script is absent, so
    # the tool still works from a source checkout.
    console = shutil.which("avm-mesh")
    launcher = [console] if console else [sys.executable, "-m", "avm_mesh"]
    if not console:
        print("note: `avm-mesh` is not on PATH; falling back to `python -m avm_mesh`, "
              "which does NOT exercise the console script")
    cmd = [*launcher, "serve", "--root", str(root),
           "--port", str(args.port),
           "--witness-id", "w1", "--operator-id", "op-a", "--chain", "voi",
           "--escrow-txid", "ESCTXID",
           "--anchor-voters-commitment-b64", anchor,
           "--anchor-ln-proven-weight", "2230418"]

    print(f"store:  {root}")
    print(f"port:   {args.port}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{args.port}"

    def get(path: str):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except (urllib.error.URLError, ConnectionError, OSError):
            return 0, b""

    # The server is a child process. Any exception below must still stop it, or a
    # failed run leaves a bound port behind and the next run fails for the wrong
    # reason.
    try:
        ready = False
        for _ in range(120):
            # A child that has already exited will never serve a request, so report
            # its stderr now rather than retrying 120 times against a dead process
            # and hiding the reason behind a timeout.
            if proc.poll() is not None:
                _, err = proc.communicate(timeout=5)
                print("server exited before it was ready; stderr tail:", file=sys.stderr)
                print(err.decode("utf-8", "replace")[-2000:], file=sys.stderr)
                return 2
            if get("/healthz")[0] == 200:
                ready = True
                break
            time.sleep(0.25)
        if not ready:
            print("server did not answer /healthz within 30s; stderr tail:", file=sys.stderr)
            proc.terminate()
            _, err = proc.communicate(timeout=5)
            print(err.decode("utf-8", "replace")[-2000:], file=sys.stderr)
            return 2

        _check("GET /healthz is 200", get("/healthz")[0] == 200)

        code, body = get("/witness")
        card = json.loads(body) if code == 200 else {}
        _check("GET /witness is 200", code == 200, f"got {code}")
        _check("witness card names the witness", card.get("witness_id") == "w1")
        _check("witness card carries the escrow", card.get("escrow_txid") == "ESCTXID")

        from avm_mesh.receipt import ProofpackPointer, SettlementReceipt
        from avm_mesh.service import Store

        store = Store(root)
        receipt = SettlementReceipt(
            version=1, chain="voi", txid="SERVE-RT" + "A" * 48,
            round=21209088, trust_root="structural",
            pointer=ProofpackPointer(uri="proofpack:" + "0" * 64, digest="0" * 64,
                                     first_attested_round=21208832,
                                     last_attested_round=21209088))
        txid = store.put_receipt(receipt)
        code, body = get("/receipts/" + urllib.parse.quote(txid, safe=""))
        _check("GET /receipts/<txid> is 200", code == 200, f"got {code}")
        got = json.loads(body) if code == 200 else {}
        _check("receipt txid round-trips", got.get("txid") == txid)
        _check("receipt trust_root round-trips", got.get("trust_root") == "structural")

        try:
            store.put_receipt(receipt)
            _check("identical rewrite accepted (idempotent)", True)
        except Exception as exc:  # noqa: BLE001 - reporting, not handling
            _check("identical rewrite accepted (idempotent)", False, type(exc).__name__)

        conflict = SettlementReceipt(version=1, chain="voi", txid=txid, round=21209088,
                                     trust_root="stake_attested", pointer=receipt.pointer)
        try:
            store.put_receipt(conflict)
            _check("conflicting rewrite refused", False, "ACCEPTED -- equivocation hole")
        except Exception as exc:  # noqa: BLE001
            _check("conflicting rewrite refused", True, type(exc).__name__)

        for probe in ("/receipts/../../etc/passwd",
                      "/receipts/%2e%2e%2f%2e%2e%2fetc%2fpasswd"):
            code, _ = get(probe)
            _check(f"traversal refused: {probe[:34]}", code in (400, 404), f"got {code}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        print("server stopped")

    if FAILURES:
        print(f"\n{len(FAILURES)} probe(s) did not behave as expected:")
        for name in FAILURES:
            print(f"  - {name}")
        return 1
    print("\nall probes behaved as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
