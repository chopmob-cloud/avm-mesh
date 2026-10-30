"""Exercise `avm-mesh serve` end to end against an INSTALLED avm-mesh.

Run this inside a container or venv where avm-mesh came from the index, not from
the source tree: the point is to check the artefact a stranger gets, including
the console script, the witness card, receipt round trip, the append-only guard
and the path-traversal refusal.

    python tools/exercise_serve.py

Asserts nothing silently -- every line is printed, and a 500 or a 200 where a 404
was expected is visible rather than folded into a pass.
"""
import base64, hashlib, json, subprocess, time, urllib.error, urllib.request

ROOT = "/tmp/store-rt"
subprocess.run(["rm", "-rf", ROOT], check=False)

anchor = base64.b64encode(bytes(range(32))).decode()
cmd = ["avm-mesh", "serve", "--root", ROOT, "--port", "8099",
       "--witness-id", "w1", "--operator-id", "op-a", "--chain", "voi",
       "--escrow-txid", "ESCTXID",
       "--anchor-voters-commitment-b64", anchor,
       "--anchor-ln-proven-weight", "2230418"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
base = "http://127.0.0.1:8099"

def get(path):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()

for _ in range(60):
    try:
        if get("/healthz")[0] == 200:
            break
    except Exception:
        pass
    time.sleep(0.25)

print("GET /healthz ->", get("/healthz")[0])
code, body = get("/witness")
card = json.loads(body) if code == 200 else {}
print("GET /witness ->", code, "| witness_id:", card.get("witness_id"),
      "| escrow:", card.get("escrow_txid"))

from avm_mesh.service import Store
from avm_mesh.receipt import ProofpackPointer, SettlementReceipt

store = Store(ROOT)
content = json.dumps({"settlement": {"tx_id": "SERVE-RT", "chain": "voi"}},
                     sort_keys=True, separators=(",", ":")).encode()
receipt = SettlementReceipt(
    version=1, chain="voi", txid="SERVE-RT" + content.hex()[:8].upper() * 0 + "A" * 48,
    round=21209088, trust_root="structural",
    pointer=ProofpackPointer(uri="proofpack:" + "0" * 64, digest="0" * 64,
                             first_attested_round=21208832, last_attested_round=21209088))
txid = store.put_receipt(receipt)
code, body = get("/receipts/" + txid)
print("GET /receipts/<txid> ->", code, "| bytes:", len(body))
got = json.loads(body)
print("  txid round-trips:", got.get("txid") == txid, "| trust_root:", got.get("trust_root"))

# idempotent rewrite, then a conflicting rewrite must be refused
try:
    store.put_receipt(receipt)
    print("  identical rewrite: accepted (idempotent)")
except Exception as exc:
    print("  identical rewrite: REFUSED", type(exc).__name__)

conflict = SettlementReceipt(version=1, chain="voi", txid=txid, round=21209088,
                             trust_root="stake_attested", pointer=receipt.pointer)
try:
    store.put_receipt(conflict)
    print("  conflicting rewrite: ACCEPTED -- equivocation hole")
except Exception as exc:
    print("  conflicting rewrite: refused", type(exc).__name__)

for probe in ("/receipts/../../etc/passwd", "/receipts/%2e%2e%2f%2e%2e%2fetc%2fpasswd"):
    print(f"traversal {probe[:36]:<38} -> {get(probe)[0]}")

proc.terminate()
try:
    proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    proc.kill()
print("server stopped")
