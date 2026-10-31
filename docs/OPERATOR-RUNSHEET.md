# Operator run sheet — two artefacts this repository cannot produce for itself

Two stages are blocked on data only an operator can legitimately produce. This
sheet gives the exact commands and the exact checks the receiving side will run,
so the handover is one paste and not a conversation.

---

## A. A second state-proof capture (for `avm-mesh anchor`)

**Why it is needed.** `anchor` walks the voters commitment forward across
intervals. One captured interval proves the walk works. Two adjacent intervals
*published by different operators* prove the walk is not reading one operator's
private view. Only the second claim needs the second capture.

**What to send:** one `.json.gz` state-proof bundle for an interval **adjacent
to or overlapping** the interval in
`tests/fixtures/stake_attested_algorand_66457600.json.gz` (round 66457600,
previous interval 66457344). Any later interval that verifies forward from that
checkpoint is fine.

**How to produce it (Algorand node):**

```sh
# 1. wait for a state-proof interval boundary (every 256 rounds)
# 2. request the proof for the interval that follows your checkpoint
curl -s "http://localhost:8080/v2/blocks/<ROUND>/lightheader/proof" -o proof.json
gzip -c proof.json > stateproof-<ROUND>.json.gz
```

Use a node **you** run, or a public endpoint you already trust; note which one
in the filename or a sidecar `.txt`, because "which node served this" is part of
what the second capture is evidence for.

**What happens on receipt (no ambiguity about pass/fail):**

```sh
avm-mesh anchor \
  --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
  --anchor-round 66457600 \
  --anchor-voters-commitment <base64 from the first capture> \
  --anchor-ln-proven-weight <integer from the first capture> \
  --target-round <ROUND of the new capture> \
  --bundles ./bundles
```

Exit 0 prints `--voters-commitment` and `--ln-proven-weight`; exit 2 means the
walk did not reach the target interval and names the round where it stopped.
There is no third outcome — a wrong checkpoint fails at the first link.

---

## B. A genuine rails receipt (for the `avm_mesh.rails` adapter)

**Why it is needed.** The adapter has already been proven against a
Falcon-1024-signed receipt this repo generated itself (LEVEL 1 PASS, LEVEL 2
`True`, exit 0). What it has not seen is a receipt produced by the rails kit,
which is the tool it is meant to replace. One file closes it.

**What to send:** a single `receipt.json` as emitted by
`verify_settlement_receipt.py`'s producer, with these fields present:

```
canonical_bytes_b64   exact bytes that were hashed
content_hash          sha256(canonical_bytes) in hex
public_key_b64        Falcon-1024 public key
signature.sig_b64     Falcon-1024 signature over the 64-byte hex string
signature.kid / alg   key id and algorithm label
issuer_did            issuer identifier
settlement.tx_id      the settled transaction
```

**If the receipt contains live keys or mnemonics, do not send those.** A rail
receipt should not contain a private key at all; if it does, that is itself a
finding and the file should be sanitised before it leaves the operator.

**What happens on receipt:**

```sh
python -m avm_mesh.rails verify receipt.json \
    --evidence ./proofpacks \
    --genesis <b64> \
    --operator-pubkey-b64 <b64>   # pin the key rather than trusting the embedded one
echo $?                            # 0 verified, 1 not verified, 2 usage
```

The expected result for a genuine receipt is `integrity: PASS` and
`signature: True`. If `signature: present-unverified`, the pin was omitted —
that is consistency, not authenticity.

---

## C. What is *not* accepted

- **Synthesised captures or receipts.** A fabricated fixture would make the
  suite green and the capability false. Anything that cannot be traced to a node
  or a signing operator is refused, even when it passes.
- **A receipt whose `canonical_bytes_b64` was re-encoded after signing.** The
  digest is over the exact bytes; re-serialising JSON to pretty-print it
  breaks LEVEL 1 and that failure is correct.
