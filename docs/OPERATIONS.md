# Operating a mesh witness

Everything a deployment needs, in the order it's needed. The short version: **you own two things** — an
anchor you obtained yourself, and a policy that pins it. Everything else is mechanism.

## 1. Obtain an anchor, independently

The signing set for a state proof is committed one interval earlier. A bundle carries that earlier
message, but the bundle's author writes it — deriving trust from it is self-attestation. So get the
anchor from somewhere you already trust:

- a **chain walk** of state proofs from a pinned genesis bootstrap
  (`avm_proofpack.consensus.chain`), or
- a node you trust, at a known round.

Never read it out of the bundle you are about to verify. If you did, every later check would be
confirming the bundle against itself.

## 2. Write a policy

One JSON document holding every pin. Commit it to your deployment repo and review changes to it like
code, because changing it changes what you accept.

```json
{
  "chain": "mainnet-v1.0",
  "genesis_hash_b64": "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
  "anchor_voters_commitment_b64": "<64 bytes, base64>",
  "anchor_ln_proven_weight": 2230418,
  "corroboration_threshold": 0,
  "witnesses": []
}
```

`require_witness_coverage()` refuses a policy asking for more independent witnesses than are bonded, so
a mistake fails at load rather than on every request months later.

## 3. Run a witness

```sh
avm-mesh serve --root /var/lib/avm-mesh --port 8080 \
  --witness-id w1 --operator-id op-a --escrow-txid <bond escrow txid>
```

The witness is a **courier**. It serves receipts and content-addressed proofpacks; it decides nothing.
If it lies about which proofpack it serves, the digest in the receipt catches it. Stored blobs are
re-hashed on read, and corruption returns `500` rather than `404` — a fault is not an absence.

## 4. Verify

```sh
avm-mesh verify receipt.json --evidence ./proofpacks \
  --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
  --voters-commitment <b64> --ln-proven-weight <n>
```

Exit `0` verified, `2` failed, `3` usage. `--json` for machines. Add `--operator-pubkey-b64` to also
check LEVEL 2 (the operator's Falcon-1024 signature over the content hash).

## What each pin buys you

| Pin | Stops |
|---|---|
| genesis hash, against the signed header | a fork reusing a chain id string |
| voters anchor | a bundle naming itself the sole signer |
| evidence digest | substituting a different bundle behind a pointer |
| attested interval | pointing at a real proofpack that covers a different interval |
| txid + round | reusing valid evidence for a different settlement |
| trust tier equality | advertising a stronger claim than the evidence earns |
| witness bonds + operator ids | counting one stake twice as a quorum |

## Failure modes, by design

Everything fails closed, and the refusal names the check that failed:

- evidence below `stake_attested` → nothing published (never a downgraded receipt)
- malformed or hostile input → `MeshError`, never a pass and never a hang
- unresolvable pointer, digest mismatch, wrong chain, wrong interval → refused
- a corroboration threshold with no witness set → error, not a silent skip

## Two operational realities

**Capture is time-sensitive.** Nodes retain roughly two state-proof intervals (~512 rounds, ~20
minutes). Miss the window and the previous interval is pruned: the bundle still verifies structurally
but cannot reach `stake_attested`.

**Only Algorand and Voi.** Hedera, Stellar, Base, Solana and Tempo have no Falcon state proofs. Their
receipts stay honestly at LEVEL 2, and `ConsensusAttestation` refuses them at construction rather than
inheriting a tier they cannot earn.

## Sizing

A receipt is ~945 bytes against an 854 KB proofpack: the proof is stored once per attested interval and
referenced by digest, never inlined per payment.
