# avm-mesh

Settlement receipts for the Algorand/Voi mesh.

A bridge is a separate system bolted onto two chains: its own validator set, its own token, its own
contracts, its own hosting, and therefore its own attack surface. `avm-mesh` takes the opposite
position — **the node set is the interop layer**. A node on the source chain produces evidence for free
because it already holds the full block. A node on the destination chain verifies that evidence because
it *cannot* see those blocks. Nothing new needs to be trusted; the asymmetry is the protocol.

## The problem with what exists

Every other cross-chain message answers "who says this happened?" with "us". Wormhole says the
Guardians, Axelar says its validator set, LayerZero says its DVNs. You are asked to trust a new
federation that did not previously exist, and to run it you must be online, because verification is a
query against someone else's indexer.

`avm-proofpack` answers with a Falcon-1024 state proof — Algorand and Voi sign their consensus state
with a NIST-selected post-quantum scheme, and a state proof verifies offline against the genesis hash.
No indexer, no RPC, no federation, and PQC by construction rather than by roadmap.

## What a receipt is

A settlement receipt is what actually moves between meshes. It is deliberately tiny:

```json
{
  "version": 1,
  "chain": "mainnet-v1.0",
  "txid": "J6FPFF4CKP4XUWUEDLEENV7EV5YDKFZHZJC6UYYWBDVBJLAT7IIA",
  "round": 66457600,
  "trust_root": "stake_attested",
  "pointer": {
    "uri": "ipfs://.../proofpack.json",
    "digest": "9f2c...",
    "first_attested_round": 66457345,
    "last_attested_round": 66457600
  },
  "corroboration": []
}
```

The proofpack itself is 428–834 KB, so it is **stored once per attested interval**, never per
transaction. The receipt commits to it by digest and points at it.

### Three properties, each enforced rather than documented

1. **Substitution.** The receipt commits to the bundle by SHA-256 over canonical JSON. Swapping the
   bundle behind the pointer changes the digest and the receipt is refused.
2. **Upgrade.** The receipt carries the tier the bundle *earned*. The verifier re-derives that tier and
   refuses a mismatch **in either direction**, so a structural bundle cannot be advertised as
   `stake_attested`, and an honest verifier cannot quietly accept a weaker claim than the evidence
   supports.
3. **Identity.** Chain, txid and round are taken from verification, not from the caller. A perfectly
   valid bundle for a different transaction is not evidence for this one.

Pass `expected_genesis_hash_b64` to pin the chain itself:

```python
verify_receipt(receipt, resolve=storage.read, trusted_voters=anchor,
               expected_genesis_hash_b64="wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=")
```

Without it, `receipt.chain` is only checked against the bundle's genesis **id** — a string a fork can
reuse. With it, the hash is enforced against the authenticated block header, which no evidence author
can choose. The receipt's claimed attested interval must also equal the interval the evidence actually
attests; otherwise a receipt can point at a real proofpack covering a different interval and still read
as verified.

```python
from avm_mesh import create_receipt, verify_receipt

receipt = create_receipt(bundle, "ipfs://.../proofpack.json")
report = verify_receipt(receipt, resolve=my_storage.read, expected_chain="mainnet-v1.0")
assert report.trust_root == "stake_attested"
```

`resolve` is caller-supplied, so storage is agnostic: a file, an HTTP endpoint, a chain.


## LEVEL 3: consensus attestation for the rails receipt

The AlgoVoi Payment Rails receipt already has two levels:

| Level | Checks |
|---|---|
| 1 | `sha256(canonical_bytes) == content_hash` |
| 2 | the **operator's** Falcon-1024 signature over that hash |

LEVEL 2 proves *"AlgoVoi issued this receipt"*. It cannot prove the settlement happened as described,
because the issuer could sign anything. **LEVEL 3** closes that: evidence that the transaction was
final, verified against chain consensus, with **no operator key in the trust base**.

```python
from avm_mesh import attest, verify_attestation

# `anchor` is YOUR trust anchor: a TrustedVoters the caller supplies.
receipt["consensus_attestation"] = attest(bundle, "ipfs://.../proofpack.json",
                                          trusted_voters=anchor).to_dict()

verify_attestation(receipt["consensus_attestation"], resolve=my_storage.read,
                   trusted_voters=anchor,                       # must match the recorded anchor
                   expected_genesis_hash_b64=ALGORAND_GENESIS_B64)
```

### The anchor is mandatory, and that is the point

The signing set for a state proof is committed by the voters commitment published **one interval
earlier**. A single bundle cannot authenticate that commitment — it carries it only as an unverified
`previous_state_proof_message`, which the bundle's own author chooses. Deriving trust from it means a
bundle can name itself as the sole signer and mint a valid-looking `stake_attested` tier.

So the anchor comes from **you**: a pinned genesis bootstrap, a chain walk
(`avm_proofpack.consensus.chain`), or a node you already trust at a known round. Never from the bundle
you are verifying. `trusted_voters` is required by `attest()` and by `verify_attestation()`, which also
checks the anchor against the one the attestation recorded — passing an attestation its own anchor
would verify nothing.

The scheme string is `avm-stateproof-falcon1024-v2`. **v1 attestations are refused by name**, because
their semantics were forgeable and must not be accepted as equivalent.

Because the attestation lives inside the receipt's canonical bytes, it is covered by LEVEL 1 and
LEVEL 2 — it cannot be swapped or stripped without breaking the content hash.

**`attest()` refuses rather than downgrades.** If the evidence does not reach `stake_attested`, no
attestation is emitted at all; shipping a weaker block would let a receipt *look* consensus-backed
while carrying an operator's word.

**Pin the genesis hash.** Without `expected_genesis_hash_b64` the attestation is self-referential —
it states its own anchor and then agrees with itself, which is no stronger than LEVEL 2.

**Only Algorand and Voi.** `ConsensusAttestation` rejects any other chain at construction. Hedera,
Stellar, Base, Solana and Tempo have no state proofs, and a receipt for them stays honestly at
LEVEL 2.

## Seal it and verify it from the command line

```sh
python -m avm_mesh verify receipt.json --evidence ./proofpacks \
    --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
    --voters-commitment <trusted-voters-commitment-b64> \
    --ln-proven-weight <proven-weight>
```

```
integrity:   PASS
signature:   None
consensus:   stake_attested
trust root:  stake_attested
attested:    J6FPFF4CKP4XUWUEDLEENV7EV5YDKFZHZJC6UYYWBDVBJLAT7IIA @ round 66457600
```

The anchor flags are required whenever the receipt carries a consensus attestation: supply the
`TrustedVoters` commitment and proven weight you independently trust. A sealed receipt with a LEVEL 3
block verifies against that anchor and fails closed without it — never from the bundle's own word. The
genesis pin is likewise enforced against the *authenticated* state-proof header, not the attestation's
self-declared field.

Exit `0` verified, `2` failed, `3` usage. `--json` for machine output. A real receipt is **945 bytes**
against an 854 KB proofpack; the proof is stored once per attested interval, not per payment.

Sealing binds the attestation into the hashed bytes:

```python
from avm_mesh import seal
receipt = seal({"settlement": {...}, "issuer": "..."}, bundle, "file://proofpack.json")
```

## A2A: settlement evidence between agents

A2A is the transport agents already use, and you are an A2A Partner with TCK standing, so this is the
route that reaches peers rather than requiring them to adopt an SDK.

```python
from avm_mesh import a2a
card = a2a.advertise(my_agent_card)          # declare the extension
artifact = a2a.as_artifact(sealed_receipt)   # evidence as an ordinary Artifact
result = a2a.verify_artifact(artifact, resolve=my_storage.read,
                             expected_genesis_hash_b64=GENESIS)
```

The extension is **optional** (`required: false`), so peers without it still interoperate and simply
fall back to whatever they trusted before. The URI is the versioning boundary — semantics behind a
published URI never change; publish a v2 instead.

**No evidence is an error, not an empty pass.** An artifact without the extension payload raises rather
than returning a vacuous success, because "verified nothing and reported OK" is how receivers end up
believing they checked something.

## Witnesses are bonded, and that is the whole point

A state proof says what the chain did. A witness is whoever hands you the proof. Without a bond a
witness can withhold, delay or selectively serve evidence **at zero cost** — and "decentralised
because node operators run it" becomes a centralised service with a bigger logo.

```python
from avm_mesh.bond import witnesses

ws = witnesses(w("w1", "op-a"), w("w2", "op-b"), w("w3", "op-c"))
quorum = ws.require_corroboration("mainnet-v1.0", threshold=2)
ws.slashable_stake("mainnet-v1.0")   # what one lie could actually cost
```

Two claims are kept strictly apart:

| Claim | Meaning |
|---|---|
| `bond_microalgo` + `escrow_txid` | economic stake that can be slashed — verifiable on-chain |
| `operator_id` | who runs the witness — **not** a trust source, only an independence input |

**Independence is enforced, not assumed.** `independent_corroborators()` counts at most one witness per
operator *and* per escrow, because:

- two endpoints of one operator are one witness wearing two hats — presenting them as a quorum is the
  oldest trick in the attestation playbook;
- two witnesses pointing at one escrow is one bond counted twice, the cheapest possible fake.

`require_corroboration()` **refuses** rather than returning a short list. A caller that cannot reach the
threshold must not be handed fewer corroborators and left to interpret that as success.

The receipt's `corroboration` field is checked against bonds when you ask it to be:

```python
verify_receipt(receipt, resolve=storage.read, witness_set=ws, corroboration_threshold=2)
```

It refuses on four distinct failures — **unknown** witness (no bond record), **unbonded** (absent,
inactive or too small), **duplicated** (same operator or same escrow), **insufficient** (fewer
independent witnesses than the threshold). Omitting these arguments keeps the old behaviour: the claim
is recorded, and the caller should describe it as recorded rather than established.

An unverifiable bond is not a bond: a witness record without an `escrow_txid` is rejected at
construction, as is one with no `operator_id`.

## Trust tiers are per chain, on purpose

Only **Algorand** and **Voi** have Falcon state proofs. Hedera, Stellar, Base, Solana and Tempo do not.
Claiming parity across seven chains would be the same dishonesty as a bridge calling itself
trustless:

| Tier | Means |
|---|---|
| `stake_attested` | offline-verified against a Falcon-signed state proof |
| `corroborated` | several independent observers agree, no consensus proof |
| `structural` | internally consistent, no external anchor |
| `unattested` | no proof material present |

*"Here are the two chains where you get cryptographic proof and the five where you get someone's
word"* is a stronger offer than claiming all seven are equal, because the merchant can check it.

## Status

`0.1.1` — receipt format, verification, LEVEL 3 consensus attestation (anchor-required), and the A2A extension.

**Dependency:** requires `avm-proofpack>=0.4.1` and is verified against **0.4.1 @ `02d2516`**, where the
`stake_attested` tier became anchor-required. `avm-mesh` 0.1.x followed that fix: LEVEL 3 no longer
authenticates from a bundle's own `previous_message`.

Not yet built: wiring LEVEL 3 into the rails bundle's own verifier (it currently lives here), the A2A
settlement extension, and witness bonding.

## Honest limits

- **A receipt is not a proof of delivery.** It proves a transaction was final and what it did. Whether
  goods shipped is not an on-chain fact.
- **Corroboration is a capture-time property.** It cannot be established after the fact, and two
  endpoints run by one operator are not independent witnesses. It is recorded, not counted.
- **Capture is time-sensitive.** Nodes retain roughly two state-proof intervals (~512 rounds, ~20
  minutes). Miss that window and the bundle falls back to `unattested`.
- **Falcon verification is only as good as the genesis hash** you pin. Ship it in your application,
  not fetched over the wire.

Apache-2.0.
