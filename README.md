# avm-mesh

Settlement receipts for the Algorand/Voi mesh.

A bridge is a separate system bolted onto two chains: its own validator set, its own token, its own
contracts, its own hosting, and therefore its own attack surface. `avm-mesh` takes the opposite
position — **the node set is the interop layer**. A node on the source chain produces evidence for free
because it already holds the full block. A node on the destination chain verifies that evidence because
it *cannot* see those blocks. Nothing new needs to be trusted; the asymmetry is the protocol.

## Install

```sh
pip install avm-mesh            # pulls avm-proofpack and avm-effectproof
```

Python 3.10+. No runtime dependencies beyond the AVM proofpack stack, and no service to reach: verification
is offline.

```pycon
>>> from avm_mesh import verify_receipt
>>> verify_receipt(receipt, resolve=storage.read, trusted_voters=anchor,
...                expected_genesis_hash_b64=ALGORAND_MAINNET)["trust_root"]
'stake_attested'
```

Three commands ship with it:

| Command | What it does |
|---|---|
| `avm-mesh verify` | offline verification of one receipt, reporting each level separately |
| `avm-mesh serve` | run a witness over a content-addressed store |
| `avm-mesh anchor` | derive the `TrustedVoters` anchor by walking state proofs from a pinned checkpoint |
| `avm-mesh corroborate` | ask several witnesses for one receipt and check they agree |

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



## Post-quantum dependency

Falcon-1024 is verified with `avm_proofpack.consensus.falcon` (stdlib-only). `pqcrypto` 1.0.0 removed
Falcon entirely when it migrated off the now-archived PQClean, so `pip install pqcrypto` no longer
provides a Falcon verifier. Why, what replaces it, and what remains unproven:
**`docs/PQC-FALCON.md`**.

## The framework, end to end

| Component | Role |
|---|---|
| `produce` | settler side: store evidence, then seal a receipt |
| `service` | **witness**: serves receipts and content-addressed proofpacks |
| `receipt` | digest + pointer, three enforced bindings |
| `attestation` | LEVEL 3 consensus attestation, anchor-required |
| `sealed` | wire format the rails already speak |
| `trust` | one auditable policy holding every pin |
| `bond` | witness bonds and enforced independence |
| `a2a` | settlement-evidence extension |
| `cli` | offline verifier, `avm-mesh verify` / `avm-mesh serve` / `avm-mesh corroborate` |

A deployment needs two things to be safe: an **anchor** it obtained itself, and a **policy** that pins
chain, genesis hash, anchor and witness set in one document. Everything else is mechanism.

```sh
# a witness publishes evidence
avm-mesh serve --root ./store --port 8080 --witness-id w1 --operator-id op-a --escrow-txid ESC

# a merchant verifies a receipt against its own policy
avm-mesh verify receipt.json --evidence ./proofpacks \
    --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
    --voters-commitment <b64> --ln-proven-weight <n>
```

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
avm-mesh verify receipt.json --evidence ./proofpacks \
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

Run a witness over a store you control:

```sh
avm-mesh serve --root ./store --port 8080 \
    --witness-id w1 --operator-id op-a --chain mainnet-v1.0 --escrow-txid ESCROW \
    --anchor-voters-commitment-b64 <trusted-voters-commitment-b64> \
    --anchor-ln-proven-weight <proven-weight>
```

The service is bounded by default: a proofpack over 8 MiB is refused (both at store time and on serve), a
request path over 2048 characters gets 414, more than 120 requests per client per 10 s gets 429 with
`Retry-After`, and a connection that stalls mid-request is dropped after 10 s.

**Behind a reverse proxy these limits key on the socket peer address**, which is the proxy, not the client.
Every user then shares one quota, and forwarded-client headers are deliberately ignored because trusting them
lets anyone spoof a fresh bucket per request. If you deploy behind a proxy, raise `--rate-limit` for the shared
quota or rate-limit per client at the proxy itself, and treat that as your responsibility rather than ours. Operators can tune these with
`--max-proofpack-bytes`, `--rate-limit` and `--rate-window`. The defaults exist so a witness cannot be used
as a free amplifier or a slowloris cushion.

The witness card is optional but all-or-nothing: supply some identity flags and not others and it refuses to
start (exit 3) rather than publish a card that is not what you configured. A witness with no card at all
serves the store and can never be counted toward corroboration, because an endpoint that will not say who
operates it is not an independent voice.

Sealing binds the attestation into the hashed bytes:

```python
from avm_mesh import seal
receipt = seal({"settlement": {...}, "issuer": "..."}, bundle, "file://proofpack.json")
```

### Verify a real mainnet receipt

`examples/` holds a receipt and the proofpack it points at, both from real Algorand mainnet evidence
(payment `J6FPFF4CKP4XUWUEDLEENV7EV5YDKFZHZJC6UYYWBDVBJLAT7IIA`, round 66457600):

```sh
avm-mesh verify examples/receipt-66457600.json --evidence examples \
  --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
  --voters-commitment 71Oh0YaxEA59JIgWUjMmnpz0KG8lWJ2jwXQiTYxp15FulxCMNfHfBMHT/8hyTNv2tMdWZl+YOz8go5DczFfuLw== \
  --ln-proven-weight 2230418
```

```
integrity:   PASS
signature:   None
consensus:   stake_attested
trust root:  stake_attested
attested:    J6FPFF4CKP4XUWUEDLEENV7EV5YDKFZHZJC6UYYWBDVBJLAT7IIA @ round 66457600
```

**What that proves, precisely.** The Falcon signatures, reveal membership, signed weight and coin selection
over that bundle are verified, and you can re-verify them yourself. The anchor in the command above is taken
from the bundle's own previous state-proof message — enough to exercise the tier, but not an independent
anchor, because whoever assembled the bundle chose it.

Derive it instead. `avm-mesh anchor` walks state proofs forward from a checkpoint you pin, verifying every
interval on the way, and prints the flags the verifier needs:

```sh
avm-mesh anchor --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
  --anchor-round 66457344 \
  --anchor-voters-commitment <the checkpoint interval's commitment> \
  --anchor-ln-proven-weight <its proven weight> \
  --target-round 66457600 --bundles ./captures
```

```
authenticated 1 interval(s) from the checkpoint
target round:        66457600
--voters-commitment  71Oh0YaxEA59JIgWUjMmnpz0KG8lWJ2jwXQiTYxp15FulxCMNfHfBMHT/8hyTNv2tMdWZl+YOz8go5DczFfuLw==
--ln-proven-weight   2230418
trust basis:         pinned checkpoint; every interval verified forward from it
```

**What a walk proves, and what it does not.** Every interval from your checkpoint to the target is verified:
Falcon signatures, reveal membership against the voters commitment, signed weight and coin selection. A
checkpoint whose weight is wrong by one, or whose voters commitment is wrong at all, fails at the first link —
both were tested and both are refused.

It does **not** prove the checkpoint itself. A checkpoint is your trust decision, and one that happens to match
an adversary's chosen signing set would be walked successfully. It also does not authenticate the genesis hash:
the dependency documents `ChainAnchor.genesis_hash` as caller bookkeeping, and the state proof carries no
genesis field, so that label is a consistency check on your own bookkeeping — the voters commitment is what the
proofs are actually checked against. Pick the checkpoint from a source you would trust independently; the walk
makes the distance between that decision and the evidence auditable, not the decision itself.

Remove both anchor flags from `verify` and it fails closed. That is deliberate: the tier is never reached
from the bundle's own word.

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

**Uniqueness is enforced; independence is not provable here.** `independent_corroborators()` counts at most one
witness per operator *and* per escrow. That stops the two cheapest fakes — one operator behind several URLs, and
one bond counted twice:

- two endpoints of one operator are one witness wearing two hats — presenting them as a quorum is the
  oldest trick in the attestation playbook;
- two witnesses pointing at one escrow is one bond counted twice, the cheapest possible fake.

What it cannot do is establish that two *distinct* `operator_id` values belong to two genuinely independent
parties. Identity strings are supplied by the witnesses themselves, so colluding operators can claim distinct
ids and satisfy the count. Treat corroboration as a consistency check whose independence rests on how you chose
the witnesses — which is why the bond exists and why the directory is a lead rather than a trust root.
<!-- The list items above continue in the original text. -->

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

## Corroborating across witnesses

A single witness is one operator's word. `avm-mesh corroborate` asks several and decides whether the mesh
agrees:

```sh
avm-mesh corroborate --txid TH2WRFV... \
  --witness https://w1.example.org \
  --witness https://w2.example.net \
  --min-operators 2
```

```
  https://w1.example.org                   COUNTED     tier=stake_attested round=66457600
  https://w2.example.net                   COUNTED     tier=stake_attested round=66457600
operators: op-a, op-b (need 2)
AGREED on proofpack 8f14e45fceea167a5a36dedd4bea2543...
```

Exit codes: `0` agreed, `2` not agreed, `3` bad arguments. `--json` emits the full report.

Instead of listing URLs by hand, point it at a published directory:

```sh
avm-mesh corroborate --txid TH2WRFV... --directory ./mesh-directory.json --min-operators 2
```

```json
{
  "version": 1,
  "witnesses": [
    {"url": "https://w1.example.org", "operator_id": "op-a", "chain": "mainnet-v1.0"},
    {"url": "https://w2.example.net", "operator_id": "op-b", "chain": "mainnet-v1.0"}
  ]
}
```

**A directory is a lead, not a trust root.** Each entry is checked against the witness's own card at
collection time, and a directory that disagrees with a card loses: that witness does not count and the
disagreement is reported. Unknown fields, duplicate URLs, a wrong document version or a non-http URL are
refused outright, because a directory arrives over the network.

What counts, and what deliberately does not:

- **A witness counts only if it publishes an `operator_id`.** Two URLs on one operator are one voice, and
  running an operator twice is the cheapest way to fake a mesh. Independence is counted over operators,
  never over endpoints.
- **The pointer is verified, not trusted.** For each witness the client fetches the proofpack and checks its
  bytes hash to the digest the receipt names. A witness that points at good evidence while serving
  something else is not counted.
- **Disagreement is reported, never averaged.** Different proofpack digests, different rounds or different
  trust tiers each make agreement fail with a named reason.
- **An unreachable or broken witness is a reported view, not an exception.** One silent witness does not
  crash the run, and it does not silently reduce the threshold either.

Corroboration is recorded, not inferred: a receipt's `corroboration` list names the witnesses that returned
it. It is a capture-time property and says nothing about whether those operators are independent — that is
what the check above is for.

## Status

**`0.7.0`** — `pip install avm-mesh`.

**319 tests, 0 skipped**, on both Python **3.12** (clean-room gate on VM2: offline install from wheels only,
audit rule A, red team) and Python **3.10.22** (319 passed), so `Requires-Python: >=3.10` is demonstrated
rather than asserted. GitHub CI runs the same suite with the fixture provisioned and a missing fixture is a
failure, not a skip.

Licence: Apache-2.0 with `LICENSE` and `NOTICE` in the repository, the wheel and the sdist, PEP 639
`License-Expression` metadata, no contradicting classifier — checked inside the built artefacts by
`tools/check_artifacts.py` and in CI. 0.5.0 shipped without either licence file; that is why this gate exists.

Security surface: `tests/test_validation.py` attacks every input path added in 0.6.0 (directory size, nesting,
field types, argument types, service configuration, CLI failure modes). Each guard was mutation-checked — one
of them was silently unpinned until the check exposed it., validated in a fresh
VM2 clean-room container that installs from the built wheels offline and runs against site-packages.

| Piece | State |
|---|---|
| Receipts, three enforced properties, genesis pin | shipped |
| Witness service (`serve`), content-addressed store, append-only receipts | shipped |
| LEVEL 3 consensus attestation, anchor-required | shipped |
| Corroboration across witnesses (`corroborate`) | shipped 0.5.0 |
| Anchor derivation (`anchor`): checkpoint walk over verified intervals | shipped 0.7.0 |
| Witness discovery (`--directory`, `/.well-known/mesh-directory.json`) | shipped 0.6.0 |
| Worked mainnet example (`examples/`) | shipped 0.6.0 |
| Service resource bounds (size cap, rate limit, slowloris timeout) | shipped 0.6.0 |
| A2A settlement-evidence extension (v1.0 wire format) | shipped; parsed by `a2a-sdk` 1.3.0 |
| Rails adoption kit (`avm_mesh.rails`) | shipped; **not round-tripped** against a real rails receipt |
| Witness bonding (`bond.py`) | model only — **no on-chain escrow**, see Honest limits |

**Dependency:** `avm-proofpack>=0.4.1`, where `stake_attested` became anchor-required. LEVEL 3 never
authenticates from a bundle's own `previous_message`, in any version after 0.1.0.

**A2A conformance, precisely:** the TCK runs on this estate (183 passed / 5 failed / 47 skipped at `must`
level against the reference SUT), but those five failures are the reference SUT's own and **no extension
requirements exist in the TCK** (no `EXT-*` ids). So a green TCK run cannot validate extension semantics;
what is proven is that our artifact parses in the reference SDK and that advertising the extension costs
zero protocol conformance. See `docs/A2A-CONFORMANCE.md`.

## Honest limits

- **A receipt is not a proof of delivery.** It proves a transaction was final and what it did. Whether
  goods shipped is not an on-chain fact.
- **Corroboration is a capture-time property.** It cannot be established after the fact, and two
  endpoints run by one operator are not independent witnesses. It is recorded, not counted.
- **Capture is time-sensitive.** Nodes retain roughly two state-proof intervals (~512 rounds, ~20
  minutes). Miss that window and the bundle falls back to `unattested`.
- **Falcon verification is only as good as the genesis hash** you pin. Ship it in your application,
  not fetched over the wire.
- **Bonding is a model, not a market.** `bond.py` enforces independence and threshold arithmetic over
  witness records you supply; it does not read an escrow, and nothing is slashed by this library. On-chain
  bonding needs four decisions we have not invented for you: asset, slash fraction, dispute window, arbiter.
- **The rails adapter has never seen a real rails receipt.** The format and signing convention are pinned
  by tests against the shipped verifier's source, but no receipt produced by that bundle has been verified
  here. Treat 'drop-in' as unproven end to end until one is.
- **LEVEL 2 end-to-end is unproven.** No Falcon-1024 *signer* is installable in this environment, so the
  operator-signature path is tested by substitution and KAT vectors, not by an operator signing for real.

Apache-2.0.
