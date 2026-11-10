# avm-mesh

**Settlement receipts for the Algorand and Voi mesh** — a small, self-contained proof that a
transaction really settled, which anyone can check offline without trusting the platform that issued it.

When two parties settle a payment across chains or platforms, each one may later need to answer a simple
question: *what actually happened, and can you prove it without my trusting your systems or you trusting
mine?* `avm-mesh` answers it with a **settlement receipt** — a tiny digest-and-pointer that resolves to
cryptographic evidence anchored in the chain's own consensus. A third party who was not present, and who
trusts neither counterparty, can verify that receipt offline against a genesis hash they pinned themselves.

And they need not take one server's word for the anchor either: `avm-mesh crossnode` asks several unrelated
node operators about the same attested interval and requires them to agree, so a single operator serving a
consistent fiction is caught rather than believed.

For the fuller rationale — and the gaps that still sit between a receipt format and fully decentralised
agentic commerce — see [`docs/WHY.md`](docs/WHY.md). For what is and is not proven yet, see
[Honest limits](#honest-limits) at the end.

## How this differs from a bridge

Most cross-chain systems are a separate layer bolted onto two chains: their own validators, token,
contracts and hosting — and therefore their own attack surface. Ask one "who says this happened?" and the
answer is "us": Wormhole's Guardians, Axelar's validator set, LayerZero's DVNs. You have to trust a
federation that did not exist before, and you have to be online to check anything, because verification is
a query against someone else's indexer.

`avm-mesh` takes a different line: **the chain's own node set is the interoperability layer.** A node on
the source chain can produce evidence essentially for free, because it already holds the full block. A node
on the destination chain can verify that evidence precisely *because* it cannot see those blocks itself.
Nothing new has to be trusted — the proof rests on the source chain's consensus.

That proof is a **Falcon-1024 state proof**. Algorand and Voi sign their consensus state with Falcon-1024,
a post-quantum signature scheme selected by NIST, and such a state proof verifies offline against the
chain's genesis hash. No indexer, no RPC, no new federation — and post-quantum security by construction
rather than as a future promise. The proof format itself lives in a companion library, `avm-proofpack`;
`avm-mesh` wraps it into receipts you can exchange and check.

## Install

```sh
pip install avm-mesh            # pulls avm-proofpack and avm-effectproof
```

Python 3.10+. There are no runtime dependencies beyond the AVM proofpack stack, and nothing to connect to:
verification is entirely offline.

```pycon
>>> from avm_mesh import verify_receipt
>>> verify_receipt(receipt, resolve=storage.read, trusted_voters=anchor,
...                expected_genesis_hash_b64=ALGORAND_MAINNET)["trust_root"]
'stake_attested'
```

The package installs one command-line tool, `avm-mesh`, with five subcommands:

| Command | What it does |
|---|---|
| `avm-mesh verify` | verify a single receipt offline, reporting each trust level separately |
| `avm-mesh serve` | run a *witness* that serves receipts and evidence over a content-addressed store |
| `avm-mesh anchor` | derive a trust anchor by walking state proofs forward from a checkpoint you pin |
| `avm-mesh corroborate` | ask several witnesses for one receipt and check that they agree |
| `avm-mesh crossnode` | ask unrelated **node operators** about one interval, so an anchor is not one endpoint's word |

A *witness* and an *anchor* are both explained below. For now: a witness is simply something that serves
evidence, and an anchor is the trusted starting point you supply yourself.

## What a receipt looks like

A settlement receipt is what moves between parties. It is deliberately tiny — it does not carry the
evidence itself, only a commitment to it and a pointer to where it lives:

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

The evidence it points at — the "proofpack" — is 428–834 KB, so it is **stored once per attested interval,
not once per transaction.** The receipt commits to that proofpack by its digest and points at it, so many
receipts can share a single stored proof.

### Three things the format enforces

These are checked in code on every verification, not left to convention:

1. **You cannot swap the evidence.** The receipt commits to the proofpack by SHA-256 over its canonical
   JSON. Change the proofpack behind the pointer and the digest no longer matches, so the receipt is
   refused.
2. **You cannot lie about the trust level.** The receipt names the tier the evidence *earned*. The
   verifier re-derives that tier from the evidence and rejects any mismatch **in either direction** — weak
   evidence cannot be dressed up as `stake_attested`, and a verifier cannot quietly accept a weaker claim
   than the evidence actually supports.
3. **You cannot reuse evidence for another transaction.** Chain, txid and round come from verifying the
   evidence, not from whatever the caller wrote into the receipt. A perfectly valid proof for a different
   transaction is not a proof for this one.

Pin the chain itself by passing its genesis hash:

```python
verify_receipt(receipt, resolve=storage.read, trusted_voters=anchor,
               expected_genesis_hash_b64="wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=")
```

Without it, `receipt.chain` is only compared to the bundle's genesis **id** — just a string a fork can
copy. With it, the hash is checked against the authenticated block header, which no evidence author can
choose. The receipt's claimed attested interval must also match the interval the evidence actually covers;
otherwise a receipt could point at a genuine proof for a *different* interval and still read as verified.

```python
from avm_mesh import create_receipt, verify_receipt

receipt = create_receipt(bundle, "ipfs://.../proofpack.json")
report = verify_receipt(receipt, resolve=my_storage.read, expected_chain="mainnet-v1.0")
assert report.trust_root == "stake_attested"
```

`resolve` is a function you supply, so storage is entirely up to you: a local file, an HTTP endpoint, or a
chain read.

## A note on the post-quantum dependency

Falcon-1024 is verified by `avm_proofpack.consensus.falcon`, which is pure standard-library Python. Note
that `pqcrypto` 1.0.0 removed Falcon when it moved off the now-archived PQClean, so `pip install pqcrypto`
no longer provides a Falcon verifier. The reasoning, what replaces it, and what remains unproven are all in
[`docs/PQC-FALCON.md`](docs/PQC-FALCON.md).

## The pieces, end to end

| Component | Role |
|---|---|
| `produce` | settler side: store the evidence, then seal a receipt |
| `service` | the **witness**: serves receipts and content-addressed proofpacks |
| `receipt` | the digest-and-pointer, with its three enforced bindings |
| `attestation` | the Level 3 consensus attestation, which requires an anchor |
| `sealed` | the wire format the payment rails are expected to speak — see Honest limits; never round-tripped |
| `trust` | one auditable policy document holding every pin |
| `bond` | witness bonds and the independence rules around them |
| `a2a` | the settlement-evidence extension for agent-to-agent transport |
| `cli` | the offline verifier and tools (`verify` / `serve` / `anchor` / `corroborate` / `crossnode`) |

A safe deployment needs just two things you provide yourself: an **anchor** you obtained independently, and
a **policy** — a single document that pins the chain, genesis hash, anchor and witness set. Everything else
in the library is mechanism around those two decisions.

```sh
# a witness publishes evidence
avm-mesh serve --root ./store --port 8080 --witness-id w1 --operator-id op-a --escrow-txid ESC

# a merchant verifies a receipt against its own policy
avm-mesh verify receipt.json --evidence ./proofpacks \
    --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
    --voters-commitment <b64> --ln-proven-weight <n>
```

## The three trust levels

The AlgoVoi Payment Rails receipt already has two levels of assurance:

| Level | What it checks |
|---|---|
| 1 | the content hash matches the bytes: `sha256(canonical_bytes) == content_hash` |
| 2 | the **operator's** Falcon-1024 signature over that hash |

Level 2 proves *"AlgoVoi issued this receipt"*. What it cannot prove is that the settlement happened as
described, because the issuer could sign anything. **Level 3** closes that gap: it carries evidence that the
transaction was final according to chain consensus, with **no operator key in the trust base at all.**

```python
from avm_mesh import attest, verify_attestation

# `anchor` is YOUR trust anchor: a TrustedVoters value the caller supplies.
receipt["consensus_attestation"] = attest(bundle, "ipfs://.../proofpack.json",
                                          trusted_voters=anchor).to_dict()

verify_attestation(receipt["consensus_attestation"], resolve=my_storage.read,
                   trusted_voters=anchor,                       # must match the recorded anchor
                   expected_genesis_hash_b64=ALGORAND_GENESIS_B64)
```

### Why the anchor must come from you

Level 3's strength rests on one input you have to supply yourself: the **anchor**. Here is why it cannot be
optional.

The set of validators that signs a state proof is committed by a "voters commitment" published one interval
earlier. A single bundle cannot authenticate that commitment on its own — it carries it only as an
unverified `previous_state_proof_message`, a field the bundle's own author chose. If you trusted that
field, a bundle could name itself as its own signer and mint a convincing-looking `stake_attested` tier out
of nothing.

So the anchor has to come from **you**, never from the bundle you are checking: a pinned genesis bootstrap,
a chain walk (`avm_proofpack.consensus.chain`), or a node you already trust at a known round.
`trusted_voters` is required by both `attest()` and `verify_attestation()`, and `verify_attestation()` also
checks your anchor against the one the attestation recorded — handing an attestation its own anchor would
prove nothing.

A few more rules keep Level 3 honest:

- **The scheme is versioned, and v1 is refused by name.** The current scheme string is
  `avm-stateproof-falcon1024-v2`; v1 attestations had forgeable semantics and are rejected rather than
  silently accepted as equivalent.
- **The attestation cannot be swapped or stripped.** It lives inside the receipt's canonical bytes, so
  Levels 1 and 2 already cover it.
- **`attest()` refuses rather than downgrades.** If the evidence does not reach `stake_attested`, no
  attestation is produced at all — shipping a weaker block would let a receipt *look* consensus-backed while
  really carrying only an operator's word.
- **Pin the genesis hash.** Without `expected_genesis_hash_b64`, the attestation only agrees with its own
  self-declared anchor, which is no stronger than Level 2.
- **Only Algorand and Voi.** `ConsensusAttestation` rejects any other chain at construction, because only
  these two have Falcon state proofs. Hedera, Stellar, Base, Solana and Tempo stay honestly at Level 2.

**Both chains are verified against real captures, not assumed from shared code.** `examples/` holds a live
Algorand bundle (round 66457600) and a live Voi bundle (round 24213754, asset transfer of 586896), plus
multi-interval walk captures for each chain. `tests/test_voi_chain.py` drives the Voi bundle through
`create_receipt` and `verify_receipt`, requires `stake_attested` against a Voi anchor, requires an Algorand
genesis pin to be refused, and requires the effect binding to read the real ASA transfer. Until 0.11.0 every
Voi reference in the suite was a chain *label* rather than evidence.

One asymmetry worth stating: the captured Voi transaction is an asset transfer, not a native payment. The
public Voi algod returns `404` from its transaction-proof endpoint for `pay` transactions at the rounds
tried, so `microvoi` payments are covered by unit tests only, not by a live capture.

## Verifying from the command line

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

Whenever a receipt carries a consensus attestation, the anchor flags are required: you supply the
`TrustedVoters` commitment and proven weight that *you* independently trust. The receipt verifies against
that anchor and fails closed without it — never from the bundle's own word. The genesis pin is likewise
checked against the *authenticated* state-proof header, not the attestation's self-declared field.

Exit codes: `0` verified, `2` failed, `3` usage error. Add `--json` for machine-readable output. For a sense
of scale, the shipped receipts are **1161 and 1213 bytes** against an 854 KB proofpack, and the proof is
stored once per attested interval, not per payment.

### Running a witness

A witness serves receipts and evidence over a content-addressed store you control:

```sh
avm-mesh serve --root ./store --port 8080 \
    --witness-id w1 --operator-id op-a --chain mainnet-v1.0 --escrow-txid ESCROW \
    --anchor-voters-commitment-b64 <trusted-voters-commitment-b64> \
    --anchor-ln-proven-weight <proven-weight>
```

The service is bounded by sensible defaults, so it cannot be turned into a free amplifier or held open by
slow clients:

- a proofpack over 8 MiB is refused, both when stored and when served;
- a request path over 2048 characters gets `414`;
- more than 120 requests per client per 10 s gets `429` with `Retry-After`;
- a connection that stalls mid-request is dropped after 10 s;
- at most 64 connections are handled at once — beyond that the witness answers `503` rather than accepting
  everything and spawning a thread per connection.

Operators can tune these with `--max-proofpack-bytes`, `--rate-limit`, `--rate-window` and
`--max-connections`.

One deployment caveat worth calling out: **behind a reverse proxy, these limits key on the socket peer
address** — which is the proxy, not the real client. Every user then shares one quota, and forwarded-client
headers are deliberately ignored (trusting them would let anyone spoof a fresh quota per request). If you
deploy behind a proxy, either raise `--rate-limit` for the shared quota or rate-limit per client at the
proxy itself; that part is your responsibility rather than the library's.

A witness's identity card is optional, but all-or-nothing: supply some identity flags and not others and it
refuses to start (exit 3) rather than publish a card that does not match what you configured. A witness with
no card still serves the store, but it can never be counted toward corroboration — an endpoint that will not
say who operates it is not an independent voice.

### Sealing a receipt

Sealing binds the attestation into the hashed bytes:

```python
from avm_mesh import seal
receipt = seal({"settlement": {...}, "issuer": "..."}, bundle, "file://proofpack.json")
```

### A worked example: a real mainnet receipt

`examples/` ships a receipt and the proofpack it points at, both from genuine Algorand mainnet evidence
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

### Checking that the capture came from more than one operator

Verification proves a proof is valid; it never proves who gave it to you. A walk can verify every interval
and still be worthless if one operator served a consistent fiction — and nothing about a state proof says
where it came from. `crossnode` closes that: fetch the same interval from operators believed to be distinct
and require their independent answers to agree on the signing set, the proven weight, the block-headers
commitment and the proof itself.

```sh
# pick a round within the last few intervals; they are pruned after that
avm-mesh crossnode --round 66647808
```

```
round 66647808
  operators answering: 2 of 2 (2 required)
  AGREE  voters_commitment: 00xqo/JW/ldbMWflfITg9UmhaD0/iib4xwXD8dsYYaROni9RWNcvaarkFYdhR7Q45xTTE/CDeRYpMM1M3j9cOg==
  AGREE  ln_proven_weight: 2230295
  AGREE  block_headers_commitment: saMg/HdZPJA/i1Z83FeBRYrGj05HuZOyR94aUHyp9L0=
  AGREE  state_proof_sha256: 86905b0efa86ffedf7f5824e8b55d0d573dc24c9934f42d84166412fc5108b25
  verdict: corroborated by distinct endpoints
```

Disagreement is a refusal, not a vote — two operators agreeing on a fiction and one telling the truth must
fail, or a coordinated pair carries it. One operator down is also a refusal, not quiet agreement with itself.

**This only works at capture time.** The round in the example above has an expiry date: public endpoints
retain three or four state-proof intervals and prune everything older, so a specific round stops working
within about ten minutes of being written here. Substitute a current one — `--round` must be a multiple of
256 — or use the shipped captures, which were corroborated when they were taken. Either way, an old interval
cannot be cross-checked afterwards by anyone. So the capture tool corroborates as it
fetches, and `examples/walk-mainnet-corroborated/` holds three consecutive intervals captured that way. The
walk then derives its anchor from the proofs alone, and that derived value equals what both operators
reported for the same interval — two independent derivations landing on the same number.

Honest limit: distinct endpoints are not proven separate businesses. `provenance.json` says so in the same
words. See [`docs/INDEPENDENT-OPERATORS.md`](docs/INDEPENDENT-OPERATORS.md).

**What this proves, exactly.** The Falcon signatures, reveal membership, signed weight and coin selection
over that bundle are all verified, and you can re-verify them yourself. One caveat: the anchor in the
command above is taken from the bundle's own previous state-proof message. That is enough to exercise the
full verification path, but it is *not* an independent anchor, because whoever assembled the bundle chose
it.

### The same thing on Voi

`examples/` also holds a genuine Voi mainnet capture and its receipt — a real asset transfer of 586896
(`75LUFZZNQNOP…`, round 24213754), so the second chain can be checked rather than taken on trust:

```sh
avm-mesh verify examples/receipt-voi-24213754.json --evidence examples \
  --genesis r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk= \
  --voters-commitment OxtxxwCffxvrKnC18BjavE8ytDQ7WXV2Lem7HVVN5ioZOa2shTlim0+xgB61KWOtnU3q1AWt1HvMzAeUaLojEw== \
  --ln-proven-weight 2164197
```

```
integrity:   PASS
signature:   None
consensus:   stake_attested
trust root:  stake_attested
attested:    75LUFZZNQNOPS3SLQRHZZKZIECEEVGGP4N3ZZ2UU2UKFFJU5WG4A @ round 24213754
```

The same caveat applies, and one more: the settlement amount is `0` units of asset `586896`, because that
is what the captured transaction actually moved. An example that claimed a rounder number would only
"verify" because the amount binding was not being checked.

To get an independent anchor, derive one. `avm-mesh anchor` walks state proofs forward from a checkpoint you
pin, verifying every interval along the way, and prints the flags `verify` needs:

```sh
avm-mesh anchor --genesis wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8= \
  --anchor-round 66647552 \
  --anchor-voters-commitment QNZAlaF/kfI2kmMnD5pXmJt5ugKYCjHT31G/XkQ7Hqa1LOxVMQF0TdbO0bXl8xt+Ks9MgXpcGns4GKWEA1blYA== \
  --anchor-ln-proven-weight 2230294 \
  --target-round 66648064 --bundles examples/walk-mainnet-corroborated
```

```
authenticated 2 interval(s) from the checkpoint
target round:        66648064
--voters-commitment  00xqo/JW/ldbMWflfITg9UmhaD0/iib4xwXD8dsYYaROni9RWNcvaarkFYdhR7Q45xTTE/CDeRYpMM1M3j9cOg==
--ln-proven-weight   2230295
trust basis:         pinned checkpoint; every interval verified forward from it
```

**What a walk proves, and what it does not.** Every interval from your checkpoint to the target is verified:
Falcon signatures, reveal membership against the voters commitment, signed weight and coin selection. A
checkpoint whose proven weight is off by one, or whose voters commitment is wrong at all, fails at the first
link (both cases are tested, and both are refused).

What a walk does **not** do is prove the checkpoint itself. The checkpoint is your trust decision; one that
happened to match an adversary's chosen signing set would be walked successfully all the same. Nor does it
authenticate the genesis hash — the proofpack library documents `ChainAnchor.genesis_hash` as caller
bookkeeping, and a state proof carries no genesis field, so that label is just a consistency check against
your own records. The voters commitment is what the proofs are actually checked against. Choose the
checkpoint from a source you would trust independently; the walk makes the distance between that decision
and the evidence auditable, not the decision itself.

Drop both anchor flags from `verify` and it fails closed, by design — the tier is never reached from the
bundle's own word.

## Sharing evidence between agents (A2A)

A2A is the transport that agents already speak, so it is the natural route for one agent to hand settlement
evidence to another without either side adopting a new SDK.

```python
from avm_mesh import a2a
card = a2a.advertise(my_agent_card)          # declare the extension
artifact = a2a.as_artifact(sealed_receipt)   # evidence as an ordinary Artifact
result = a2a.verify_artifact(artifact, resolve=my_storage.read,
                             expected_genesis_hash_b64=GENESIS)
```

The extension is **optional** (`required: false`): peers that do not support it still interoperate and
simply fall back to whatever they trusted before. The extension's URI is its versioning boundary — the
meaning behind a published URI never changes; a breaking change ships as a new v2 URI instead.

And **missing evidence is treated as an error, not a silent pass.** An artifact that lacks the extension
payload raises, rather than returning a vacuous success — because "verified nothing and reported OK" is
exactly how a receiver ends up believing it checked something it did not.

## Witnesses and bonding

A state proof says what the chain did. A **witness** is simply whoever hands you that proof — and that role
carries its own risk. Without some cost attached, a witness can withhold, delay, or selectively serve
evidence for free, and "decentralised because node operators run it" quietly becomes an ordinary
centralised service.

A **bond** attaches that cost:

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
| `operator_id` | who runs the witness — **not** a source of trust, only an input to independence |

**Uniqueness is enforced; genuine independence cannot be proven here.** `independent_corroborators()`
counts at most one witness per operator and one per escrow. That blocks the two cheapest fakes:

- several endpoints run by one operator are one witness wearing several hats — presenting them as a quorum
  is an old trick;
- two witnesses pointing at the same escrow are one bond counted twice.

What the count *cannot* do is prove that two genuinely different `operator_id` values belong to two
genuinely independent parties. Those identity strings are supplied by the witnesses themselves, so colluding
operators could claim distinct ids and still satisfy the count. So treat corroboration as a consistency
check whose independence rests on how carefully *you* chose the witnesses — which is exactly why the bond
exists, and why a witness directory is a lead rather than a trust root.

`require_corroboration()` **refuses** rather than quietly returning a short list: a caller that cannot reach
the threshold must not be handed fewer corroborators and left to read that as success.

You can have a receipt's `corroboration` field checked against bonds whenever you want that:

```python
verify_receipt(receipt, resolve=storage.read, witness_set=ws, corroboration_threshold=2)
```

It refuses on four distinct failures — **unknown** (no bond record), **unbonded** (absent, inactive or too
small), **duplicated** (same operator or same escrow), and **insufficient** (fewer independent witnesses
than the threshold). Leave these arguments out and the older behaviour stands: the claim is simply recorded,
and you should describe it as recorded rather than established.

Finally, an unverifiable bond is not a bond: a witness record with no `escrow_txid`, or no `operator_id`, is
rejected when it is constructed.

## Trust tiers are per chain, on purpose

Only **Algorand** and **Voi** have Falcon state proofs; Hedera, Stellar, Base, Solana and Tempo do not.
The wider AlgoVoi rails estate carries seven chains; this library ships chain identifiers for three
(Algorand mainnet, Algorand testnet, Voi mainnet) and refuses an attestation for anything else. Rather than
borrow the estate's breadth in a claim it cannot back, `avm-mesh` reports a tier per chain:

| Tier | Means |
|---|---|
| `stake_attested` | offline-verified against a Falcon-signed state proof |
| `corroborated` | several independent observers agree, but no consensus proof |
| `structural` | internally consistent, but no external anchor |
| `unattested` | no proof material present |

Telling a merchant "here are the two chains where you get cryptographic proof, and the five where you get
someone's word" is a stronger, more honest offer than claiming all seven are equal — because the merchant
can check it.

## Corroborating across witnesses

A single witness is still just one operator's word. `avm-mesh corroborate` asks several and decides whether
the mesh actually agrees:

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

Instead of listing URLs by hand, you can point it at a published directory:

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

A directory is fetched over the network, which brings its own risks, so the client is careful with it:

- **Outbound fetches refuse non-public addresses.** Because a directory supplies the witness URLs, a hostile
  one could otherwise point the client at loopback, a private (RFC1918) host, or the cloud link-local
  metadata service. Both the directory fetch and every witness fetch resolve the host and refuse anything
  that is not a public address, re-checking on each redirect hop (a public host can still redirect inward).
  Running a *local* witness therefore needs `--allow-private`, which is off by default precisely because
  inheriting it from a fetched document would be the attack.
- **A directory is a lead, not a trust root.** Each entry is checked against the witness's own card when it
  is collected; if the directory and the card disagree, that witness does not count and the disagreement is
  reported. Unknown fields, duplicate URLs, a wrong document version or a non-HTTP URL are all refused
  outright.

What counts toward agreement, and what deliberately does not:

- **A witness counts only if it publishes an `operator_id`.** Two URLs on one operator are one voice;
  independence is counted over operators, never over endpoints.
- **The pointer is verified, not trusted.** For each witness the client fetches the proofpack and checks
  that its bytes hash to the digest the receipt names. A witness that points at good evidence but serves
  something else is not counted.
- **Disagreement is reported, never averaged.** Different proofpack digests, rounds or trust tiers each make
  agreement fail, with a named reason.
- **An unreachable or broken witness is a reported view, not a crash.** One silent witness does not abort
  the run, and it does not silently lower the threshold either.

One last distinction: the `corroboration` list on a receipt simply names the witnesses that returned it at
capture time. It records what was seen; on its own it says nothing about whether those operators are
independent. That is what the check above is for.

## Status

**Version `0.13.3`** — `pip install avm-mesh`.

The portable test gate runs **540 tests with 0 skipped** on both Python 3.12 and Python 3.10.22 (an isolated
clean-room run: offline install from wheels only, plus the trust-boundary audit and the red-team suite), so
`Requires-Python: >=3.10` is demonstrated rather than asserted.

543 tests are collected in total. The portable gate deselects three test-only Falcon *signer* checks, which run
separately in a signer-enabled environment and pass with `pqcrypto` 0.1.0 — deliberately not a runtime
dependency. With the fixtures provisioned this Windows host skips six, all of them symlink checks needing a
platform that can create one (`test_anchor.py` twice, `test_cli_gzip.py`, `test_file_resolver.py` twice,
`test_service.py`); they run rather than skip on the Linux clean room, which is how it reports 540 tests with
0 skipped. CI runs the portable suite with the test fixture provisioned, and a missing fixture is treated as a
failure, not a skip.

**Licence:** Apache-2.0, with `LICENSE` and `NOTICE` present in the repository, the wheel and the sdist,
plus PEP 639 `License-Expression` metadata and no contradicting classifier — all checked inside the built
artefacts by `tools/check_artifacts.py` and in CI. (Version 0.5.0 once shipped without either licence file,
which is why this gate exists.)

**Security surface:** `tests/test_validation.py` attacks every input path added in 0.6.0 — directory size,
nesting, field types, argument types, service configuration and CLI failure modes. Each guard was
mutation-checked (removed to confirm a test goes red, then restored), and one was found to be silently
unpinned until the check exposed it. These checks run in a fresh clean-room container that installs from the
built wheels offline and runs against site-packages.

| Piece | State |
|---|---|
| Receipts, three enforced properties, genesis pin | shipped |
| Witness service (`serve`), content-addressed store, append-only receipts | shipped |
| Level 3 consensus attestation, anchor-required | shipped |
| Corroboration across witnesses (`corroborate`) | shipped 0.5.0 |
| Anchor derivation (`anchor`): checkpoint walk over verified intervals | shipped 0.7.0; **proven across two intervals** in 0.10.0, see below |
| **Cross-node corroboration (`crossnode`)**: unrelated operators must agree on the signing set, proven weight, block-headers commitment and the proof | shipped 0.13.0; **capture-time only** — see below |
| Witness discovery (`--directory`, `/.well-known/mesh-directory.json`) | shipped 0.6.0 |
| Worked mainnet example (`examples/`) | shipped 0.6.0 |
| Service resource bounds (size cap, rate limit, slowloris timeout) | shipped 0.6.0 |
| A2A settlement-evidence extension (v1.0 wire format) | shipped; parsed by `a2a-sdk` 1.3.0; TCK `must`/jsonrpc is a **required CI gate** (80 passed, 155 skipped as inapplicable at `--level must`, 0 failed) |
| Rails adoption kit (`avm_mesh.rails`) | shipped; **not yet round-tripped** against a real rails receipt |
| Corroborated walk captures (`examples/walk-mainnet-corroborated/`) | shipped 0.13.0 — three intervals, two operators agreeing, walk derived from the proofs alone |
| Witness bonding (`bond.py`) | model only — **no on-chain escrow**, see Honest limits |

**Dependency note:** `avm-proofpack>=0.4.1`, the version in which `stake_attested` became anchor-required.
Level 3 never authenticates from a bundle's own `previous_message` in any version after 0.1.0.

**A2A conformance, precisely.** The project's own system-under-test runs the TCK at
`--level must --transport jsonrpc` as a **required CI job** — 80 passed, 155 skipped, 0 failed — after that job surfaced
one real defect that was then fixed (a `text/plain` body returned `ParseError -32700` instead of
`ContentTypeNotSupportedError -32005`; it now answers HTTP 415 before the parser). That is protocol
conformance for the transport the project claims. It is **not** extension validation: the TCK's
extension-related requirements (`CARD-EXT-001`, `CARD-EXT-002`, `EXTENSION_SUPPORT_REQUIRED`) cover extended
agent-card retrieval and the refusal of an unsupported required extension, and none of them constructs,
carries or inspects a third-party extension payload. A green run therefore cannot validate the extension's
own semantics — only that carrying it breaks nothing. See [`docs/A2A-CONFORMANCE.md`](docs/A2A-CONFORMANCE.md).

**The extension's own contract is checked separately.** `tests/vectors/a2a/settlement-evidence-v1.json`
holds fourteen cases (two must pass, twelve must refuse) and both verifiers — the library and
`tools/verify_settlement_artifact.py`, which imports nothing from this project — are required to reach the
same verdict on every one. See [`docs/EXTENSION-VECTORS.md`](docs/EXTENSION-VECTORS.md).

**The anchor walk is now proven across two intervals, on real mainnet data.** Three consecutive captures —
rounds `66606336`, `66606592`, `66606848` — are checked in under `examples/walk-mainnet-66606848/`, with
hashes pinned in `provenance.json` and reproducible through `tools/fetch_walk_captures.py`. From the
checkpoint at `66606336` the walk verifies two intervals and derives the input the target round is signed
against. Until this release the walk had only ever been exercised over one interval, because a second
capture was not available.

Be careful what it establishes: all three captures came from **one public endpoint in one fetch**, so this
proves the chaining mechanism, not source independence. `provenance.json` records that in its own
`independence` field rather than leaving it to a reader to notice.
`tests/test_walk_multi_interval.py` walks the captures offline and requires four hostile variants to be
refused: a wrong anchor, a missing interval, a corrupted state proof, and a capture named for a round its
proof does not attest.

## Honest limits

- **A receipt is not a proof of delivery.** It proves a transaction was final, and what it did. Whether the
  goods actually shipped is not an on-chain fact.
- **Corroboration is a capture-time property.** It cannot be established after the fact, and two endpoints
  run by one operator are not independent witnesses. It is recorded, not counted.
- **Capture is time-sensitive.** Measured against public Algorand endpoints while building the cross-node
  check: three or four state-proof intervals are retained, not two. Miss that window and the interval cannot
  be captured or cross-checked by anyone, and a bundle built from it falls back to `unattested`.
- **Falcon verification is only as good as the genesis hash you pin.** Ship that hash inside your
  application, rather than fetching it over the wire.
- **Bonding is a model, not a market.** `bond.py` enforces independence and threshold arithmetic over
  witness records you supply; it does not read an escrow, and nothing is slashed by this library. On-chain
  bonding would need four decisions this library does not make for you: the asset, the slash fraction, the
  dispute window and the arbiter.
- **The rails adapter has never seen a real rails receipt.** Its format and signing convention are pinned by
  tests against the shipped verifier's source, but no receipt produced by that verifier has been checked
  here. Treat "drop-in" as unproven end to end until one has.
- **Level 2 needs an operator-side signer.** No signer is a *runtime* dependency, and `pqcrypto` 0.1.0 ships
  no prebuilt Linux wheel, so it is built from sdist wherever the acceptance test runs. With that signer
  installed, the operator-signature path is exercised end to end (`tests/test_level2_real_signer.py`, three
  tests, marked `signer`); without it, those tests are deselected rather than counted as passing. The
  primitive itself is pinned by real Falcon-1024 KAT vectors.

Licensed under Apache-2.0.
