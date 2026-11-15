# Cross-operator corroboration

## The gap this closes

A settlement attestation that rests on one endpoint's word is worth very little. A walk can verify
every interval from a pinned checkpoint to a target and still be worthless if a single operator
served a consistent fiction — and the verification would pass, because nothing about a state proof
says *who gave it to you*.

Captures taken from one endpoint in one fetch prove chaining and prove nothing about source
independence. That is an honest limitation but not a useful one. `crossnode` is the answer.

## What it does

Fetch the same attested interval from several operators believed to be organisationally
distinct, and require their independent responses to agree on the fields the proof is
verified against:

| Field | Why it matters |
|---|---|
| `VotersCommitment` | the signing set. If this differs, the operators disagree about who signed |
| `LnProvenWeight` | the weight those voters held. Differs, and the same proof means different things |
| `BlockHeadersCommitment` | the chain state the interval attests |
| `StateProof` (SHA-256) | two different proofs of the same interval is a contradiction no consensus rule allows |

Disagreement is a refusal, not a vote. That is the design choice that matters: two
operators agreeing on a fiction and one telling the truth must FAIL. A quorum would let a
coordinated pair carry it, and a coordinated pair is exactly the adversary worth defending
against. `tests/test_crossnode.py` pins this by giving the liar a majority.

```sh
avm-mesh crossnode --round 66647808 \
  --operator nodely=https://mainnet-api.4160.nodely.dev \
  --operator mine=https://your-node.example
```

```
round 66647808
  operators answering: 2 of 2 (2 required)
  AGREE  voters_commitment: 00xqo/JW/ldbMWflfITg9UmhaD0/iib4xwXD8dsYYaROni9RWNcvaarkFYdhR7Q45xTTE/CDeRYpMM1M3j9cOg==
  AGREE  ln_proven_weight: 2230295
  AGREE  block_headers_commitment: saMg/HdZPJA/i1Z83FeBRYrGj05HuZOyR94aUHyp9L0=
  AGREE  state_proof_sha256: 86905b0efa86ffedf7f5824e8b55d0d573dc24c9934f42d84166412fc5108b25
  verdict: corroborated by distinct endpoints
  caveat: agreement across distinct endpoints, not proof of independent ownership
```

**Required, with no default.** There is no operator list the tool can supply honestly: the
only two public Algorand endpoints serving state proofs are Nodely's current and legacy
hostnames, which are one provider. Naming them both used to produce exactly the output
above — "corroborated by distinct endpoints" — for a provider agreeing with itself. That
case is now refused:

```
round 66982144
  AGREE  voters_commitment: jfd9KRQn63mVC+NGawhIU+K6rHGnJFHx044W8pios/ASuUYSMtxPHnHgG27b1+6Rq/j+IstO6xSae2lGqbiJ4g==
  AGREE  ln_proven_weight: 2230109
  verdict: NOT CORROBORATED -- not corroborated: operators 'algonode' and 'nodely'
           returned the same provider header (x-and-dl=0.05), so they are one provider
           answering under two names
```

Exit codes: `0` corroborated, `2` refused (disagreement, too few answering, or one provider
under two names), `3` refused as malformed input.

## Corroboration has to happen at capture time — on Algorand

This is the fact that shapes the design, and it was found by running it rather than
reasoning about it. **Public Algorand endpoints retain only the three or four most recent
state-proof intervals.** Measured against `mainnet-api.algonode.cloud`: one interval back
was available, four back was pruned, and every interval older than that returned
`500 ledger does not have entry`. Re-measured later, round `66982144` was available and then
pruned within the same working session, and round `66647552` — the oldest interval in the
shipped walk — now returns `500` permanently.

**This is not true of Voi.** Measured 2026-11-14 against `mainnet-api.voi.nodely.dev`:
65,536 rounds back still answered, and the request returned the interval *asked for*
(`FirstAttestedRound 24497153 / LastAttestedRound 24497408`), not a nearby one. The shipped
Voi example, round `24213760`, was ~349,000 rounds (~11 days) behind head and still returned
its exact interval.

So the constraint is chain-specific:

| Chain | Retention | Can corroboration be widened later? |
|---|---|---|
| Algorand | newest interval or two | **No** — capture at settlement time or never |
| Voi | at least ~65,536 rounds (weeks) | **Yes**, within that window |

An earlier revision of this document stated the Algorand figure for both chains, which made
"an old capture cannot be corroborated afterwards by anyone" false for Voi. That mattered
for the gateway integration: an Algorand settlement's proof must be captured within minutes,
while a Voi one can be proved later.

On Algorand, the tool that fetches a walk therefore corroborates as it captures:

```sh
python tools/fetch_corroborated_walk.py --hops 3 --out examples/walk-mainnet-X \
  --operator nodely=https://mainnet-api.4160.nodely.dev \
  --operator mine=https://your-node.example
```

It probes which rounds are still retained, keeps the newest contiguous run, records the
rounds it had to drop in `beyond_retention`, and writes every capture's corroboration
result into `provenance.json`. If the operators disagree it exits non-zero rather than
writing a walk that looks corroborated — unless `--allow-disagreement` is passed, in which
case the disagreement is recorded rather than hidden.

`crossnode` distinguishes a pruned interval from a broken operator, because the remedy
differs: retrying cannot help with a pruned interval, and an error message that invites a
retry wastes the reader's time.

## The evidence shipped

`examples/walk-mainnet-corroborated/` holds three consecutive intervals — `66647552`,
`66647808`, `66648064` — captured when two hostnames agreed on all four fields.
`tests/test_corroborated_walk.py` then checks the property that makes it worth anything:
the walk derives its anchor **from the proofs alone**, and that derived value equals what
the endpoints reported for the same interval.

Those are two separate derivations, and that part still holds. What does **not** hold is
the word "operators": both hostnames belong to Nodely, so this example demonstrates that
two derivations agree, not that two organisations do. It is retained rather than deleted
because it is honest evidence of chaining and of the agreement machinery; it is not
evidence of independent corroboration, and the repository no longer describes it as such.
A genuinely corroborated capture set requires a second operator that is not Nodely, and
none is available publicly on either chain as of this writing.

## What it does not prove

Being precise about this is the reason the mechanism is worth trusting.

- **`algonode` and `nodely` are one operator, and the previous version of this document
  claimed otherwise.** Nodely's own documentation states that the old `algonode.cloud`
  hosts are "same rules, same infra as `nodely.dev`". Measured: both return byte-identical
  state proofs *and* the same `x-and-nl` provider header (`de2@de_central`), so they are
  one business answering under two hostnames. An earlier revision said only that separate
  ownership "is not established here" — which understated the problem, because a reader
  took the two names as two witnesses. `crossnode` now refuses a pair like this, so the
  shipped example corroborates nothing: see `beyond_retention` and the `independence`
  field, which records this in those words.
- **Not a majority of honest operators.** Two agreeing operators out of two proves those
  two agree. It does not prove either is honest. What it does prove is that one of them
  alone cannot substitute a different signing set without the other contradicting it, which
  is a real reduction in who you have to trust but not the elimination of trust.
- **Not that the chain is the chain.** A genesis hash passed to `anchor.walk` is
  bookkeeping only — a state proof and its signed message carry no genesis field, so it
  cannot bind cryptographically. The binding comes from the anchor's voters commitment,
  which the proofs *are* verified against. The receipt path is stronger: there
  `expected_genesis_hash_b64` is checked against the authenticated block header. The two
  are not the same guarantee and the documentation does not pretend they are.

## What an operator has to be, now that sameness is detectable

`crossnode` refuses a pair that looks like one provider (shared provider header, or the
same endpoint twice), so adding a second operator means adding one that is genuinely
separate:

1. A node you run yourself, on infrastructure you control, with its own ledger. This is the
   only option that needs no third party's cooperation.
2. A provider other than Nodely. As of this writing there is no public one serving Voi, and
   on Algorand every public endpoint checked either is Nodely or requires credentials. That
   is stated as a measurement, not as a permanent fact.

`avm-mesh crossnode` exits `2` with `not corroborated: …` when the answers look like one
provider. Use `--allow-same-operator` only to re-analyse captures someone else made; it
compares the fields and reports `agreed`, and never reports `corroborated`.

## Adding an operator

```sh
avm-mesh crossnode --round 66647808 \
  --operator nodely=https://mainnet-api.4160.nodely.dev \
  --operator mine=https://your-node.example
```

Two Nodely hostnames is not a valid pair and the check refuses it. `--min-operators` sets
how many must ANSWER, not how many are configured, because two configured and one down is
not corroboration. A value below 2 is refused: one operator agreeing with itself is the
failure mode this whole mechanism exists to prevent.
