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
  caveat: agreement across distinct endpoints, not proof of independent ownership; a shared upstream or hosting provider defeats this
```

Exit codes: `0` corroborated, `2` refused (disagreement or too few answering), `3` refused
as malformed input.

## Corroboration has to happen at capture time

This is the fact that shapes the design, and it was found by running it rather than
reasoning about it. **Public Algorand endpoints retain only the three or four most recent
state-proof intervals.** Measured against `mainnet-api.algonode.cloud` while writing this:
one interval back was available, four back was pruned, and every interval older than that
returned `500 ledger does not have entry`.

So an old capture cannot be corroborated afterwards by anyone, no matter how many
operators you ask. The tool that fetches a walk therefore corroborates as it captures:

```sh
python tools/fetch_corroborated_walk.py --hops 3 --out examples/walk-mainnet-X
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
`66647808`, `66648064` — each captured while two public operators (`algonode`, `nodely`)
agreed on all four fields. `tests/test_corroborated_walk.py` then checks the property that
makes it worth anything: the walk derives its anchor **from the proofs alone**, and that
derived value equals what the operators independently reported for the same interval.

Those are two separate derivations — one from the state proof walk, one from two
operators' own ledgers — landing on the same `ln_proven_weight` and `voters_commitment`.
That is the difference between this capture set and every earlier one in this repository.

## What it does not prove

Being precise about this is the reason the mechanism is worth trusting.

- **Not separate ownership.** `algonode` and `nodely` are distinct endpoints; whether they
  are distinct businesses, or share an upstream provider or a hosting account, is not
  established here. `provenance.json` records this in its `independence` field in those
  words, and a reader who knows better should correct it.
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

## Adding an operator

```sh
avm-mesh crossnode --round 66647808 \
  --operator algonode=https://mainnet-api.algonode.cloud \
  --operator nodely=https://mainnet-api.4160.nodely.dev \
  --operator other=https://your-node.example
```

`--min-operators` sets how many must ANSWER, not how many are configured, because two
configured and one down is not corroboration. A value below 2 is refused: one operator
agreeing with itself is the failure mode this whole mechanism exists to prevent.
