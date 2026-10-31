<!-- DRAFT: proposed README reframed as an open offer to the Algorand and VOI ecosystems.
     Not yet swapped in for README.md. Preserves the honest limits of the current README
     verbatim; condenses the deep mechanism sections and links them rather than dropping
     them. Review and approve before replacing README.md. -->

# avm-mesh

**Settlement receipts for the Algorand and VOI mesh, offered openly to both ecosystems.**

This repository is an open offer, under Apache-2.0, to the Algorand and VOI communities and
their node operators. It is not a product you buy and not a federation you join. It is a
mechanism that turns the nodes you already run into the interop layer, plus an invitation to
use it and to shape what it becomes. Take it up if it is useful to you; if it is not, nothing
here asks anything of you.

## The offer, in one paragraph

A node on the source chain already holds the full block, so it can produce evidence that a
settlement was final for free. A node on the destination chain cannot see those blocks, so it
has a genuine reason to verify that evidence. `avm-mesh` makes the second node able to check
the first node's evidence **offline**, against a Falcon-1024 state proof, with no new
validator set, no new token, no new contract and nothing new to trust. The asymmetry between
the two nodes is the whole protocol. That is the offer: cross-chain settlement evidence that a
merchant can verify by themselves, built out of nodes that already exist.

## Why Algorand and VOI specifically

Only Algorand and VOI sign their consensus state with Falcon-1024, a NIST-selected
post-quantum scheme, and publish state proofs that verify offline against the genesis hash. No
indexer, no RPC, no federation, post-quantum by construction rather than by roadmap. That
shared property is why this offer is made to these two ecosystems together: they are the two
chains where a settlement receipt can carry cryptographic proof rather than someone's word.

We are honest about the edge of that: Hedera, Stellar, Base, Solana and Tempo have no Falcon
state proofs, so a receipt for them stays at a lower, clearly labelled tier. "Here are the two
chains where you get a proof and the rest where you get an observation" is a stronger, checkable
offer than pretending every chain is equal.

## What a node operator can do with it today

You already run a node. With `pip install avm-mesh` you can:

- **Verify** a settlement receipt offline, each trust level reported separately: `avm-mesh verify`.
- **Serve** evidence as a witness over a content-addressed store you control: `avm-mesh serve`.
- **Derive your own trust anchor** by walking state proofs forward from a checkpoint you pin,
  never from the evidence you are checking: `avm-mesh anchor`.
- **Corroborate** a receipt across several independent witnesses and see whether the mesh
  agrees: `avm-mesh corroborate`.

Verification is offline and depends on no service of ours. The full command reference, the
receipt format, the three enforced bindings (substitution, upgrade, identity), the mandatory
anchor, the A2A settlement-evidence extension and the resource bounds on a witness are in
[`docs/REFERENCE.md`](docs/REFERENCE.md) (the current detailed README content).

## The part the ecosystems decide, not us

A witness that serves evidence is only as trustworthy as its incentive to be honest. The design
answer is a **bond**: a stake a witness forfeits if it lies or withholds. But *how much*, *in
what asset*, *what counts as a lie*, *who judges* and *where a forfeited stake goes* are
legitimacy questions, not engineering ones, and they belong to the people whose chain secures
the bond.

So we do not set them. [`docs/BONDING-DECISIONS.md`](docs/BONDING-DECISIONS.md) lays out the
decision surface, the options and the trade-offs, and offers them to the Algorand and VOI
communities to decide through their own governance, **if they want to**. Uptake is not assumed
and not pushed; the hope is simply that node operators take this up and shape its future
themselves.

To make that a real choice rather than a slide, the same document specifies a **testnet
proof-of-concept**: the whole flow (declare a bond, attest, corroborate, challenge,
slash-or-remove) running on testnet with no real funds at risk, so operators and reviewers can
inspect the mechanism working before committing any stake or any governance. Today `bond.py`
enforces independence and threshold arithmetic over declared bonds; it does not yet read an
escrow on chain. That gap is stated plainly below and is the first thing built if an ecosystem
chooses to engage.

## Honest limits

- **A receipt is not a proof of delivery.** It proves a transaction was final and what it did.
  Whether goods shipped is not an on-chain fact.
- **Corroboration is a capture-time property.** It cannot be established after the fact, and two
  endpoints run by one operator are not independent witnesses. It is recorded, not counted.
- **Capture is time-sensitive.** Nodes retain roughly two state-proof intervals (~512 rounds,
  ~20 minutes). Miss that window and the bundle falls back to `unattested`.
- **Falcon verification is only as good as the genesis hash** you pin. Ship it in your
  application, not fetched over the wire.
- **Bonding is a model, not a market.** `bond.py` enforces independence and threshold arithmetic
  over witness records you supply; it does not read an escrow, and nothing is slashed by this
  library. On-chain bonding needs decisions this repository deliberately leaves to the ecosystems
  (see `docs/BONDING-DECISIONS.md`): asset, slash fraction, dispute window, arbiter.
- **The rails adapter has never seen a real rails receipt.** The format and signing convention
  are pinned by tests against the shipped verifier's source, but no receipt produced by that
  bundle has been verified here. Treat 'drop-in' as unproven end to end until one is.
- **LEVEL 2 end-to-end is unproven.** No Falcon-1024 *signer* is installable in this environment,
  so the operator-signature path is tested by substitution and KAT vectors, not by an operator
  signing for real.

## Status and provenance

**`0.7.1`** on PyPI, Python 3.10+. 361 tests, 0 skipped in the portable gate on Python 3.12 and
3.10, run in a VM2 clean room from offline wheels, with an audit rule and a red-team gate. The
A2A TCK `must` suite at the jsonrpc transport is a required CI gate (80 passed, 0 failed); it
proves protocol conformance, not extension payload semantics. Full gate detail and the per-piece
shipped/unproven table are in [`docs/REFERENCE.md`](docs/REFERENCE.md) and
[`docs/HANDOVER.md`](docs/HANDOVER.md).

## Licence and reuse

Apache-2.0. `LICENSE` and `NOTICE` are in the repository, the wheel and the sdist. Reuse with
credit is welcome and is the point of making this an open offer; the only thing asked in return
is that attribution is kept. If you build on it for either ecosystem, we would rather hear that
you did than not.
