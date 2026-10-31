# Why this exists

## The angle

Decentralised commerce on Algorand and Voi already has a settlement layer. What it does not have is a
neutral answer to a simple question two parties ask each other after the fact: *what actually happened, and
can you prove it without trusting my platform or yours?*

Every existing answer requires someone to be trusted. A bridge with its own validators. A payment processor's
dashboard. An indexer whose database you hope is honest. Each one is a party that can be wrong, compromised or
simply absent when a dispute happens years later.

`avm-mesh` removes that party from the question. A settlement receipt is a small digest and pointer that
resolves to evidence anchored in the chain's own consensus, verifiable offline against a pinned genesis hash,
by a third party who was not present and does not trust either counterparty.

The same primitive is what agentic commerce needs. When an agent claims it paid, the counterparty, an
auditor, or a dispute process needs to check that claim without asking the agent's operator to confirm it.

## Why these two chains

Algorand and Voi both produce Falcon-1024 state proofs. That is the property that matters, and it is rarer
than it sounds: a chain whose consensus can be checked offline by a stranger, at a point in time, without
contacting the network.

It means one receipt format binds to each chain's own consensus with no new validator set, no bridge, and no
additional trust assumption. The root of trust is the chain, not us. `avm-proofpack` verifies the proofs;
`avm-mesh` packages the receipt and the verification path around them.

This is also why the design refuses to invent a mesh-level consensus. A second consensus layer on top of two
chains that already have one would be a weaker claim wearing a stronger name.

## What a receipt proves, and what it does not

**Proves:** a transaction was final, what it did, and which interval's state proof attests it. The evidence
resolves to bytes whose digest is committed inside the receipt, and verification is offline.

**Does not prove:** that goods or services were delivered; that the amount stated in a sealed invoice matches
what moved (that is a separate binding through `avm-effectproof`); that the agent spending the money was
authorised to. Authority, mandate and policy are different layers with different evidence.

Every claim in this repository is written to that boundary. Where a tier could not be checked, the output
says so rather than rounding up.

## The three gaps between this and the angle

These are the honest distance between a working receipt format and decentralised agentic commerce. Each is
named with what it would take, in `docs/HANDOVER.md`.

### 1. Cost of lying is not yet economic

A receipt proves what the chain did. It does not make a witness's attestation expensive to falsify. Today
`bond.py` reasons over **declared** values: an escrow transaction id, a bond amount, an active flag. There is
no reader that checks the chain for an unspent, active bond.

Until that exists, everything downstream of a bond is a model rather than a guarantee. Closing it needs four
decisions that are economic and legal rather than technical: the bonding asset, the slash fraction, the
dispute window, and who arbitrates.

### 2. Independence is one capture deep

`avm-mesh anchor` walks a voters commitment forward from a pinned checkpoint, so a verifier can derive its
anchor instead of copying it out of the bundle being checked. That mechanism is tested against one real
mainnet interval.

One interval proves the walk works. It does not prove the walk is not reading a single operator's private
view of the chain. That needs a second capture from a different node, which is a file somebody has to
produce; inventing one would make the suite green and the claim false.

### 3. Commerce-side agreement is asserted, not demonstrated

The rails adapter converts a rails-shaped receipt into a verification result, and it does so correctly: it
was proven against a receipt signed with a real Falcon-1024 key, LEVEL 1 and LEVEL 2 both passing, exit 0.

What it has not seen is a receipt produced by the rails kit it is meant to replace. That is one file, and
`docs/OPERATOR-RUNSHEET.md` describes exactly what it should contain.

### And one assurance gap behind all three

`avm-proofpack` is the root of trust: the Falcon verification and the state-proof arithmetic. `avm-mesh` has
had two independent reviews. The root of trust has not had the same treatment. A review of our wrapper does
not substitute for one of the dependency that decides whether a receipt is genuine.

## What is proven today

- `0.7.1` on PyPI, wheel and sdist, licence and metadata verified inside the published artefact.
- 361 tests, 0 skipped, in the portable gate on Python 3.12 and 3.10, in fresh containers from an offline
  wheel install.
- 14 red-team attacks refused, positive control first.
- Guards proven load-bearing by mutation: removing the guard turns a named test red, restoring it returns
  green. The list is in `docs/REVIEW-REQUEST.md`. The one known exception is the 64-connection ceiling,
  which is timing-bound and has a functional saturation test only.
- A2A conformance at the `must` level over the `jsonrpc` transport is a required CI job. It does not, and
  cannot, validate our extension's payload semantics.

## The short version

We are not building a bridge, a payment processor or a marketplace. We are building the evidence layer that
makes commerce between parties who do not trust each other possible without appointing a trusted third party
to remember what happened, and then making that evidence cheap to verify and expensive to fake.

The first half of that sentence is built. The second half is the bonding work, and it is waiting on decisions
rather than on code.
