# Adding a second operator — the only thing that closes the independence claim

Status: **the blocking item on both chains.** No amount of engineering closes it. This
document is what an operator, or whoever recruits one, needs in order to act, and it states
what is required without overstating what it buys.

## Why this and not something else

`crossnode` now refuses a pair of endpoints that look like one provider. So the mechanism
cannot be fooled into reporting self-agreement — but it also cannot report anything at all
until there are two genuinely separate answers to compare. That is where things stand:

| Chain | Public providers serving state proofs | Genuinely separate? |
|---|---|---|
| Algorand | `mainnet-api.algonode.cloud`, `mainnet-api.4160.nodely.dev` | **No** — one business, "same infra" per Nodely's docs |
| Voi | `mainnet-api.voi.nodely.dev`, `mainnet-api.voi.nodely.io` | **No** — same operator, byte-identical proofs |

Measured 2026-11-14. Other Algorand providers were checked and either require credentials
(PureStake, Alchemy, Chainstack) or do not serve `/v2/stateproofs` at all (AlgoExplorer,
algoindexer). One provider serves Voi, per CompareNodes' own provider list.

So there is no shortcut: the second witness has to be created.

## Option A — run one yourself (needs no one's cooperation)

This is the only route that can be taken today, and it is what I would do first.

**What it costs.** A Voi or Algorand participation/relay node on your own infrastructure.
Voi publishes the guidance: minimum 8 vCPU / 4 cores, 8 GB RAM, 100 GB storage, 100 Mbps;
recommended 16 vCPU / 16 GB / 1 Gbps. Algorand's is comparable. Docker image:
`ghcr.io/voinetwork/voi-node` (last commit March 2025, no tagged releases — check before
relying on it).

**What it buys — the honest version.** Two *hosting* failures instead of one. It does not
give two *organisations*: an adversary who compromises you compromises both. But it removes
the single-provider failure mode, which is the one that exists today, and it makes
`crossnode` report something real rather than refusing.

**Then:**

```sh
avm-mesh crossnode --round <current multiple of 256> \
  --operator nodely=https://mainnet-api.4160.nodely.dev \
  --operator mine=https://your-node.example
```

Expected: four `AGREE` lines and `verdict: corroborated by distinct endpoints`, **not** a
`NOT CORROBORATED` line. If your node's `x-and-nl` names the same datacentre as
Nodely — because it is behind a Nodely-fronted proxy, for instance — the check will treat it
as the same provider. That is intended: it is measuring what a reader would measure.

**Retention decides when you can do this, and it differs by chain.** Algorand keeps one or
two state-proof intervals: the capture has to be taken now. Voi retains at least 65,536
rounds (measured), so a Voi corroboration can be widened afterwards, within weeks.

## Option B — recruit a second organisation (needs someone else's decision)

Worth doing, and not mine to do. It requires a party that is willing to be named as a
witness and to keep a node up. What it buys beyond Option A is the thing the docs currently
say is unproven: that two *businesses* agree.

The ask is small and can be made concrete:

1. A node serving `/v2/stateproofs/{round}` on Algorand or Voi.
2. Permission to name them in `provenance.json` as a source.
3. Nothing else — no key, no payment path, no integration. `crossnode` only reads.

## What neither option proves

Stated plainly, because the whole point of this work is not repeating an overstatement:

- **Not that either operator is honest.** Two agreeing nodes prove those two agree. It does
  not prove either is telling the truth about the chain.
- **Not that the chain is the chain.** A genesis hash passed to `anchor.walk` is bookkeeping;
  the binding comes from the anchor's voters commitment.
- **Not economic independence** unless the two are separately owned and funded. Option A
  gives hosting independence only, and says so.

What it does prove, which is worth having: one operator alone cannot substitute a different
signing set without the other contradicting it. That is a real reduction in who you must
trust, and it is currently unexercised rather than false.

## What NOT to do

- **Do not put the two Nodely hostnames back as a default.** A reader takes "2 operators
  agree" at face value, and that is the specific error this repository has just corrected.
- **Do not accept a node's word that it is separate.** The check reads headers and endpoint
  identity, and it is heuristic: a provider that strips headers defeats it. A claim of
  independence in a config file is not evidence.
- **Do not treat identical state proofs as collusion.** A state proof is deterministic in
  its signing set, so honest independent nodes *must* return the same bytes.

## The bootstrap the decision list refers to

`docs/BONDING-DECISIONS.md` proposes a testnet-only bootstrap. Two measured constraints on
that plan:

- **Algorand testnet is reachable** (`testnet-api.4160.nodely.dev` answers `200`).
- **There is no public Voi testnet.** Nodely's endpoint matrix advertises
  `testnet-api.voi.nodely.dev` and `testnet-idx.voi.nodely.dev`; both are NXDOMAIN. Voi's
  docs give the `voitest-v1` genesis hash but no live endpoint. A Voi testnet leg needs a
  self-run `voi-node`, which is the same machine Option A needs — so doing Option A on Voi
  testnet closes both problems at once.
