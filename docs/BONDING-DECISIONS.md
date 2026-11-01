# Witness bonding parameters — community decision proposal

Status: TWO PARTS. (1) A BOOTSTRAP configuration, below, that AlgoVoi sets so there is a
live initial platform on day one. (2) An OPEN PROPOSAL, offered to the Algorand and VOI
communities IF they want it, to decide the lasting parameters themselves. Created
2026-10-31.

The bootstrap exists only to let the platform be live now; it is interim, honestly
caveated, and overridable by either community through the proposal. Uptake of the proposal
is not assumed and not pushed. The hope is that node operators take this up and shape the
future of witness bonding themselves; if the genuine interest is not there, the platform
simply keeps running on the bootstrap and nothing is forced. The lasting parameters are
deliberately NOT set by AlgoVoi. This document lays out the decision surface, the options
and the trade-offs so that, should a community choose to engage, it can ratify its own
answers through its own governance. Every "Starting point" below is a non-binding
suggestion to open discussion, not a decision. Publication of the proposal to either
community is a separate, gated step and has not happened.

## Bootstrap: the initial live platform (proof of concept / test validation)

Purpose, stated plainly: to have a live platform NOW for testing, validation and proof of
concept. It exists to exercise the whole witness-bonding flow end to end, declare a bond,
attest, corroborate, challenge, slash-or-remove, so operators and reviewers can see the
mechanism work and judge it BEFORE any real stake or real governance is committed. It is
not production economic security and does not claim to be.

Bootstrap configuration:
- Network: TESTNET only (Algorand testnet first; VOI testnet when an operator joins). No
  mainnet value is at risk at any point in the PoC.
- Collateral: testnet ALGO/VOI, a nominal floor (the existing `MIN_BOND_MICROALGO = 1`
  ALGO placeholder is adequate for a PoC). Bonds are DECLARED, per current `bond.py`; the
  chain-verified escrow reader is the first thing built if the PoC validates and operators
  engage.
- Enforcement: the deterministic proven-false check (attestation vs authenticated testnet
  header) is demonstrated for real; the economic consequence is administrative at this
  stage, a witness is REMOVED and the event recorded, because there is no on-chain escrow
  to slash yet. The PoC proves the detection and the flow, not real fund forfeiture.
- Adjudication: a single interim signer (founder or the operator running the PoC), purely
  to exercise the subjective path. No panel, no vote at PoC stage.
- Windows: SHORT, so a validation run completes in minutes to hours rather than the
  production-scale 7/14-day figures discussed below. Exact PoC counts set at setup.

Explicit non-claims for the bootstrap: not production security, no real funds, no
guarantee that a bond exists or is enforceable. Every number here is a placeholder chosen
to make the PoC runnable and is superseded by whatever a community ratifies. The PoC's job
is to turn "here is a design" into "here is the mechanism running on testnet that you can
inspect" — which is also what the handover's validation gates and the invitation below
need in order to be credible.

## Why the LASTING parameters are a community decision, not a product default

A witness bond is the only thing that makes a false or withholding attestation cost money
(see `src/avm_mesh/bond.py`). Its economics and dispute rules are governance, not
engineering: who stakes, how much, what counts as a lie, who judges, and where forfeited
funds go are legitimacy questions that belong to the people whose chain secures the bond.
AlgoVoi supplies the mechanism and a neutral starting proposal and then steps back. If
node operators in either community want witness bonding, they drive it and decide the
values; if they do not, it remains an unexercised option. Each community can choose
differently, and the framework supports both running side by side, but AlgoVoi does not
presume either will take it up.

## Grounding: what the mechanism does today, and what it cannot

See `src/avm_mesh/bond.py`.

- It reasons only over DECLARED values on `Witness` (`bond_microalgo`, `escrow_txid`,
  `active`). It does NOT read any chain. "Bonded" means "claims a stake at or above the
  floor", not "proven on-chain to exist, be unspent and be active".
- The floor is a single constant (`MIN_BOND_MICROALGO = 1_000_000`) and
  `slashable_stake()` currently sums the full declared bond, i.e. an implicit 100% slash.
  Neither is a ratified policy; both are placeholders awaiting the decisions below.
- There is no slash fraction, dispute window or arbiter concept in the code. Nothing
  enforces any of this on-chain yet. An escrow reader and escrow application are the
  engineering tail that follows ratification.

Framing of the four questions was validated by a bounded Codex consult (2026-10-31): the
four headings are correct but each carries the sub-decisions shown.

---

## 1. Collateral: what is staked, and how much

Both communities are first class. Each bonds in its OWN native asset on its OWN chain:
the Algorand community bonds ALGO in an Algorand escrow; the VOI community bonds VOI in a
VOI escrow. `bond.py` already keeps escrows independent (one operator, one escrow), so the
two sets coexist without one community's stake standing in for the other's.

Open choices for EACH community:
- Asset: native coin (ALGO / VOI) or a community-designated token. Native coin is simplest
  and needs no valuation rule.
- Minimum bond: a fixed floor, or a floor scaled to the exposure a witness covers.
  (Scaling needs a cross-chain valuation source that does not exist today.)
- Denomination and identifier: for a token, the asset id and decimals.

Starting point (non-binding): native coin, a FIXED floor chosen by each community to be a
real deterrent rather than the 1-unit dev placeholder. Each community picks its own number.

## 2. Penalty: what a false or withholding attestation costs

Open choices:
- Shape: a single fixed fraction, fractions that differ per offence, or a schedule that
  escalates for repeat offenders.
- Which acts are slashable, and the admissible evidence. The cleanly objective case is a
  PROVEN-FALSE attestation: one whose claimed state contradicts the authenticated chain
  header and is therefore checkable by anyone. WITHHOLDING (failing to serve a requested
  proof within a deadline) is real but harder to prove objectively and may warrant a
  lighter response or removal rather than a slash.
- Base and cap: the fraction applies to what balance, and whether cumulative penalties are
  capped.
- Destination of forfeited funds: burned, paid to the challenger who caught the lie, sent
  to a community treasury, or split.
- Life after a slash: permanent removal versus re-bonding, and any replenishment rule.

Starting point (non-binding): 100% slash for a proven-false attestation (partial slashing
of provable fraud invites "lie and keep most of it"); withholding handled by removal, not
slash, until there is a verifiable service log; a challenger bounty funded from the slash
to pay for the work of catching a lie, remainder burned or to a community treasury as the
community prefers.

## 3. Timing: the windows, in that chain's blocks

These are distinct and should not be collapsed into one window. For each, the community
fixes the length and the starting event, counted in its own chain's blocks:
- Challenge window: how long anyone has to dispute an attestation.
- Adjudication deadline: how long the judge has, and what happens on inaction.
- Appeal window, or an explicit statement that the decision is final.
- Unbonding delay: notice to withdraw a bond, kept LONGER than the challenge window so a
  witness cannot attest and then withdraw before a lie surfaces, with continued liability
  for earlier attestations while their windows remain open.

Starting point (non-binding): a challenge window measured in days (e.g. 7), an unbonding
delay comfortably longer (e.g. 14), automatic adjudication treated as final for the
objective offence, and the subjective path defaulting to NO penalty if the judge fails to
act. Exact block counts pinned at implementation against each chain's current block time.

## 4. Adjudication: who judges, and who pays

Open choices:
- Model: fully automatic on-chain for objectively verifiable offences; and for subjective
  offences a single signer, a threshold panel, or a community vote. A community may mix
  these: automatic where the chain can decide, human where it cannot.
- Appointment, quorum, conflicts, replacement.
- Who pays: a challenger deposit (refunded on a successful challenge, forfeited if
  frivolous) and who bears adjudication and execution costs.
- Enforcement authority and whether decisions are appealable or final.

Starting point (non-binding): automatic on-chain adjudication for the proven-false offence
(the escrow application checks the attestation against the authenticated header, so no
trusted judge is needed for the case that matters most), and a community-chosen body for
subjective disputes, with a challenger deposit to deter griefing. The choice of body is
exactly the kind of legitimacy question this proposal leaves to each community.

---

## What AlgoVoi commits to regardless of the answers

- The objectively verifiable offence (attestation vs authenticated header) is decided on
  chain, by anyone, with no trusted third party. That is the core of AlgoVoi's
  offline-verifier thesis and is not up for negotiation; only the penalty and process
  around it are.
- The mechanism stays neutral between the two chains: neither community's parameters
  constrain the other's.

## Process from here

1. Stand up the bootstrap PoC on testnet (above) so there is a live platform to test,
   validate and demonstrate. This is the near-term, in-house step and claims nothing beyond
   a working mechanism on testnet.
2. Finalise this proposal's wording and the recommended starting ranges.
3. Offer it to the Algorand and VOI communities through their governance channels, as an
   invitation rather than a roadmap, with the running PoC as the thing they can inspect
   (publication is gated and founder-approved before it goes out). If node operators show
   genuine interest, they lead from here.
4. Only if a community chooses to adopt it, implement the ratified PRODUCTION values: a
   read-only escrow reader per chain, an escrow application per chain enforcing the chosen
   penalty, windows and adjudication, and a regression path distinguishing "declared bond"
   from "chain-verified bond" so the model-vs-guarantee caveat in `bond.py` can be retired
   honestly.
5. Mandatory before anything touches mainnet: Codex independent validation on the running
   code, and legal review of the slashing arrangement.

Absent operator uptake, the platform keeps running on the testnet PoC, honestly caveated,
and no mainnet escrow reader or slashing contract is built. That is an acceptable outcome,
not a failure.
