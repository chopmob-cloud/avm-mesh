# Handover — avm-mesh

Written for the next agent or reviewer picking this up cold. It states what is done, what is
blocked, and who or what each blocked item waits on. Nothing here claims a capability that is
not evidenced.

## Repository

| Fact | Value |
|---|---|
| Remote | `github.com/chopmob-cloud/avm-mesh` — **public**, Apache-2.0 |
| Branch | `main`, working tree clean, local equals origin |
| Version | `0.13.3` on PyPI, wheel and sdist |
| Python floor | `>=3.10`, executed in a container rather than asserted |
| Runtime deps | `avm-proofpack>=0.4.1`, `avm-effectproof>=0.1.1` |
| Install | `pip install avm-mesh`; console script `avm-mesh` |

Nothing needed to work on this repository lives outside it. The dependent packages are on PyPI,
and their sources are separate repositories.

## What the tool does

Five subcommands, all offline by default:

| Command | Purpose |
|---|---|
| `verify` | Check a settlement receipt against an anchor you pin yourself |
| `serve` | Publish receipts over HTTP for other people to verify |
| `corroborate` | Compare one receipt's claims against several sources |
| `anchor` | Walk a chain of state-proof intervals backwards from a pinned anchor |
| `crossnode` | Require several operators to agree on the same attested interval |

## State of the gates

Collection is **552 tests**; three are signer tests excluded by `-m 'not signer'`, leaving **549** in
the portable gate.

- **Portable gate on Linux (VM2 clean room, Python 3.12)**: `549 passed, 0 skipped`. No skips are
  permitted — the clean room fails on a skipped test, on zero collected, on a missing wheel, on a fatal
  audit rule and on an accepted red-team attack. Audit rule A OK; every red-team attack refused;
  `CLEAN-ROOM GREEN`.
- **Portable gate on Linux, Python 3.10**: the same suite on the floor interpreter.
- **On Windows**: `543 passed, 6 skipped`. The six are symlink checks, which report themselves as such
  because the platform does not support symlinks without elevation. They run rather than skip on Linux,
  which is why the clean room reports 549. Neither figure is a discrepancy; they are the same suite on
  two environments.
- **GitHub CI** on the public repository: `tests (py3.10)`, `tests (py3.12)`,
  `artefacts (licence + metadata)` and `a2a TCK (jsonrpc, must)` all success. The A2A job is a
  required gate, not advisory.
- **Mutation-proven guards**: `tools/mutation_check.py` removes each guard, requires the matching
  test to go red, restores the original bytes, and requires green again. One guard is knowingly
  **not** mutation-proven because it is timing-bound: the 64-connection ceiling has a functional
  saturation test only.

## Blockers, in order of what unblocks the most

### 1. A genuine rails receipt (blocks proving the adapter against the tool it replaces)

**What is missing**: one `receipt.json` produced by `verify_settlement_receipt.py`'s producer.

**What already exists**: `python -m avm_mesh.rails verify` was proven against a receipt this
repository signed itself with `pqcrypto==0.1.0`: LEVEL 1 PASS, LEVEL 2 `True`, exit 0, with the
hex-digest signing convention and the embedded key pinned. The adapter converts correctly on a
real Falcon-1024 signature.

**What is unproven**: that the rails kit's own field set, canonicalisation and key handling
arrive in the shape the adapter expects. A self-signed trial cannot show that.

**Who owns it**: whoever operates the rails kit. `docs/OPERATOR-RUNSHEET.md` section B lists the
exact fields, the command to run on receipt, and the meaning of each exit code.

**Effort once supplied**: half a day, including a regression test built on the real fixture.

### 2. More independent operators, captured while the data exists (bounds the independence claim)

**Substantially closed in 0.13.0.** `crossnode` requires several operators believed
organisationally distinct to agree on the same attested interval — on `VotersCommitment`,
`LnProvenWeight`, `BlockHeadersCommitment` and `sha256(StateProof)`. Disagreement is a refusal,
not a vote, because a majority rule would let two operators agreeing on a fiction outvote one
telling the truth. One operator answering is also a refusal, and `--min-operators 1` is refused
outright. `examples/walk-mainnet-corroborated/` holds a three-interval walk whose derived
`ln_proven_weight` matches what both operators independently reported.

**What is still missing**: corroboration happens at capture time, and public endpoints retain
only three or four state-proof intervals — one interval back is available, four back is pruned,
and older requests return `500 ledger does not have entry`. An old capture cannot be
cross-checked by anyone afterwards, so the set of corroborated intervals cannot be widened
retrospectively. `provenance.json` states plainly that distinct endpoints are not proven to be
separate businesses.

**What is unproven**: that any operator is honest, and that the operators are economically
independent. Agreement shows that one operator alone cannot substitute a different signing set
without another contradicting it. It does not show that either is telling the truth about the
chain.

**Who owns it**: an operator with a node. `docs/INDEPENDENT-OPERATORS.md` gives the collection
and acceptance commands.

### 3. Four economic decisions (blocks on-chain bonding entirely)

**What is missing**: asset (ALGO, VOI, or a reward token), slash fraction, dispute window in
blocks, and arbiter (single signer, panel, or vote).

**What already exists**: `bond.py` reasons over **declared** values — `escrow_txid`,
`bond_microalgo`, `active`. `independent_corroborators()` and `slashable_stake()` are arithmetic
over declarations.

**What is unproven**: that any bond exists, is unspent, or is active. There is no escrow reader.
Everything downstream of a bond is a model, not a guarantee, and the code says so.

A read-only balance reader was considered and deliberately **rejected**: a balance is not a
commitment, because the operator can withdraw it between the check and the claim. Verification
needs an escrow application holding the funds, which needs these four parameters.

**Who owns it**: AlgoVoi sets a **bootstrap** configuration so a live platform exists to exercise
the flow; the lasting parameters are offered to the Algorand and VOI communities to ratify
through their own governance. `docs/BONDING-DECISIONS.md` lays out the decision surface, the
options and the trade-offs, and states that the lasting parameters are deliberately not
AlgoVoi's to set.

**Effort**: not estimable until the four answers exist. The implementation work is real, but the
specification is the blocker.

### 4. An external review of `avm-proofpack` internals (blocks the root-of-trust claim)

**What is missing**: an engaged reviewer for the Falcon-1024 implementation, the Merkle and
state-proof arithmetic, and the coin-selection walk.

**What already exists**: `avm-mesh` has had independent review, and every finding was reproduced
before being acted on. `avm-proofpack` is the actual root of trust and has not had the same
treatment.

**Who owns it**: whoever commissions the review. It can be scoped and the artefact handed over;
an independent review of one's own dependency cannot be self-performed.

## Things that look like blockers and are not

- **PyPI publication**: done. `0.13.3` is live, installed from the index in a fresh virtual
  environment with `PYTHONPATH` cleared, console script exercised.
- **Licence and metadata**: done. `LICENSE` and `NOTICE` in repository, wheel and sdist; PEP 639
  `License-Expression`; no contradicting classifier; verified inside the published wheel.
- **A2A conformance**: the TCK `must` suite at the `jsonrpc` transport is a required CI gate. It
  proves protocol conformance and that carrying the extension breaks nothing. It does **not**
  validate extension payload semantics, and no requirement in the TCK does. The 14 local
  conformance vectors in `docs/EXTENSION-VECTORS.md` are the evidence for the extension itself.
- **The Falcon signer**: available as `pqcrypto==0.1.0`, test-only, no Linux wheel on PyPI. It is
  installed for the signer run only and must never become a runtime dependency.

## Known defects and deliberate choices

- **`trust.py` is an unsigned root of trust.** A tampered policy document is accepted. Documented
  as the operator's responsibility; a reviewer may reasonably call that a rationalisation.
- **`bond.py` verifies nothing on chain** (see blocker 3).
- **Rule D of the trust audit reports advisories rather than failures.** It measures whether
  refusal messages are pinned by `match=`, while behaviour is covered by fail-closed tests. The
  count is reported as-is rather than driven to zero by adding assertions that pin wording.
- **Windows path limits are accepted, not fixed.** Junctions and reparse points are not refused, a
  TOCTOU window exists between the check and the read, and hard links cannot be detected from a
  path. All three are documented rather than silently tolerated.

## What the testnet PoC (0.8.0) does and does not change

`poc.EnforcementLedger` and `bond.BondPolicy` make the challenge flow runnable end to end on
Algorand testnet: attest, challenge against the challenger's own anchor, record an
administrative removal, and keep the decisions in a hash-chained log that detects tampering and
truncation. `docs/POC-RUNBOOK.md` states what it proves; the short version is that it proves the
detection and the flow, not economic security.

None of the four blockers above are closed by it, and no escrow reader was added. That was a
decision rather than an omission, for the reason given under blocker 3.

## How to re-run everything

```sh
# portable suite
pip install avm-mesh==0.13.3 pytest
AVM_PROOFPACK_TESTS=<avm-proofpack-checkout>/tests AVM_MESH_REQUIRE_FIXTURE=1 \
  python -m pytest tests -q -m 'not signer'

# signer acceptance (needs pqcrypto==0.1.0, test-only)
python -m pytest tests/test_level2_real_signer.py -q

# security gates
python tools/audit_trust_boundary.py                  # rule A must be OK
python tools/red_team.py --fixture <bundle>.json.gz   # RED TEAM CLEAN
python tools/mutation_check.py                        # every guard must bite

# full clean room on VM2, fresh containers, offline wheel install
sh tools/cleanroom.sh /work
```

## What to do next, in this order

1. Ask the rails operator for one receipt (blocker 1) and other node operators for captures taken
   while their intervals are still retained (blocker 2). Both are single files, and both unblock a
   claim that is currently caveated.
2. Put the four economic questions to the community as a decision list rather than an engineering
   task (blocker 3).
3. Commission the `avm-proofpack` review (blocker 4); it is the only remaining root-of-trust gap.
4. In the meantime, `docs/WHY.md`, `docs/OPERATOR-RUNSHEET.md` and
   `docs/INDEPENDENT-OPERATORS.md` are the documents a reviewer should read first.
