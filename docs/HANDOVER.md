# Handover — avm-mesh (as at 2026-10-31, `ac92eb0`)

Written for the next agent or reviewer picking this up cold. It states what is done, what is blocked,
and who or what each blocked item waits on. Nothing here claims a capability that is not evidenced.

## Repository

| Fact | Value |
|---|---|
| Local path | `***REMOVED***` |
| Remote | `github.com/chopmob-cloud/avm-mesh` (private) |
| Branch | `main` @ `ac92eb0`, working tree clean, local equals origin |
| Version | `0.8.0` (testnet bonding PoC), published to PyPI as wheel and sdist |
| Python floor | `>=3.10`, executed in a container rather than asserted |
| Runtime deps | `avm-proofpack>=0.4.1`, `avm-effectproof>=0.1.1` |
| Sibling repos | `***REMOVED***`, `***REMOVED***`; proofpack fixtures live in the former |

Related artefacts outside the repo: handover and review documents in
`***REMOVED***\` (`HANDOVER-CLAUDE-2026-10-31-review-round-2.md`,
`HANDOVER-CODEX-2026-10-31.md`).

## State of the gates

- **VM2 portable clean room, Python 3.12**: 361 passed, 0 skipped, 3 signer tests deselected, audit rule A
  OK, red team refused all 14 attacks, `CLEAN-ROOM GREEN`.
- **VM2 Python 3.10**: 361 passed, 0 skipped, 3 deselected.
- **Signer acceptance, separate run**: 3 passed with `pqcrypto==0.1.0`, which is test-only and not a runtime
  dependency.
- **GitHub CI** on `ac92eb0`: `tests (3.10)`, `tests (3.12)`, `artefacts`, `a2a TCK (jsonrpc, must)` all
  success. The A2A job is a required gate, not advisory; it reports 80 passed, 0 failed, 155 skipped,
  30 deselected.
- **Mutation-proven guards**: each listed guard was removed, a named test went red, and restoring it
  returned green. The list is in `docs/REVIEW-REQUEST.md`. One guard is knowingly **not** mutation-proven
  because it is timing-bound: the 64-connection ceiling, which has a functional saturation test only.

## Blockers, in order of what unblocks the most

### 1. A genuine rails receipt (blocks proving the adapter against the tool it replaces)

**What is missing**: one `receipt.json` produced by `verify_settlement_receipt.py`'s producer.

**What already exists**: `python -m avm_mesh.rails verify` was proven against a receipt this repository
signed itself with `pqcrypto==0.1.0`: LEVEL 1 PASS, LEVEL 2 `True`, exit 0, with the hex-digest signing
convention and the embedded key pinned. The adapter converts correctly on a real Falcon-1024 signature.

**What is unproven**: that the rails kit's own field set, canonicalisation and key handling arrive in the
shape the adapter expects. A self-signed trial cannot show that.

**Who owns it**: whoever operates the rails kit. `docs/OPERATOR-RUNSHEET.md` section B lists the exact
fields, the command to run on receipt, and the meaning of each exit code.

**Effort once supplied**: half a day, including a regression test built on the real fixture.

### 2. A second independent state-proof capture (blocks the anchor walk's independence claim)

**Partly closed in 0.10.0.** The walk is now proven across two intervals on real mainnet data:
`examples/walk-mainnet-66606848/` holds three consecutive captures (66606336, 66606592, 66606848) with
pinned hashes, and `tests/test_walk_multi_interval.py` walks them offline. The chaining mechanism is no
longer a one-hop demonstration.

**What is still missing**: those three captures came from **one public endpoint in one fetch**, so they
prove the mechanism, not that the source is independent or honest. Closing that needs one capture of an
adjacent interval from a node run by a different operator, and a walk that mixes the two.

**What is unproven**: that the walk is not merely reading one operator's private view. Inventing a second
source would make the suite green and the capability false.

**Who owns it**: an operator with a node. `docs/OPERATOR-RUNSHEET.md` section A gives the collection command
and the acceptance command; `tools/fetch_walk_captures.py` is what produced the checked-in set.

**Effort once supplied**: half a day — fetch one adjacent interval from the second operator, add it to the
directory, assert that the walk verifies with captures drawn from both sources, and update the
`independence` field in `provenance.json` from "not source independence" to what the mixed walk establishes.

### 3. Four economic decisions (blocks on-chain bonding entirely)

**What is missing**: asset (ALGO, VOI, or a reward token), slash fraction, dispute window in blocks, and
arbiter (single signer, panel, or vote).

**What already exists**: `bond.py` reasons over **declared** values: `escrow_txid`, `bond_microalgo`,
`active`. `independent_corroborators()` and `slashable_stake()` are arithmetic over declarations.

**What is unproven**: that any bond exists, is unspent, or is active. There is no escrow reader. Everything
downstream of a bond is a model, not a guarantee, and the code says so.

**Who owns it**: AlgoVoi sets a **bootstrap** configuration so a live platform exists to exercise the flow,
and the lasting parameters are offered to the Algorand and VOI communities to ratify through their own
governance. `docs/BONDING-DECISIONS.md` lays out the decision surface, the options and the trade-offs, and
states that the lasting parameters are deliberately not AlgoVoi's to set. The bootstrap is the owner's call;
the lasting values are not, which is a narrower blocker than this document originally implied.

**Effort**: not estimable until the four answers exist. The implementation work is real but the specification
is the blocker.

### 4. An external review of `avm-proofpack` internals (blocks the root-of-trust claim)

**What is missing**: an engaged reviewer for the Falcon-1024 implementation, the Merkle/state-proof
arithmetic, and the coin-selection walk.

**What already exists**: `avm-mesh` has had two independent reviews (Codex, 8 findings; Claude, 3 findings,
all fixed). `avm-proofpack` is the actual root of trust and has not had the same treatment.

**Who owns it**: whoever commissions the review. I can scope it and hand over the artefact; I cannot
perform an independent review of my own dependencies.

## Things that look like blockers and are not

- **PyPI publication**: done. 0.8.0 is live, installed from the index in a fresh venv, console script
  exercised.
- **Licence and metadata**: done. `LICENSE` and `NOTICE` in repository, wheel and sdist; PEP 639
  `License-Expression`; no contradicting classifier; verified inside the published wheel.
- **A2A conformance**: the TCK `must` suite at the `jsonrpc` transport is a required CI gate. It proves
  protocol conformance and that carrying the extension breaks nothing. It does **not** validate extension
  payload semantics, and no requirement in the TCK does.
- **The Falcon signer**: available as `pqcrypto==0.1.0`, test-only, no Linux wheel on PyPI. It is installed
  for the signer run only and must never become a runtime dependency.

## Known defects and deliberate choices

- **`trust.py` is an unsigned root of trust.** A tampered policy document is accepted. Documented as the
  operator's responsibility; a reviewer may reasonably call that a rationalisation.
- **`bond.py` verifies nothing on chain** (see blocker 3).
- **Rule D of the trust audit reports 189 advisories.** It measures whether refusal messages are pinned by
  `match=`; behaviour is covered by fail-closed tests. Chosen not to inflate the count.
- **`origin/claude/vigilant-volta-3kjwyy`** is a divergent branch with no shared history, containing
  nothing newer than `main`. Left in place; deleting it is the owner's call.
- **A superseded stash was dropped** on 2026-10-31; its two changes (genesis pin against the authenticated
  header, attested-interval binding) are already in `receipt.py` at HEAD.

## Claims corrected in this session, kept here so they do not return

- The 0.7.0 sdist shipped three signer-dependent tests that skipped on a recipient's machine. A skip reads
  as a pass, so 0.7.1 exists solely to mark and separate them. No runtime behaviour changed.
- README and `docs/A2A-CONFORMANCE.md` said the TCK has no `EXT-*` ids. It has `CARD-EXT-001`,
  `CARD-EXT-002` and `EXTENSION_SUPPORT_REQUIRED`; none inspects a third-party extension payload, which is
  the claim that actually mattered.
- `docs/REVIEW-REQUEST.md` described 0.4.2 with 226 tests and claimed the package was not on PyPI. It now
  leads with current state and keeps the old body as history.

## The testnet PoC (0.8.0) and what it does not change

`poc.EnforcementLedger` and `bond.BondPolicy` make the challenge flow runnable end to end on Algorand
testnet: attest, challenge against the challenger's own anchor, record an administrative removal, and keep
the decisions in a hash-chained log that detects tampering and truncation. `docs/POC-RUNBOOK.md` states what
it proves; the short version is that it proves the detection and the flow, not economic security.

None of the four blockers above are closed by it. In particular, no escrow reader was added, and that was a
decision rather than an omission: reading an account balance would not make a bond a commitment, because the
operator can withdraw it. Verification needs an escrow application holding the funds, which needs the four
parameters.

## How to re-run everything

```sh
# portable suite (361 passed, 0 skipped)
pip install avm-mesh==0.8.0 pytest
AVM_PROOFPACK_TESTS=<avm-proofpack-checkout>/tests AVM_MESH_REQUIRE_FIXTURE=1 \
  python -m pytest tests -q -m 'not signer'

# signer acceptance (3 passed, needs pqcrypto==0.1.0)
python -m pytest tests/test_level2_real_signer.py -q

# security gates
python tools/audit_trust_boundary.py            # rule A must be OK
python tools/red_team.py --fixture <bundle>.json.gz   # RED TEAM CLEAN

# full clean room on VM2, fresh containers, offline wheel install
sh tools/cleanroom.sh /work
```

## What I would do next, in this order

1. Ask the rails operator for one receipt (blocker 1) and the node operator for one capture (blocker 2).
   Both are single files and both unblock a claim that is currently caveated.
2. Put the four economic questions to the founder as a decision list rather than an engineering task.
3. Commission the `avm-proofpack` review (blocker 4); it is the only remaining root-of-trust gap.
4. In the meantime, nothing is idle-invented. `docs/REVIEW-REQUEST.md`, `docs/OPERATOR-RUNSHEET.md` and
   `docs/A2A-CONFORMANCE.md` are the documents a reviewer should read first, and they are current.
