# Independent review request — avm-mesh 0.3.0 (`1b27b63`)

What I want from you is **adversarial review of running code**, not a read-through. Every real defect in
this estate so far was found by attacking it — five by you in `avm-proofpack`, two by me attacking
`service.py` — and none by reading a diff.

## How to run it

```sh
git clone https://github.com/chopmob-cloud/avm-mesh && cd avm-mesh
pip install avm-proofpack==0.4.1   # or: pip install -e ../avm-proofpack @ c97dcc3
pip install -e . && pip install pytest

python -m pytest tests/ -q                     # expect 202 passed, 0 skipped
python tools/audit_trust_boundary.py           # expect rule A OK; B/C/D advisory
python tools/red_team.py --fixture <bundle>.json.gz   # expect RED TEAM CLEAN
```

The fixture is `avm-proofpack/tests/fixtures/stake_attested_algorand_66457600.json.gz`.

A clean-room run is reproducible with a fresh `python:3.12-slim`, an offline `--no-index` install from
the staged wheels, and the suite executed against **site-packages** rather than the source tree. Both
give 202 passed, 0 skipped as of `07e2a74`. `tools/cleanroom.sh` encodes the whole check and treats a
skipped test as a failure -- an unstaged input used to make tests decline to run while the run still
looked green.

## What has already been proven, so you can skip it

- **202 tests, 0 skipped**, clean-room validated against the installed wheel, not the source tree.
- **14 red-team attacks refused**, positive control first: path traversal, digest substitution, tier
  upgrade, anchor mismatch, genesis pin for another chain, interval shift, txid reuse, receipt rewriting.
- **Guards proven load-bearing by mutation**: disabling the attested-interval binding turns
  `test_receipt.py` red (1 failed, 13 passed) and restoring it returns 14 passed — verified both in the
  source tree and inside the installed package.
- **Two independent mainnet rounds** exercised end to end with sockets blocked: `66457600` and
  `66474240`.

## Where I would attack, if I were you

Ordered by my own doubt, highest first.

### 1. The settlement amount is not bound to the transaction

`produce.settlement_from_bundle(bundle, amount, asset, issuer)` takes `amount` **from the caller** and
writes it into the sealed content. Nothing checks it against the transaction's actual `ApplyData`. A
merchant could be shown a receipt asserting 250,000 microalgo while the transaction moved 1. This is a
deliberate separation — evidence is a fact, an invoice is an interpretation — but it means **a receipt
must not be read as evidence of an amount**. My view: this needs either a hard prohibition on the field
or a verification path through `avm-effectproof`. Convince me which.

### 2. LEVEL 2: the primitive is proven; an operator-signed receipt end to end is not

This was originally stated as "LEVEL 2 has never seen a real key". That overstates the gap as the code
now stands, and is corrected here. `cli._make_signature_verifier` no longer calls `pqcrypto` at all --
it uses `avm_proofpack.consensus.falcon.falcon1024_verify` (stdlib-only; `pqcrypto` 1.0.0 dropped Falcon entirely -- see `docs/PQC-FALCON.md` for why and what replaces it).
`tests/test_level2_real_falcon.py` exercises that primitive against **genuine Falcon-1024 KAT vectors**
(real keys and signatures, not stubs), proves rejection under a changed message and a different key, and
proves the plumbing by substitution (the verifier is replaced with a recorder, so the test fails if the
code stops hashing what it claims to hash or stops checking the returned bool).

What is still *not* shown, and is recorded as such: an operator generating their own Falcon-1024 key and
signing a freshly produced receipt, verified end to end. No Falcon-1024 *signer* is installable in this
environment, so that belongs in an operator's acceptance test. `sealed.verify_sealed` still accepts an
injected `verify_signature`, which is correct -- the verifier's job is to check a signature, not to own a
signing toolchain -- but it means the signer side of LEVEL 2 is unexercised here by design, not by stub.

### 3. `trust.py` is an unsigned root of trust

`TrustPolicy` pins chain, genesis hash, anchor and witnesses — but the policy document itself has no
integrity protection. A deployment that ships a tampered policy accepts evidence it should not. I
documented it as "the operator's job"; that may be a rationalisation.

### 4. `bond.py` verifies nothing

`escrow_txid` is an assertion. `slashable_stake()` is arithmetic over declared numbers. There is no
on-chain check that the bond exists, is unspent, or is still active. Everything downstream of the bond
is therefore a model, not a guarantee.

### 5. `service.py` has no resource bounds

`_safe_name` bounds the name, but nothing bounds request rate, bundle size on read, or concurrent
writers. A witness is a courier and can be replaced, so this may be acceptable — but say so explicitly
rather than leaving it implicit.

## Known and deliberate

- **Rule D of the audit reports ~95 advisories.** It measures whether refusal *messages* are pinned by
  `match=`; the behaviour is covered by 95 fail-closed tests. I chose not to inflate the number by
  adding string matches. If you think that metric is wrong, say so.
- **No on-chain bonding contract.** Track 3 work, decisions pending.
- **Not on PyPI.** Blocked on `avm-proofpack` 0.4.1 being released first.
- **One stash exists locally** (`wip: receipt genesis pin + attested-interval binding (unreviewed)`) —
  superseded work, kept for traceability, not part of any branch.

## What counts as a finding

Anything that makes a verifier accept something it should refuse, or that makes a claim in the README,
docstrings or commit messages untrue. The second category has been the more productive one: this estate
has had more false *claims* than defective *code*.

## House rules

`Signed-off-by: AlgoVoi <chopmob@gmail.com>`. If you fix something, please also add the mutation result
to the commit — "guard disabled → N failed; restored → M passed" — because a guard with no evidence it
bites is what this review is meant to catch.

## Addendum — review response (branch `fix/bind-settlement-amount-effectproof`, 2026-10-30)

This branch acts on the review above; the counts in the sections before it describe the pre-review state.

- **Finding #1 (settlement amount) is closed.** The stated amount is now bound to the authenticated STIB
  via `avm-effectproof` in both `produce()` and `verify_sealed()` (new `avm_mesh.effects`), fail-closed on
  close-remainder or any shape that is not an unambiguous `pay`/`axfer`. Guards proven by mutation
  (produce: 1 failed → restored 5 passed; verify_sealed: 1 failed → restored 10 passed) and validated by
  Codex on the running code.
- **Suite is now 202 tests** (two added for the binding): **202 passed, 0 skipped** in the Linux clean
  room; 201 passed + 1 skipped on a Windows host, where the symlink-refusal test cannot plant a symlink.
- **New dependency `avm-effectproof>=0.1.1`** — stage its wheel in the clean room alongside `avm-proofpack`.
- Findings #3 (`trust.py`) and #5 (`service.py`) remain accept-and-document design decisions; #4 (`bond.py`
  on-chain verification) is addressed as a docstring-truth fix pending the Track 3 escrow check.
