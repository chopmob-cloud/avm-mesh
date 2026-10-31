# Independent review request — avm-mesh 0.7.1 (`c0b25c8`)

> **Everything below the horizontal rule is historical** (0.4.2 at `9bfda93`, 226 tests). It is kept because
> the findings and the addendum are still the record of what was reviewed and what closed. The current
> instructions and numbers are this section.
>
> | Fact | Value |
> |---|---|
> | Version | `0.7.1`, live on PyPI as wheel and sdist |
> | Reviewed commit | `c0b25c8` on `main` |
> | Python floor | 3.10, executed in a container rather than asserted |
> | Runtime deps | `avm-proofpack>=0.4.1`, `avm-effectproof>=0.1.1` |
>
> ```sh
> pip install avm-mesh==0.7.1 pytest
>
> python -m pytest tests -q -m 'not signer'           # 361 passed, 0 skipped
> python tools/audit_trust_boundary.py                # rule A OK; B/C/D advisory
> python tools/red_team.py --fixture <bundle>.json.gz # RED TEAM CLEAN
> ```
>
> Fixture: `avm-proofpack/tests/fixtures/stake_attested_algorand_66457600.json.gz`. Set
> `AVM_PROOFPACK_TESTS` to a checkout's `tests/` directory and `AVM_MESH_REQUIRE_FIXTURE=1` so an absent
> fixture fails rather than skips.
>
> Three tests carry the `signer` marker and are excluded above: they need `pqcrypto==0.1.0`, which is
> test-only, has no Linux wheel, and is not a runtime dependency. Run them where that signer exists and
> expect **3 passed**. `tools/cleanroom.sh` encodes the full gate and fails on a missing wheel, on any
> skipped test, on zero collected, on a fatal audit rule, and on an accepted red-team attack.
>
> **Still true from the body below**: `trust.py` is unsigned; `bond.py` verifies nothing on chain; rule D is
> advisory by choice. **No longer true**: the package is on PyPI; `avm-proofpack` 0.4.1 is released; the
> settlement amount is bound via `avm_mesh.effects`; the LEVEL 2 signer is demonstrable with
> `pqcrypto==0.1.0`; `service.py` has size caps, a rate limit, a slowloris timeout, a 64-connection ceiling
> and an SSRF guard.
>
> Current review focus and the unproven list are in `docs/OPERATOR-RUNSHEET.md` and `docs/A2A-CONFORMANCE.md`;
> the short version: a genuine rails receipt, a second independent capture, and `avm_proofpack` internals.

---

# Historical review request — avm-mesh 0.4.2 (`9bfda93`)

What I want from you is **adversarial review of running code**, not a read-through. Every real defect in
this estate so far was found by attacking it — five by you in `avm-proofpack`, two by me attacking
`service.py` — and none by reading a diff.

## How to run it

```sh
git clone https://github.com/chopmob-cloud/avm-mesh && cd avm-mesh
pip install avm-proofpack==0.4.1   # or: pip install -e ../avm-proofpack @ c97dcc3
pip install -e . && pip install pytest

python -m pytest tests/ -q                     # expect 226 passed, 0 skipped
python tools/audit_trust_boundary.py           # expect rule A OK; B/C/D advisory
python tools/red_team.py --fixture <bundle>.json.gz   # expect RED TEAM CLEAN
```

The fixture is `avm-proofpack/tests/fixtures/stake_attested_algorand_66457600.json.gz`.

A clean-room run is reproducible with a fresh `python:3.12-slim`, an offline `--no-index` install from
the staged wheels, and the suite executed against **site-packages** rather than the source tree. Both
give 221 passed, 0 skipped as of `c37aa9e`. `tools/cleanroom.sh` encodes the whole check and treats a
skipped test as a failure -- an unstaged input used to make tests decline to run while the run still
looked green.

## What has already been proven, so you can skip it

- **226 tests, 0 skipped**, clean-room validated against the installed wheel, not the source tree.
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
- ~~Not on PyPI~~ — superseded: 0.7.1 is published; `avm-proofpack` 0.4.1 was released.
- ~~One stash exists locally~~ — resolved and dropped; its genesis-pin and interval-binding changes are in
  `receipt.py` at HEAD.

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
