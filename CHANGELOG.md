# Changelog

## 0.11.0 — Voi, proven rather than assumed

Every previous Voi reference in this repository was a label. `chain="voimain-v1.0"` was passed to bond and
corroboration helpers, and one test asserted that a Voi policy refuses an Algorand receipt. No test had ever
verified a genuine Voi bundle, so "works on both AVM chains" rested on shared code and an argument about
shared encoding. This release replaces that argument with evidence.

### Added

- **`examples/voi-proofpack-24213754.json.gz`** — a genuine Voi mainnet capture, transaction
  `75LUFZZNQNOPS3SLQRHZZKZIECEEVGGP4N3ZZ2UU2UKFFJU5WG4A` in round 24213754, taken from
  `https://mainnet-api.voi.nodely.dev`. The uncompressed bundle's SHA-256 is pinned in the test.
- **`examples/walk-voi-24213760/`** — three consecutive Voi state proofs (24213248, 24213504, 24213760),
  hashed in `provenance.json`, so the anchor walk is demonstrated chaining on Voi as well as Algorand.
- **`tests/test_voi_chain.py`** — thirteen tests over that evidence: the bundle identifies itself as
  `voimain-v1.0`; it reaches `stake_attested` against a Voi anchor; an Algorand genesis pin is refused;
  without an anchor it stays `unattested`; the amount binding reads the real ASA transfer (asset 586896,
  0 units) and refuses a wrong amount, a wrong asset id, and a native-unit claim on an asset transfer;
  and a Voi receipt round-trips through `create_receipt` / `verify_receipt`.

### What this changes

The second chain is now covered by a real bundle end to end, including the tier that requires an anchor and
the effect binding that reads chain-specific transaction encoding.

### What it does not change

- The captures came from **one public endpoint**. This proves the Voi path works, not that the endpoint is
  independent or honest.
- **No genuine Voi *payment* was captured.** The public Voi algod returns `404` from
  `/v2/blocks/{round}/transactions/{txid}/proof` for `pay` transactions at the rounds tried, so the native
  payment path (`microvoi`) remains verified by unit tests only, not by a live capture. The asset-transfer
  path is verified live. That asymmetry is a property of the node's pruning, not of the code, and it is
  recorded here rather than smoothed over.
- On-chain bonding, a genuine rails receipt, and external crypto review remain open, as documented in
  `docs/PUBLISH-READINESS.md`.

## 0.10.2 — hardening: bounded rate-limiter table (§6.2 of the external validation)

### Fixed
- **Rate-limiter table is now bounded on every call.** The previous implementation pruned expired
  entries only once the table exceeded 10 000 keys, so under a flood from many short-lived addresses the
  table could stay full of live windows for the duration of the window (10 s) without any pruning and grow
  past 10 000; even at threshold, only expired windows were removed, leaving no room for new active peers.
  Pruning now happens on every request, and when the table is full and the client is new, the oldest tracked
  peer is evicted (insertion order) so the table converges on at most 10 000 concurrent buckets. Two requests
  from the same address can no longer collide with a foreign address's window; the candidate identifier is
  never read from a forwarded header, only from the socket peer, so the only way to grow it is actual source
  addresses.
  Found by the static review in `docs/avm-mesh-v0.10.0-validation.md` (§6.2).

### Changed
- No wire, version-pin, or on-chain claim changes.

## 0.10.1 — hardening: sealed resolver (§6.1 of the external validation)

### Fixed

- **`_file_resolver` no longer follows symlinks or reads unbounded files.** The offline
  `avm-mesh verify --evidence <dir>` resolver resolved `path = root / uri.rsplit("/", 1)[-1]`
  and then read the file with no size check and no symlink check, unlike `Store._safe_name`,
  which hardens the same operation. A directory holding a symlink named for a digest, or a
  renamed multi-gigabyte file, could exfiltrate or exhaust memory from a local verifier.
  The name is now restricted to `[A-Za-z0-9_.-]{1,128}`, the path is refused if it is a
  link (on POSIX `O_NOFOLLOW` does this atomically; on Windows an explicit pre-open
  `is_symlink()` covers the common case, though it has a well-known TOCTOU window that
  cannot be closed without OS-level `O_NOFOLLOW`).
  (`MAX_PROOF_BYTES_DEFAULT`, 8 MiB).
  Found by the static review in `docs/avm-mesh-v0.10.0-validation.md` (§6.1).

### Changed
- Runtime behaviour changed, but only to refuse more safely: the resolver is now a
  fail-closed file reader instead of a plain `read_text` call, matching `Store`'s
  behaviour. No on-chain claims, wire formats, thresholds or CLI command surfaces
  changed.

## 0.10.0 — the anchor walk, proven across two intervals

A minor bump for a change in what the package has **proven**, not in what it does. No runtime behaviour
changed.

### Added

- **Three consecutive mainnet captures**, `examples/walk-mainnet-66606848/` (rounds 66606336, 66606592,
  66606848), with SHA-256 pinned in `provenance.json`.
- **`tools/fetch_walk_captures.py`** — fetches consecutive state proofs from an algod endpoint and writes
  them as walk captures, so anyone can reproduce or extend the evidence rather than take ours on trust. It
  refuses a target round that is not an interval boundary, refuses fewer than two hops (one capture cannot
  show chaining), and refuses a response whose message attests a different round than the one requested.
- **`tests/test_walk_multi_interval.py`** — walks the checked-in captures offline: two intervals verified
  from one pinned checkpoint, plus a single-hop control from the middle interval, plus four required
  refusals (wrong anchor, missing interval, corrupted state proof, mislabelled capture).

### What this changes, precisely

The anchor walk shipped in 0.7.0 had only ever been exercised over one interval, because proving two needed
a second capture and only one had been published. That was the weakest claim in the project: the module
exists to carry trust across distance, and a one-hop demonstration is nearly the case it was designed to
avoid. It now verifies two intervals from a single checkpoint on real mainnet data.

### What this does not change

The captures all came from **one public endpoint in one fetch**. This proves the chaining mechanism, not
that the sources are independent: a single endpoint could in principle serve a consistent fiction, and only
a second capture obtained independently would rule that out. `provenance.json` records this in an
`independence` field, the test asserts the field is present, and the README says the same in fewer words.

The anchor is still trust you supply. A walk that succeeds against a wrong checkpoint fails at the first
link, which is the intended behaviour, but nothing here proves the checkpoint was ever the chain's real
signing set.

## 0.9.2 — capture directory hygiene

Three defects that were named in the handover and left open, now closed. All three are in how a capture
directory is read, which is a trust boundary: whatever is loaded here becomes evidence.

### Fixed

- **A symlinked capture is refused.** `path.is_file()` follows symlinks, so a link named `66457600.json`
  pointing anywhere on the host was accepted and its bytes were parsed as a capture. The store already
  refused symlinked entries; the anchor loader did not. Both `load_bundle` and the directory walk now refuse
  a symlink and name the file. Hard links cannot be detected from a path, and the code says so rather than
  implying it sees everything.
- **Gzip is detected from the bytes, not the filename.** The magic bytes decide the decoder, so a capture
  that was compressed and left with a `.json` name now loads instead of failing. The reverse is refused
  outright: a `.gz` name over bytes that are not gzip is a name/content mismatch, and in a trust path that is
  a reason to stop rather than to guess. The refusal says exactly that, instead of letting the JSON parser
  report `Expecting value`.
- **The directory cap is enforced while scanning.** `sorted(root.iterdir())` listed every entry before any
  limit applied, so a directory with a million names was paid for in memory whether or not one capture was
  read. The scan now refuses past `MAX_DIRECTORY_ENTRIES` (10240) as it goes, so memory tracks the cap rather
  than the directory an attacker chose.

### Verified

Six tests added: five refusals and one positive control (`test_a_directory_within_the_cap_is_walked_normally`),
so the cap cannot pass by refusing everything. Three of the guards are proven by mutation on Windows; the
two symlink refusals cannot be, because this Windows host cannot plant a symlink without developer mode.
Those two skip locally and are proven on Linux instead, where they run rather than skip, and where the
guards were removed and the tests required to fail before being restored. A skip that hides an unproven guard is the failure
mode this release is about, so the Linux run is the one that counts.

## 0.9.1 — close an ambiguity bypass found in review

### Fixed

- **A part carrying the extension but a null receipt no longer lets a second payload through.** Both
  verifiers detected duplicate payloads by testing whether the payload value was non-`None`, so
  `[{extension, receipt: null}, {extension, receipt: <valid>}]` was accepted by both: the ambiguity check
  was skipped by the very shape it exists to refuse. Both now count extension-bearing parts, and
  `null_payload_then_valid_payload` is the fourteenth vector, required to be refused by both.

Found by the independent validation gate on 0.9.0. Two of its three other findings were refuted with
reproductions rather than applied: the claimed missing `kind`-tag check is present at `a2a.py:132` and the
`kind_contradicts_payload` vector is refused by the library, and the claimed misspelling of
`MAX_CANONICAL_B64_CHARS` does not exist in the file.

## 0.9.0 — extension conformance vectors and a standalone verifier

### Added

- **`tests/vectors/a2a/settlement-evidence-v1.json`** — thirteen cases for the settlement-evidence
  artefact: two that must pass, eleven that must be refused, each with the reason it is in the set.
- **`tools/verify_settlement_artifact.py`** — a standalone verifier for the artefact that imports nothing
  from AlgoVoi: standard library only, short enough to read before running. It establishes the envelope and
  LEVEL 1 integrity, and reports LEVEL 2 and LEVEL 3 as `not checked` rather than omitting them, because a
  convenience verifier that stayed quiet about the levels it skipped would be worse than none.
- **`docs/EXTENSION-VECTORS.md`** — what the vectors prove, what each verifier establishes, and the five
  guards proven by removing them.

The TCK has requirements for extensions as a mechanism but none for the payload a third-party extension
carries, so a green TCK run cannot say whether this extension accepts what it should and refuses what it
should not. These vectors are that check, and they are offered openly so another implementer can hold us to
them.

### Changed

- **`verify_artifact` refuses an artefact carrying two settlement-evidence payloads.** It previously took
  the first match and ignored the rest. A sender who means one thing does not send two, and a receiver that
  silently picks one can disagree with another receiver reading the same bytes. The standalone verifier makes
  the same refusal, and a vector pins both.

### Verified

Every case is run through the library and the standalone tool and the suite fails if they disagree. Each of
the five guards was removed in turn and the matching case required to fail, then restored.

## 0.8.0 — testnet witness-bonding proof of concept

New public surface, all of it testnet-only and declared-value-only. The limits are
stated here because they are the point of the release, not a footnote to it.

### Added

- **`bond.BondPolicy`** — a declared-bond floor and a slash fraction, with exact
  rational arithmetic (no binary float). Threaded through `WitnessSet` and
  `validate_corroboration`; the defaults reproduce the previous constants, so
  existing callers behave identically.
- **`poc.EnforcementLedger` and `poc.verify_ledger`** — the challenge flow:
  examine a witness's attestation against the challenger's own anchor, and on a
  failed verification record a REMOVED event and mark the witness inactive. The
  log is hash-chained, truncation-evident through a head sidecar, written
  durably before the decision takes effect, and guarded against a second writer
  forking it. Tamper **evident**, not tamper proof: rewriting both the log and
  the sidecar, or rolling back an uncheckpointed tail, needs an externally
  retained `expected_head_hash` to detect.
- **`testnet-v1.0`** admitted to `SUPPORTED_CHAINS`. Algorand testnet emits
  Falcon-1024 state proofs, so the PoC runs on real evidence. Isolation is
  enforced, not asserted: a testnet attestation is refused where the mainnet
  genesis is pinned, with a control proving the same attestation verifies under
  its own pin.
- **`examples/testnet-proofpack-68812906.json`** plus
  `examples/testnet_poc_demo.py`, and **`docs/POC-RUNBOOK.md`**.
- **`docs/BONDING-DECISIONS.md`** — the decision surface offered to the Algorand
  and VOI communities, with a bootstrap configuration so the flow can be
  exercised before any lasting parameter is set.

### Not included, deliberately

- **No escrow reader, and therefore no on-chain verification of a bond.** A bond
  is a declaration; `escrow_txid` is an assertion. Reading an account balance
  would not fix that, because a balance is not a commitment: the operator can
  withdraw it at will. Verification needs an escrow *application* that holds the
  funds and enforces the conditions, and that needs the four parameters this
  release declines to invent. Adding a balance check here would have looked like
  progress and proved nothing.
- **No slashing.** A failed challenge removes the witness administratively and
  records the event. No funds move.
- **Testnet consensus is testnet-grade security.** Nothing in this release should
  be described as production security.

## 0.7.1 — test packaging correction (no runtime change)

The published 0.7.0 sdist carried three tests that call a Falcon-1024 signer.
`pqcrypto` is not a runtime dependency and its 0.1.0 release has no Linux wheel,
so a recipient running the sdist suite saw three skips. A skip reads as a pass in
a summary line, which is precisely the failure mode the clean-room gate exists to
remove, and shipping an archive whose own gate policy would reject it is wrong
even when no runtime code is affected.

Those three tests now carry a `signer` marker. The portable gates run
`-m 'not signer'` and still fail on any real skip; the signing acceptance path is
run explicitly in a signer-enabled environment and passes there.

Runtime behaviour is unchanged from 0.7.0. No receipt, verification, service or
CLI semantics were touched.

## 0.7.0 — anchor derivation + security hardening

**Behaviour change (SSRF hardening):** `avm-mesh corroborate` now refuses to fetch witnesses whose host
resolves to a non-public address (loopback, RFC1918, link-local, reserved, multicast, unspecified)
by default, and all redirect hops are re-resolved and re-checked. Previously, pointing `corroborate`
at a loopback witness worked; it now needs the explicit `--allow-private` flag. `corroborate --directory`
(directory documents are attacker-influenced) has always been denied private addresses; the change makes
`corroborate --witness` behave the same unless opted in. Operators embedding a local witness in their
corroborate invocation should add `--allow-private`.

**Resource limits:** witness service now caps concurrent connections at 64 (503 on saturation) instead
of spawning a thread per connection. Proofpack, card and receipt reads are each capped independently.
Library reads (`Store.get_proofpack`) enforce the proofpack cap so embedders meet the same limit as the
HTTP path.

## 0.7.0 continued (anchor derivation)

### Added — `avm-mesh anchor`

The gap this closes: a verifier needs `TrustedVoters`, and until now the only ways to obtain them were to be
handed them or to read them out of the bundle's own previous message — which proves nothing, because whoever
assembled the bundle chose it. The worked example in this repo had to carry a caveat for exactly that reason.

`avm-mesh anchor` takes one pinned checkpoint (round, voters commitment, proven weight, genesis hash) plus a
directory of captured proofpacks, verifies every interval forward with `authenticate_chain`, and prints the
`--voters-commitment` / `--ln-proven-weight` the verifier needs:

```
authenticated 1 interval(s) from the checkpoint
--voters-commitment  71Oh0YaxEA59JIgWUjMmnpz0KG8lWJ2jwXQiTYxp15FulxCMNfHfBMHT/8hyTNv2tMdWZl+YOz8go5DczFfuLw==
--ln-proven-weight   2230418
trust basis:         pinned checkpoint; every interval verified forward from it
```

A wrong checkpoint fails at the first link (tested: `ln_proven_weight + 1` gives exit 2, "coin selection
failed at round 66457600"), so a bad checkpoint cannot produce a successful walk. The checkpoint remains
trust — the walk proves "authentic back to the checkpoint you chose" — but one labelled trust decision
replaces one per bundle, and the distance between them is auditable.

Capture directories are strict: the filename must be the round the bundle's own message attests, because a
mislabelled capture would otherwise be walked as if it belonged somewhere it did not.

Captures are also size-capped at 8 MiB, checked twice: against the file on disk before opening, and against
the bytes actually read after decompression. The second check exists because a gzip bomb is small on disk and
enormous in memory, so a `stat()` alone would wave it through.

### Security — independent review findings

An independent review (Codex) of the 0.7.0 candidate found eight defects; a second reviewer (Claude) then found
three more. Fixed here, with the evidence status of each recorded in the commit that fixes it:

- **LEVEL 2 was silently skipped.** The CLI accepted `--operator-pubkey-b64` and never passed a verifier, so a
  requested check did not run and the command exited 0. Now wired, and a key with no signature to check fails
  closed. The rails entry point declares its own signing convention (hex digest) rather than inheriting the
  mesh one (raw digest) — the two are not interchangeable.
- **Corroboration could be aborted or fooled** by a malformed witness card (unhashable or empty `operator_id`),
  and could report agreement across two different chains. Identity fields are validated, chains are compared,
  and a card contradicting its own receipt is refused.
- **Witness responses were unbounded**; per-endpoint caps now apply to cards, receipts and proofpacks.
- **Anchor loaded every capture in a directory**, not just the rounds the walk needed.
- **Append-only receipt storage had a check-then-write race**; commits are now atomic (`link()` with an
  `O_EXCL` fallback), so two conflicting writers cannot both succeed.
- **The sdist could not run its own tests** (missing `conftest.py` and `_assets.py`); `MANIFEST.in` fixed the
  contents and the artefact checker now extracts the sdist and collects its tests.
- **Malformed captures escaped `MeshError`** (truncated gzip, non-ASCII digit filenames).
- **SSRF:** a fetched directory could point the client at internal addresses. Outbound fetches now resolve and
  refuse non-public targets and re-check every redirect; `--allow-private` opts a local witness back in.
- **Concurrency:** the witness server now caps concurrent connections (503 when saturated) instead of spawning a
  thread per connection without limit, and the library read path enforces the same proofpack size cap as HTTP.

### Note on a guard found redundant

The interval-grid check duplicates one inside `authenticate_chain`. Mutation testing showed removing it changes
no outcome — it stays only because it fails *before* the capture directory is read. Recorded rather than
quietly kept, so it is not mistaken for load-bearing.

### README

The worked example's caveat is replaced by the procedure that removes it: derive the anchor, don't copy it.

## 0.6.0 — replaces 0.5.0

### Fixed — 0.5.0 declared a licence it did not ship

`avm-mesh` stated Apache-2.0 through the deprecated `license = {text = ...}` form and shipped **no `LICENSE`
and no `NOTICE`** — not in the repository, the wheel, or the sdist. That contradicts the estate decision
(memory-graph claims 11229 and 4594: licence files normalised estate-wide, PEP 639 SPDX, Apache-2.0 LICENSE
and NOTICE in both artifacts) which `avm-proofpack` already follows.

Now: `license = "Apache-2.0"` with `license-files = ["LICENSE", "NOTICE"]`, both files in the repository,
`setuptools>=77` so the metadata is actually understood, and no `License ::` classifier contradicting the
expression. `tools/check_artifacts.py` inspects the **built** wheel and sdist for the files and the
`License-Expression`, and CI runs it on every push.

### Added — CI, including the Python floor that was only asserted

`Requires-Python: >=3.10` had never been executed. `.github/workflows/ci.yml` runs the suite on 3.10 and
3.12 and checks artefacts separately. `avm-mesh` previously had no CI at all while its dependency did.

### Added — witness discovery

`avm-mesh corroborate --directory <url-or-path>` reads a published directory document
(`{"version": 1, "witnesses": [...]}`), and `/.well-known/mesh-directory.json` is the conventional location.
A directory is a lead and never a trust root: each entry is checked against the witness's own card, and a
mismatch means that witness does not count and the disagreement is named. Unknown fields, duplicate URLs,
wrong versions and non-http URLs are refused.

### Added — service resource bounds

The witness service had no limits. Now: proofpacks over 8 MiB refused at store *and* on serve, request paths
over 2048 characters get 414, over 120 requests per client per 10 s gets 429 with `Retry-After`, and a stalled
connection is dropped after 10 s. Tunable via `--max-proofpack-bytes`, `--rate-limit`, `--rate-window`.

### Added — a worked example, with its limits stated

`examples/` carries a receipt and the mainnet proofpack it points at (round 66457600),
`tools/make_example.py` regenerates them, and `tests/test_example.py` fails if the committed pair stops
verifying. The README prints the exact command and says what it does **not** establish: the anchor is derived
from the bundle's own previous message, so the tier's mechanics are demonstrated with real data while
independence of that anchor is not claimed.

### Process note

0.4.2, 0.4.3 and 0.5.0 were published in one session without consulting the memory graph for the packaging
standard. 0.4.2 shipped without a console script and with a documented-but-unimplemented `serve`. Publishing
is irreversible; the graph check costs one command. `docs/RELEASE-CRITERIA.md` now lists what must be true
before the next upload.

## 0.5.0

### Added — `avm-mesh corroborate`: the mesh actually checking itself

Until now the mesh could serve a receipt and verify one. It could not answer the question the mesh exists
for: *do independent operators agree?* `bond.py` held corroboration rules, but nothing went out to several
witnesses and applied them.

```sh
avm-mesh corroborate --txid X --witness https://w1 --witness https://w2 --min-operators 2
```

Three refusals define the feature:

1. **Endpoints are not operators.** Independence is counted over distinct `operator_id`s from each witness's
   card. One operator behind two URLs is one voice — the cheapest fake mesh there is.
2. **A pointer is a claim until the bytes are hashed.** For every witness the client fetches the proofpack
   and recomputes its digest. A witness serving different bytes than it points at is not counted. (Our own
   service refuses to serve tampered bytes at all — the store is content-addressed — so this check protects
   against *other* implementations, and is tested against a stubbed dishonest peer.)
3. **Disagreement is named, not averaged.** Different digests, rounds or tiers each fail with a reason.

Exit codes 0/2/3, `--json` for machines. 15 tests, including three that drive the CLI as a subprocess
against live in-process witnesses.

### Note on our own service

The tampered-store test initially failed because the service returns HTTP 500 rather than serving wrong
bytes. That is the store doing its job one layer earlier than the client check; both behaviours are now
pinned, and the client check is exercised separately so it does not go untested just because our own code
is honest.

## 0.4.3

### Fixed — the documented `avm-mesh` command did not exist

`README.md` documents `avm-mesh verify` and `avm-mesh serve`. `pyproject.toml` defined no console script, so
**every PyPI install got `avm-mesh: command not found`**. The package worked via `python -m avm_mesh`, which
is what the changelog and the E2E tests used, so nothing caught it.

Added `[project.scripts] avm-mesh = "avm_mesh.cli:main"`.

### Fixed — `avm-mesh serve` was documented and not implemented

The same README documents `avm-mesh serve --root ./store --port 8080 ...`. The CLI parsed only `verify`,
so the command exited with an argparse error. `serve` is now implemented over `service.Store` /
`WitnessInfo` / `serve_forever`, with the documented flags.

An incomplete witness card **fails closed**: supplying some identity fields and not others exits 3 rather
than starting a witness whose published card is not what the operator configured. Serving without any card
remains valid (a plain store node).

`Store()` also wrapped filesystem failures in `MeshError` instead of letting `FileExistsError` escape —
a path that is a file rather than a directory is a configuration error, not a traceback, and the package
promises never to leak `OSError` to callers.

### Guarding it

`tests/test_packaging.py` derives the command list from the README and asserts each one exists on the
parser, and asserts `[project.scripts]` names a real callable. `tests/test_serve_cli.py` parses the exact
README invocation, checks the documented flags, and pins the fail-closed behaviour. Every earlier test
imported the module, which is precisely why none of them noticed.

### Why 0.4.2 shipped it

Because publication is the first time the package is used the way the README says it should be. No test in
the repo invokes the console script — they import the module. A test that shells out to `avm-mesh --help`
would have caught it, and one now does.

## 0.4.2

### Fixed — the A2A artifact used a wire format v1.0 removed

A2A **v1.0 removed the inline `kind` discriminator** as a breaking change (spec appendix A.2.1). A DataPart
is now identified by the presence of the `data` member:

```json
// v0.3.x (what we emitted)        // v1.0 (what we emit now)
{"kind": "data", "data": {...}}    {"data": {...}, "mediaType": "application/json"}
```

Emitting the legacy form to a v1.0 peer produces a part it cannot parse: there is no `kind` to read and the
extra member is unexpected. `as_artifact()` now emits the current form.

`verify_artifact()` **accepts both**, because the spec asks implementors to dual-handle during the overlap
period and a peer may still be on 0.3.x. A part whose `kind` contradicts its payload (`kind: text` carrying
`data`) is still refused.

### Found by

Reading the TCK's own specification rather than assuming conformance. Five new tests pin: the emitted part
carries no `kind`, the legacy part still verifies, a contradictory `kind` is refused, the extension
descriptor matches the §4.6.1 declaration shape, and advertising preserves v1.0 `supportedInterfaces`.

### Scope

This is conformance to the **published spec text and schemas**, not a TCK run. Executing the full suite
needs a running A2A SUT, which is a separate piece of work; saying "TCK-validated" on the strength of these
tests would be a false claim.

## 0.4.1

### Fixed — 0.4.0's rails verifier was not compatible with real rails receipts

Reading the shipped `verify_settlement_receipt.py` line by line showed four differences. The first would
have rejected every genuine receipt:

1. **Signature payload.** The rails sign `sha256(canonical_bytes).hexdigest().encode("utf-8")` — 64 ASCII
   bytes — not the raw 32-byte digest. 0.4.0 signed the raw digest.
2. **Embedded key.** Receipts carry `public_key_b64`. Now supported, and reported as `"self-asserted"`
   unless the caller pins a key: whoever writes the receipt chooses the key, so verifying against it proves
   internal consistency, not the operator's identity. A pinned key that disagrees with the embedded one is
   refused.
3. **Exit codes.** The rails use 0 / 1 / 2; the CLI uses 0 / 2 / 3. `python -m avm_mesh.rails` now
   translates, so an existing script does not read a failed verification as a usage error.
4. **Field names** (`settlement.tx_id`, `amount_microunits`, `issuer_did`, `signature.kid/alg`) documented,
   with `content` returned decoded rather than renamed.

18 tests, including one that captures the exact payload bytes the signature is checked over — the
convention that, got wrong, yields a verifier that passes its own tests and rejects every real receipt.

### Lesson

This is what "not round-tripped against a genuine receipt" cost. The shape was compatible; the cryptography
was not. Reading the consumer's source is not optional when claiming drop-in compatibility.

## 0.4.0

### Added — the rails adoption kit (`avm_mesh.rails`)

`verify_rails_receipt()` verifies the AlgoVoi Payment Rails receipt format and reports three levels
separately, never collapsed into one boolean:

| Level | Check |
|---|---|
| 1 | `sha256(canonical_bytes) == content_hash` |
| 2 | the operator's Falcon-1024 signature over that hash — via `avm_proofpack`, **not** `pqcrypto` |
| 3 | consensus attestation, anchor-required, inside the hashed bytes |

It is an **adapter**, not a second implementation: the rules live once in `sealed` and `attestation`.
Two implementations of the same verification logic is how one of them ends up weaker.

`python -m avm_mesh.rails verify receipt.json ...` delegates to the existing CLI, so the exit codes and
output are identical by construction.

### Why this exists

The rails' shipped standalone verifier imports `pqcrypto.sign.falcon_1024`, which fails on any current
install (`pqcrypto` 1.0.0 removed Falcon when PQClean was archived). It also stops at LEVEL 2, where the
trust root is the operator. `docs/RAILS-MIGRATION.md` covers the swap, the dependency change, the
customer-facing trust statement, and what remains unproven.

### Validation

- 13 new tests. Negative control: disabling the integrity comparison turns **2 failed, 11 passed**;
  restoring returns **13 passed** — which also demonstrates that LEVEL 3 is protected by the LEVEL 1 hash.
- The first mutation attempt silently matched nothing; the assertion that it applied is what caught it,
  not the test result.

## 0.3.0

### Fixed — the settlement amount is now bound to the transaction

A receipt carried an `amount` supplied by the producer, and nothing compared it to what the transaction
actually moved. A merchant reading `stake_attested` next to that figure would reasonably, and wrongly,
read the amount as attested too. New `avm_mesh.effects` reads the amount out of the **authenticated**
`SignedTxnInBlock` via `avm-effectproof`, after `verify_bundle` has proven those bytes, and binds it in
both `produce()` and `verify_sealed()`.

Fail-closed by construction: any shape whose amount cannot be mapped to a single unambiguous on-chain
transfer — an app call, a key registration, a close-remainder, an asset the transaction did not move —
is refused. A receipt gets to assert an amount only when the evidence proves that exact amount moved.

Contributed by Claude/Codex with mutation evidence for both guards (produce: 1 failed → restored 5
passed; verify_sealed: 1 failed → restored 10 passed).

### Changed — new required dependency

`avm-effectproof>=0.1.1`. Its wheel must be staged alongside `avm-proofpack` for an offline install.

### Docs corrected

- `bond.py` no longer claims to be "verifiable on-chain". It reasons over **declared** bond values and
  does not read the chain; "bonded" means "claims a stake at or above the floor".
- The review request's "LEVEL 2 has never seen a real key" was overstated once the `pqcrypto` dependency
  was removed; it now states precisely what the KAT vectors prove and what remains unproven.

### Docs

- **`docs/PQC-FALCON.md`**: why `pqcrypto` 1.0.0 no longer provides Falcon (PQClean archived; upstream
  rewrote onto Rust and dropped it), why we cannot substitute ML-DSA (Algorand/Voi fix Falcon in the
  protocol), the implementation we use instead, the rejected alternatives, and the residual risks.

### Notes

- **202 tests, 0 skipped**, clean-room green in a fresh Docker container on VM2 with an offline
  `--no-index` install of `avm_mesh` + `avm_effectproof` + `avm_proofpack`, the suite run against
  site-packages, and the `tools/cleanroom.sh` gate enforcing skips-as-failures.
- 201 passed + 1 skipped on a Windows host, where the symlink-refusal test cannot plant a symlink.

## 0.2.2

### Fixed

- **Witness equivocation.** `put_receipt` overwrote unconditionally, so a witness could serve one receipt
  for a transaction, let a client verify it, then replace it with a different receipt (other tier, pointer
  or corroboration) for the next client. Both receipts can be individually valid — the *service* is the
  attack. Receipts are now append-only per transaction: an identical rewrite is idempotent, a different
  one is refused.
- **Stored receipts are now corruption-checked on read**, via a `<txid>.sha256` sidecar written with the
  receipt, matching the discipline proofpacks already had (the filename is the digest).

### Notes

- Found by attacking my own module rather than waiting for review: the question was "what can this
  service do that a verifier would not notice", and the answer was replace its own history.

## 0.2.1

### Fixed

- **`Witness` and `WitnessInfo` accepted non-string identities.** The guards tested truthiness, so
  `Witness(42, ...)` and `Witness("a string", ...)` were valid records: an id no other record could ever
  match, and a bond amount that was not a number. Both now require a non-empty `str`, and
  `bond_microalgo` must be an integer (`bool` excluded).

### Added

- **95 fail-closed tests.** Every public entry point is fed `None`, numbers, strings, bytes, lists,
  mappings and booleans, and must raise `MeshError`/`BondError` — never `TypeError`, `AttributeError` or
  `KeyError`. An unexpected exception type is what a caller's `except Exception` swallows into a pass, so
  the *type* of the refusal is part of the contract.
- **`tools/red_team.py`** — attempts the forgeries a real adversary would try (path traversal, digest
  swap, tier upgrade, anchor mismatch, wrong genesis, interval shift, transaction reuse, policy chain)
  against the **installed** package. A positive control runs first: if honest evidence fails to verify,
  the run aborts rather than reporting vacuous refusals.

### Notes

- 189 tests. Rule D of the audit still reports ~95 advisories: it measures whether refusal *messages*
  are pinned by `match=`, and these tests assert behaviour without pinning prose. That metric is a weaker
  proxy than the property the tests actually establish, and is recorded as such rather than inflated by
  adding string matches.

## 0.2.0

The framework becomes complete: a settler can publish, a witness can serve, and a merchant can verify
against a single auditable policy.

### Added

- **`produce`** — the producer path: store the proofpack, then seal the receipt. Evidence is persisted
  before anything points at it, so a receipt never references bytes that failed to write. `produce()`
  refuses rather than downgrades: evidence below `stake_attested` publishes nothing.
- **`service`** — the witness. Serves receipts and content-addressed proofpacks over stdlib
  `http.server`. Re-hashes on read and refuses a blob whose content no longer matches its name;
  corruption returns `500`, not `404`, because it is a fault rather than an absence. `Store.resolve`
  rejects any URI that does not name a digest, so the courier cannot choose the evidence.
- **`trust`** — `TrustPolicy`: chain, genesis hash, voters anchor, bonded witnesses and corroboration
  threshold in one document. `require_witness_coverage()` refuses a policy demanding more independent
  witnesses than are bonded, so misconfiguration fails at load rather than on every request.
- **CLI `serve`** — run a witness from the command line.
- **CLI LEVEL 2** — `--operator-pubkey-b64` checks the operator's Falcon-1024 signature.
  `pqcrypto.verify` returns a bool rather than raising, so the return value is checked; an unchecked
  call reads as success for any signature.

### Security

- `verify_receipt` takes `expected_genesis_hash_b64` and enforces it against the **authenticated block
  header**. Previously the standalone path checked only `receipt.chain`, a string a fork can reuse.
- The receipt's attested interval must equal the interval the evidence actually attests. Before, a
  receipt could point at a real proofpack covering a different interval and still read as verified.

### Notes

- **94 tests**, validated in a **fresh Docker container on VM2** (`avm-mesh-clean`): both wheels installed
  **offline** (`--no-index`) into a clean `python:3.12-slim`, the suite run against the *installed*
  package rather than the source tree, 94 collected / 94 passed. Negative control inside the container:
  disabling the attested-interval guard turned `test_receipt.py` red (1 failed, 13 passed); restoring it
  returned 14 passed.
- End-to-end path proven on a **fresh mainnet capture** (round `66474240`, interval
  `66473985 → 66474240`) with sockets blocked, not only on the original fixture.
- `docs/OPERATIONS.md`: anchor-first deployment guide, the policy document, and a table of what each pin
  stops.
- `avm-proofpack>=0.4.1` is required. That release made `stake_attested` anchor-required after the
  tier was found forgeable; 0.1.x of this package inherited the flaw and is superseded.
- Deliberately absent: a round-inside-interval check. It is unreachable given the interval equality,
  the round binding, and avm-proofpack's own invariant, and an unpinnable guard is worse than none.

## 0.1.1

- Adopt anchor-required `stake_attested` (avm-proofpack 0.4.1). Scheme `avm-stateproof-falcon1024-v2`;
  v1 attestations are refused by name because their semantics were forgeable.
- `attest()`, `verify_attestation()`, `seal()`, `verify_sealed()`, `verify_artifact()` all require the
  caller's `TrustedVoters` anchor; the verifier checks it against the anchor recorded in the claim.
- A caller-supplied corroboration threshold with no `witness_set` is an error rather than a silent skip.

## 0.1.0

- Settlement receipts: digest + pointer, with substitution, upgrade and identity bindings.
- LEVEL 3 consensus attestation for the AlgoVoi Payment Rails receipt format.
- Sealed receipts (`canonical_bytes_b64` + `content_hash`, optional operator signature).
- Standalone offline verifier CLI with exit codes.
- A2A settlement-evidence extension (optional, `required: false`).
- Witness bonding with enforced independence: one witness per operator and per escrow, and
  `require_corroboration()` refuses rather than returning a short list.
