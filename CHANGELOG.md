# Changelog

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
