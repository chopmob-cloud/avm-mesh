# Changelog

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

- 85 tests. Validated in a VM2 clean-room with a negative control: the harness is proven able to fail.
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
