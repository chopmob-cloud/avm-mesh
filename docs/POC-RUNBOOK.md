# Testnet proof-of-concept run sheet

What this is: a live, runnable demonstration of the whole witness-bonding flow
(declare a bond, attest, corroborate, challenge, remove) against REAL Algorand
testnet consensus. Its job is to turn "here is a design" into "here is the
mechanism running that you can inspect", so an operator or reviewer can judge it
before any real stake, real governance, or on-chain slashing exists.

It is the near-term, in-house step behind `docs/BONDING-DECISIONS.md` (the open
proposal to the Algorand and VOI communities). The PoC claims nothing beyond a
working mechanism on testnet.

## Run it

Offline, from the committed example bundle (repeatable, no network):

```sh
python examples/testnet_poc_demo.py
```

Live, pulling fresh evidence from a testnet node (capture any confirmed testnet
transaction whose round sits inside a state-proof-attested interval):

```sh
python examples/testnet_poc_demo.py --capture \
    --node https://testnet-api.algonode.cloud \
    --txid <TXID> --round <ROUND>
```

Expected output: `attest` reaches `stake_attested` on `testnet-v1.0`;
`verify_attestation` confirms it with the testnet genesis pinned; the honest
witness is upheld; a witness serving a false attestation is removed with the
reason `evidence attests a different settlement`; it drops out of the independent
corroborator set; and the append-only audit ledger's hash chain verifies.

The same path is covered as a test:

```sh
AVM_PROOFPACK_TESTS=<avm-proofpack>/tests AVM_MESH_REQUIRE_FIXTURE=1 \
  python -m pytest tests/test_testnet_poc_example.py -q
```

## What the PoC proves

- Algorand testnet emits Falcon-1024 state proofs, and `avm-mesh` builds a
  verified bundle from a testnet node, attests LEVEL 3 against it, and verifies
  it offline with the testnet genesis hash pinned. (`testnet-v1.0` is admitted in
  `attestation.py`; the genesis pin still isolates it from mainnet.)
- The bonding mechanism runs end to end: a witness that serves an attestation
  which does not verify against the trusted anchor is detected, removed, and
  dropped from corroboration, and every verdict is recorded in a hash-chained,
  truncation-evident ledger.

## What the PoC does NOT prove (read before quoting any of it)

- **Testnet, not mainnet.** Testnet consensus is testnet-grade security. Nothing
  here is a mainnet guarantee.
- **Declared bonds, not escrow.** `bond.py` reasons over declared bond figures; it
  does not read an on-chain escrow. "Removed" is administrative, and the declared
  forfeit is illustrative arithmetic. No funds move. On-chain bonding is the
  work that follows community ratification (`docs/BONDING-DECISIONS.md`).
- **Not an independence claim.** The anchor is taken from the bundle's own
  previous state-proof message (as the repo's fixtures do), so it exercises the
  tier mechanics but does not show the walk is more than one operator's view. A
  second independent capture is a separate blocker (`docs/HANDOVER.md` #2).
- **The PoC does not adjudicate intent.** A removal follows a failed verification;
  it is not a finding of dishonesty. Separating malice from an operational
  failure, with a challenge deposit, dispute window and arbiter, is exactly what
  the community proposal leaves open.
- **The ledger is tamper-EVIDENT, not tamper-PROOF.** In-place edits break the
  hash chain and truncation is caught by the `.head` sidecar, but a writer who
  rewrites both the log and the head, or who rolls back the single uncheckpointed
  tail entry after a crash, is only detected by an externally retained
  `expected_head_hash`. A single writer per ledger file is required (no OS lock).

## Where it sits

- `docs/BONDING-DECISIONS.md` — the open proposal to the Algorand and VOI
  communities; the PoC is the thing they can inspect to decide whether to engage.
- `docs/HANDOVER.md` — the standing blocker list; the on-chain escrow reader and
  slashing contract are built only if a community ratifies the parameters.
- Validation: the PoC code (`bond.py`, `poc.py`, the `attestation.py` testnet
  admission) was reviewed by Codex on the running code across several passes; the
  ledger's durability and tamper model were hardened until the only residual was
  the documented external-anchor limit above.
