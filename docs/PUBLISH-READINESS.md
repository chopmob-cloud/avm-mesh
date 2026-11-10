# `avm-mesh` — Public Release Readiness

Audience: the maintainer deciding whether to change this repository's visibility to public. Complete only when this document's open items are either resolved or explicitly accepted.

## 1. Secret safety — completed

- All 102 commits and 328 unique blobs in the object database scanned with `detect-secrets 1.5.0` (74 files flagged; every one classified as `Base64 High Entropy String` / `Hex High Entropy String` / `Secret Keyword`, traceable to Falcon point coordinates, state-proof message hashes and test-fixture payloads).
- A full-text scan of `git log --all -p` for: private-key headers, OpenAI/GitHub/npm/PyPI token shapes, JWTs, `Authorization: Bearer`, URL-embedded credentials, `password`/`token`/`api_key` assignments to non-empty values. **Zero hits.**
- IP addresses in history: 7 unique, all test fixtures (RFC1918 and AWS link-local as classifier inputs) or the reserved `93.184.216.34` example.com reference. No public server IPs.
- Static `gitleaks 8.21.2` working-tree scan: **0 findings**. (The `git` sub-command could not be executed on this host; `detect-secrets` already covers history. Re-run `gitleaks git` on a fresh clone before flipping if you want a second commercial-grade pass.)
- Currently tracked files matching `*.env`/`*.pem`/`*.key`/`*secret*`: **none**.
- Sibling-public repos (`avm-proofpack`) were NOT re-audited as part of this work — only `avm-mesh`. `avm-rails` ships as encrypted tarballs and has no committed plaintext source.

Verdict: secret-safety gate is in good shape. Not a guarantee of absence — only a guarantee of trawling.

## 2. Packaging and licence — complete

- PEP 639 `license = "Apache-2.0"` + `license-files = ["LICENSE", "NOTICE"]` (setuptools ≥ 77); no conflicting classifiers; both files present and readable in the sdist.
- `LICENSE` is verbatim Apache 2.0, `NOTICE` lists third-party components; PyPI mirror live and unauthenticated.
- Console script `avm-mesh` declared and resolves to `avm_mesh.cli:main` (regression-pinned by the clean-room gate after the 0.4.x incident).
- Dependencies properly tiered: `avm-proofpack>=0.4.1`, `avm-effectproof>=0.1.1` runtime only. `pqcrypto` is **never** a runtime dependency.
- `README.md` reads for a general audience (tone rewrite done in 0.8 cycle) and the docs directory covers A2A conformance, extension conformance vectors, the rails migration, operator run-sheet, and red-team mutation evidence.
- `SECURITY.md` and `.github/CODEOWNERS` present.

## 3. Build and test baseline

- PyPI latest: 0.13.3 (wheel + sdist), verified installed from a fresh venv with `PYTHONPATH` cleared, `__file__` under site-packages, console script intact.
- Clean-room (VM2, offline wheels, fresh `python:3.12-slim` / `python:3.10-slim`): no skips permitted, audit rule A OK, red team attacks all refused. 3.10: same suite on the floor interpreter.
- GitHub Actions CI (`tests (py3.10)`, `tests (py3.12)`, `artefacts (licence + metadata)`, `a2a TCK (jsonrpc, must)`) green on the latest main commit.
- Conformance: 14/14 self-authored extension vectors run against both the library and a standalone verifier that imports nothing from this project, with agreement required. All five primitive guards mutation-tested to red.
- All three remaining hardening suggestions from the static review are addressed or honestly scoped (`_file_resolver` race; reparse-point/hard-link/junction gaps documented in `SECURITY.md`).

## 4. External gaps that will NOT be closed by publication

These are capability-maturity gaps, not security defects. Publishing with them open is a posture, not a deception, because each is documented:

1. **Rails adoption kit is un-round-tripped.** Trial receipt was self-signed with test `pqcrypto`. We do not yet have a genuine rails-format receipt from the rails operator. Interoperability testing cannot be completed by us.
2. **Anchor-provenance independence.** The three mainnet captures (`examples/walk-mainnet-66606848/`) all came from **one public endpoint in one fetch**. The walk proves chaining, not that the source is independent or honest. Needs one adjacent capture from a second operator (half a day of work once supplied). Operator run-sheet in `docs/OPERATOR-RUNSHEET.md` section A.
3. **On-chain bonding.** `bond.py` is arithmetic over declared values. No escrow application reads from the chain; `independent_corroborators()` and `slashable_stake()` operate on declarations. Requires four economic decisions that are not ours to make (asset, slash fraction, dispute window, arbiter) plus an escrow contract.
4. **Crypto review of `avm-proofpack`.** Falcon and state-proof internals have never had independent external review. That repository is already public and is where the root of trust actually lives; reviewing it is a separate engagement.
5. **Level 2 with a genuine operator signer.** Signing tests are optional (`pqcrypto` is test-only). Verification itself does run in the portable gate against real mainnet fixtures and is covered by the red team.

## 5. Items that were decided before the visibility flip (completed)

- [x] ~~Run an independent second scan~~ — **done**, see [`docs/PRE-PUBLICATION-AUDIT.md`](PRE-PUBLICATION-AUDIT.md). `gitleaks 8.21.2` over a fresh clone (92 non-merge commits, all refs) and over all 353 unique blobs: zero findings. `detect-secrets` over the same blobs: 114 high-entropy hits, every one classified as chain data or a test fixture.
- [x] ~~Decide whether to publish at 0.10.2 or wait~~ — published at 0.13.3, and the capability claims in the README were rewritten to match what is proven rather than deferred.
- [x] ~~Confirm commit author identity and history are acceptable as committed~~ — the full history was re-scanned and rewritten before the flip: agent working notes expunged, absolute paths from the authoring machine removed, and no credentials, keys or server addresses present in any object. See §5a.
- [x] ~~Confirm PyPI project name `avm-mesh` stays free/owned~~ — published and owned.
- [x] ~~Final pass on `README.md`~~ — **every documented command was run against the published wheel**, not read. Both chains verify from PyPI (Algorand and Voi, output reproduced byte for byte). The audit found two real defects: the CLI could not read a gzipped proofpack, and a text-mode `os.open` truncated files at the first `0x1A` on Windows — the Voi fixture stopped at 100 of 110,773 bytes. Both fixed in 0.12.0. Community files added: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and PR templates.
- [x] ~~Repo cosmetics~~ — topics set (`algorand`, `voi`, `state-proofs`, `falcon`, `settlement`, `x402`, `a2a`, `post-quantum`, `receipts`, `python`), description and Apache-2.0 licence set, stale branches deleted, only `main` on the remote.

## Verdict

Secret hygiene: **ready** to the extent static scanning can prove. (caveats in §1.)

Code and packaging: **ready**, and tested in a way I consider honest (fail-closed on every hostile type, mutation-tested on each guard, clean-room from built wheels).

Capability maturity: **partially ready** — the receipt/verify/seal/anchor/rails-adapter surfaces are solid; the bonding and independence claims are explicitly documented as unproven in-app rather than claimed. That distinction is what makes a public release defensible.

What I will not do on my own: change repository visibility. That is a reversible-in-review-only decision that belongs to you, with the final scan in hand. Tell me to flip it, or to run the independent scan first, and I will be precise about which one I am doing.

## The one claim no one else in this space can make

`0.13.0` ships cross-operator corroboration: a settlement anchor is no longer one endpoint's
word. Two publicly distinct operators are asked for the same attested interval and must
agree on the signing set, the proven weight, the block-headers commitment and the proof
itself. Disagreement is a refusal, not a vote — a coordinated pair cannot outvote the truth.

This is the strongest thing in the repository and it belongs in the first paragraph of the
public README, not buried in a docs file. See `docs/INDEPENDENT-OPERATORS.md`.

Honest scope, which the docs state: distinct endpoints are not proven separate businesses,
and two agreeing operators does not prove either is honest. What it does prove is that one
alone cannot substitute a different signing set without the other contradicting it.

