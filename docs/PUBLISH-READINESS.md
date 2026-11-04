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

## 3. Build and test baseline — complete as of 0.10.2

- PyPI latest: 0.10.2 (wheel + sdist), verified installed from a fresh venv with `PYTHONPATH` cleared, `__file__` under site-packages, console script intact.
- Clean-room (VM2, offline wheels, fresh `python:3.12-slim` / `python:3.10-slim`): **432 tests passed, 0 skipped, 3 deselected** (signed tests requiring `pqcrypto`), audit rule A OK, red team 14/14 attacks refused. 3.10: same.
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

## 5. Items to decide before flipping visibility

- [x] ~~Run an independent second scan~~ — **done**, see [`docs/PRE-PUBLICATION-AUDIT.md`](PRE-PUBLICATION-AUDIT.md). `gitleaks 8.21.2` over a fresh clone (92 non-merge commits, all refs) and over all 353 unique blobs: zero findings. `detect-secrets` over the same blobs: 114 high-entropy hits, every one classified as chain data or a test fixture.
- [ ] Decide whether to publish at the current 0.10.2 version or wait for an external deliverable (a genuine rails receipt, say) so the first public source matches the first public capability claim.
- [ ] Confirm commit author identity and history are acceptable as committed (`AlgoVoi <chopmob@gmail.com>`). Some early commits or handovers may contain personal notes.
- [ ] Confirm PyPI project name `avm-mesh` stays free/owned (already published).
- [ ] Final pass on `README.md` tone and "Honest limits" section for general-audience readers.
- [ ] Repo cosmetics: add topics (`algorand`, `voi`, `state-proofs`, `falcon`, `settlement`, `x402`, `a2a`), set a homepage, and delete the nine stale branches listed in the audit (including `claude/vigilant-volta-3kjwyy`, which would delete 13,288 lines if merged).

## Verdict

Secret hygiene: **ready** to the extent static scanning can prove. (caveats in §1.)

Code and packaging: **ready**, and tested in a way I consider honest (fail-closed on every hostile type, mutation-tested on each guard, clean-room from built wheels).

Capability maturity: **partially ready** — the receipt/verify/seal/anchor/rails-adapter surfaces are solid; the bonding and independence claims are explicitly documented as unproven in-app rather than claimed. That distinction is what makes a public release defensible.

What I will not do on my own: change repository visibility. That is a reversible-in-review-only decision that belongs to you, with the final scan in hand. Tell me to flip it, or to run the independent scan first, and I will be precise about which one I am doing.