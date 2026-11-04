# Pre-publication audit — 2026-11-04

Supplements `docs/PUBLISH-READINESS.md` with the results of the pre-flight scan that document listed as the
one outstanding item, plus repo-state findings.

## 1. Secret scan — two independent scanners, zero credentials

Run against a **fresh clone from the remote** (not the working tree, so nothing local can mask a history
finding), at `e72321b`, 2026-11-04.

| Scanner | Scope | Result |
|---|---|---|
| `gitleaks 8.21.2` (`git . --log-opts="--all"`) | 92 non-merge commits across all refs | **no leaks found** |
| `gitleaks 8.21.2` (`dir`) | all **353 unique blobs** in the object database, including deleted files | **0 findings** |
| `detect-secrets 1.5.0` | all 353 unique blobs | 114 high-entropy hits, all classified below |

### The 92-versus-110 question, answered

The clone has 110 commits across all refs but gitleaks reported 92. That is not under-scanning: 92 is exactly
`git rev-list --count --no-merges --all`. gitleaks does not scan merge commits, because a merge normally adds
no new content. The case that matters is an *evil merge* — one that introduces content present in neither
parent — and that possibility is covered twice:

- every merge was checked for unique content with `git diff-tree -c`: **0 merges alter paths relative to both
  parents**;
- the blob-level scan covers every object in the database regardless of which commit introduced it, which is
  a strictly stronger guarantee than commit-by-commit scanning.

### All 114 detect-secrets hits classified

- **14 `Secret Keyword`** — every one is a test fixture string: `{"secret": "nope"}` and
  `{"secret": "via-symlink"}` inside symlink-refusal tests. Not credentials.
- **86 `Base64 High Entropy String`** and **14 `Hex High Entropy String`** — Falcon-1024 point coordinates,
  state-proof message commitments (`voters_commitment`, `block_headers_commitment`), transaction digests, and
  bundle SHA-256 pins. These are public chain data, in the same class as a block hash.

No private key header, no OpenAI/GitHub/PyPI/npm token shape, no JWT, no bearer header, no URL-embedded
credential, no non-empty password or token assignment.

### IP addresses in history

7 unique, all accounted for: `127.0.0.1`, `0.0.0.0`, `::1` (bind addresses), `10.1.2.3`, `172.16.0.5`,
`192.168.0.10` (RFC1918 literals used as SSRF-classifier test inputs), `169.254.169.254` (AWS metadata
endpoint, cited in documentation and tests), `93.184.216.34` (example.com, reserved). **No server address.**

## 2. Commit identities

| Identity | Count |
|---|---|
| `AlgoVoi <chopmob@gmail.com>` | 90 |
| `AlgoVoi (Christopher Hopley) <chopmob@gmail.com>` | 17 (GitHub web edits) |
| `Claude <chopmob@gmail.com>` | 3 |

Every commit shares one email. The three `Claude` commits are authored by the assistant under the same
address, not a separate party. Historical, immutable without a rewrite, and harmless — the identity carries no
credential. Stated here so it is not discovered after the flip.

## 3. Repo state

- **Description** present; **topics** empty (add before or after the flip: `algorand`, `voi`, `state-proofs`,
  `falcon`, `settlement`, `x402`, `a2a`); **homepage** empty.
- **Issues** enabled, **zero open** — nothing to triage before the flip.
- **Wiki** disabled.

### Branches to delete

Seven remote branches are fully merged into `main` and are dead weight:

```
chore/protect-main        claude/tender-pasteur-qmmgqz    claude/validation-handover
feat/hardening-0101       feat/testnet-poc-bonding        release/0.11.0
release/0.8.0
```

Two are stale in a way worth naming:

- **`feat/extension-vectors`** — reported as unmerged, but the diff against `main` is only main's later
  progress; its content was cherry-picked. Safe to delete.
- **`claude/vigilant-volta-3kjwyy`** — reported as unmerged, and the diff against `main` would **delete
  13,288 lines** across 105 files, including `tools/sut/`, `tools/verify_settlement_artifact.py` and the
  current validation harness. It is a stale branch from an earlier assistant session that predates the
  hardening work. **Do not merge it.** Delete it, or keep it out of the way; leaving it visible invites
  someone to try.

Deleting branches is a repo-state change, so it is listed here for a decision rather than done.

## 4. What remains genuinely open

Unchanged from `docs/PUBLISH-READINESS.md` §4, and none of them is a publication blocker:

1. A genuine rails receipt (owner: whoever operates rails).
2. A second-operator capture for the Algorand walk, and independently for Voi.
3. The four bonding economics decisions plus an escrow application.
4. External review of `avm-proofpack`'s Falcon and state-proof internals.
5. A live `microvoi` **payment** capture (the captured Voi transaction is an asset transfer; the Voi algod
   404s its transaction-proof endpoint for `pay` at the rounds tried).

## Verdict

Secret hygiene: **scanned twice, independently, over every object in the database — clean.**
Repo state: **three cosmetic items** (topics, homepage, stale branches) and nothing blocking.
Remaining gaps: **capability maturity, documented in-app**, not disclosure risk.

The one irreversible act — changing visibility — is the maintainer's, and this document is what it should be
taken on.
