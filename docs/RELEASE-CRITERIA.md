# Release criteria

What must be true before `avm-mesh` is published again. Written after 0.4.2, 0.4.3 and 0.5.0 were
published in one session, and 0.5.0 turned out to claim a licence it does not ship.

Publication is irreversible: a version cannot be withdrawn from PyPI, only superseded or yanked. So the
check happens before the upload, not after.

## The estate standard (not invented here)

From the memory graph, which is the first thing to consult and must not be skipped:

- **Claim 11229** (EVIDENCED, 2026-10-29) — licence files normalised estate-wide; PEP 639 SPDX with no
  conflicting classifier.
- **Claim 4594** — the shipped pattern: Apache-2.0 `LICENSE` + `NOTICE` in both artifacts, via PEP 639
  `license-files`.

`avm-proofpack` complies. `avm-mesh` 0.5.0 does not, and that is the defect the replacing version fixes.

## Checklist

Each line is checkable, and the ones marked *enforced* are asserted by a test so that remembering the rule
is not part of the process.

- [ ] `LICENSE` and `NOTICE` exist in the repository root.
- [ ] `pyproject.toml` uses the PEP 639 form: `license = "<SPDX expression>"` and `license-files`, with no
      `License :: OSI Approved` classifier contradicting it.
- [ ] The built wheel **and** sdist each contain `LICENSE` and `NOTICE` — inspect the built artifacts, not
      the source tree. *(enforced)*
- [ ] `METADATA` declares `License-Expression` and `License-File`. *(enforced)*
- [ ] Suite green on **3.10** and **3.12**, installed from the wheel, not from the source tree.
- [ ] Clean-room gate green on VM2: offline install from wheels, `0 skipped`, audit rule A, red team.
- [ ] Every README-documented command exists and runs — `verify`, `serve`, `corroborate` — exercised against
      the installed package. *(enforced)*
- [ ] From-index verification in a fresh container: the published version installs without local paths, the
      console script runs, and `pip list` shows the dependency versions you built against.
- [ ] Any claim in `README.md` about counts, versions, or conformance matches the gate output, not the local
      run.

## Why the licence matters more than it looks

A package that tells PyPI and every installer it is Apache-2.0 while shipping none of the licence text is
not making a cosmetic error. Apache-2.0 requires the licence and NOTICE to travel with the distribution, and
the first organisation to evaluate adoption will run exactly this check. It also means the repository and
the artifact disagree with each other, which is worse than either being wrong on its own.

## Standing rule

Consult the memory graph for the estate's packaging standard **before** building, not after publishing.
The cost of looking is one command. The cost of not looking has already been three versions.
