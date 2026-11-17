"""Version claims in the current-state documents must match the package.

`tests/test_packaging.py` already compares `pyproject.toml`, `__version__` and the
README. That is four sites, and it left the three documents an operator reads
first unguarded — so they drifted two releases behind: after 0.13.4 was published
`docs/HANDOVER.md` still called 0.13.4 "the source tree" while `pyproject.toml`
said 0.13.5, and both `docs/PUBLISH-READINESS.md` and `docs/WHY.md` still called
0.13.3 "the latest on PyPI".

The rules are derived, not a list of expected strings:

* a "<version> in the source tree" claim must be the declared version — the tree
  and the metadata cannot disagree about what is being built;
* a "PyPI latest: <version>" / "<version> on PyPI" / "<version> is what is live
  on PyPI" claim must be the declared version or the one immediately before it.
  A document may lag one release, because the window between a bump and the
  upload that publishes it is real; two behind is always a stale document.

Historical records are excluded by name, and the exclusion is asserted to still
match real files so it cannot quietly widen: the CHANGELOG is the record of what
each version did, `docs/REVIEW-REQUEST.md` is pinned to the version it asked
someone to review, and `docs/PRE-PUBLICATION-AUDIT.md` is a dated scan.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CURRENT_STATE_DOCS = (
    "README.md",
    "docs/HANDOVER.md",
    "docs/PUBLISH-READINESS.md",
    "docs/WHY.md",
)

HISTORICAL_DOCS = (
    "CHANGELOG.md",
    "docs/REVIEW-REQUEST.md",
    "docs/PRE-PUBLICATION-AUDIT.md",
)

_SEMVER = r"([0-9]+\.[0-9]+\.[0-9]+)"

SOURCE_TREE_CLAIMS = (
    re.compile(_SEMVER + r"`? in the source tree"),
)

PUBLISHED_CLAIMS = (
    re.compile(r"PyPI latest:\s*`?" + _SEMVER),
    re.compile(r"`" + _SEMVER + r"` on PyPI"),
    re.compile(r"`" + _SEMVER + r"` is what is live on PyPI"),
    re.compile(r"`" + _SEMVER + r"` is live"),
    re.compile(_SEMVER + r" is the published version"),
)


def _declared_version() -> str:
    """The version in `[project]`, read with a regex and no TOML import.

    Same reasoning as `tests/test_packaging.py`: `tomllib` is 3.11+ and the floor
    is 3.10, and `tomli` is not installed by the CI test leg.
    """
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert match, "no version line found in pyproject.toml"
    return match.group(1)


def _previous(version: str) -> str:
    head, _, patch = version.rpartition(".")
    return f"{head}.{int(patch) - 1}"


def test_a_source_tree_claim_names_the_declared_version():
    declared = _declared_version()
    seen = 0
    wrong: list[str] = []
    for name in CURRENT_STATE_DOCS:
        text = (ROOT / name).read_text(encoding="utf-8")
        for pattern in SOURCE_TREE_CLAIMS:
            for claim in pattern.findall(text):
                seen += 1
                if claim != declared:
                    wrong.append(f"{name}: says {claim} is in the source tree, pyproject says {declared}")
    assert seen, (
        "no document states a version 'in the source tree'; either the wording moved "
        "or the guard has stopped looking at anything")
    assert not wrong, "\n".join(wrong)


def test_a_published_version_claim_is_at_most_one_release_behind():
    declared = _declared_version()
    allowed = {declared, _previous(declared)}
    seen = 0
    wrong: list[str] = []
    for name in CURRENT_STATE_DOCS:
        text = (ROOT / name).read_text(encoding="utf-8")
        for pattern in PUBLISHED_CLAIMS:
            for claim in pattern.findall(text):
                seen += 1
                if claim not in allowed:
                    wrong.append(
                        f"{name}: names {claim} as published, but the package in the tree is "
                        f"{declared} (allowed: {sorted(allowed)})")
    assert seen, (
        "no document states which version is published; either the wording moved "
        "or the guard has stopped looking at anything")
    assert not wrong, "\n".join(wrong)


def test_the_historical_exclusions_still_name_real_files():
    missing = [name for name in HISTORICAL_DOCS if not (ROOT / name).is_file()]
    assert not missing, (
        f"historical exclusions no longer exist: {missing} — drop them from the list "
        "rather than letting the set cover nothing")
