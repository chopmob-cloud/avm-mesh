"""Locate avm-proofpack test assets, with an override for gated runs.

Order:
  1. ``AVM_PROOFPACK_TESTS`` — the directory holding ``fixtures/`` and ``falcon_kat/``.
     CI checks out the sibling repo at a pinned commit and points here.
  2. the sibling checkout beside this repo, which is what a developer has.

Every path goes through here. When a lookup is hardcoded, a gate silently skips the
test instead of failing, and a green tick then covers less than it appears to.
"""
from __future__ import annotations

import os
import pathlib

_SIBLING = pathlib.Path(__file__).resolve().parents[2] / "avm-proofpack" / "tests"


def proofpack_tests_dir() -> pathlib.Path:
    override = os.environ.get("AVM_PROOFPACK_TESTS")
    return pathlib.Path(override) if override else _SIBLING


def asset(*parts: str) -> pathlib.Path:
    return proofpack_tests_dir().joinpath(*parts)


def fixture_bundle() -> pathlib.Path:
    return asset("fixtures", "stake_attested_algorand_66457600.json.gz")


def falcon_kat() -> pathlib.Path:
    return asset("falcon_kat", "falcon1024_det_kat.json")


def require(path: pathlib.Path, what: str) -> pathlib.Path:
    """Skip when an asset is absent — unless a gate is running, where absence fails.

    A skip is a developer convenience, never a gate result: CI must not be able to go
    green on evidence it did not load.
    """
    if path.exists():
        return path
    import pytest

    if os.environ.get("AVM_MESH_REQUIRE_FIXTURE") == "1":
        pytest.fail(f"{what} is required for this run but absent at {path}")
    pytest.skip(f"{what} not present at {path}")
