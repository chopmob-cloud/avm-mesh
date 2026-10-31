"""Shared fixtures: the real mainnet bundle, and an independently-derived anchor."""
import base64
import gzip
import json
import os
import pathlib

import pytest

DEFAULT_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "avm-proofpack" / "tests" / "fixtures"
    / "stake_attested_algorand_66457600.json.gz"
)


from _assets import fixture_bundle  # noqa: E402 - sibling test module
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="


@pytest.fixture(scope="session")
def bundle():
    explicit = os.environ.get("AVM_MESH_FIXTURE")
    path = pathlib.Path(explicit) if explicit else fixture_bundle()
    if not path.exists():
        # A missing fixture is normally a skip for a developer who has not cloned
        # the sibling repo. In a gate it must be a failure: "215 passed, 81 skipped"
        # is not evidence that the crypto paths work.
        if os.environ.get("AVM_MESH_REQUIRE_FIXTURE") == "1":
            pytest.fail(f"AVM_MESH_REQUIRE_FIXTURE=1 but the fixture is absent at {path}")
        pytest.skip(f"fixture not present at {path}")
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def anchor(bundle):
    """A TrustedVoters anchor.

    In production this comes from a pinned genesis bootstrap or a chain walk.
    Here it is taken from the fixture's previous interval so the code path is
    exercised -- tests document that, they do not claim it is independent.
    """
    from avm_proofpack.verify import TrustedVoters

    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]),
    )


@pytest.fixture(scope="session")
def wrong_anchor(bundle):
    """An anchor that is not the one this bundle was attested under."""
    from avm_proofpack.verify import TrustedVoters

    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(
        voters_commitment=base64.b64decode(prev["voters_commitment_b64"]),
        ln_proven_weight=int(prev["ln_proven_weight"]) + 1,
    )

