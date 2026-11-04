"""Conformance vectors for the settlement-evidence artefact, run against both verifiers.

Two implementations have to agree on every case: the package's `verify_artifact`
and the standalone stdlib tool a counterparty can read and run without installing
us. Agreement is the property that matters. If they diverge, one of them is wrong
and a receiver could reach a different verdict than the sender expected, which is
the failure this suite exists to prevent.

The standalone tool is not a reference implementation for ambiguous input, and
neither is the library: both refuse the ambiguous case rather than resolving it.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

from avm_mesh import MeshError
from avm_mesh.a2a import EXTENSION_URI, verify_artifact

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "a2a" / "settlement-evidence-v1.json"
TOOL = ROOT / "tools" / "verify_settlement_artifact.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("standalone_artifact_verifier", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STANDALONE = _load_tool()


def _cases():
    payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert payload["extension"] == EXTENSION_URI
    return payload["cases"]


def test_the_vector_file_covers_both_verdicts():
    verdicts = {c["expect"] for c in _cases()}
    assert verdicts == {"pass", "reject"}, verdicts


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_both_verifiers_reach_the_expected_verdict(case):
    expected = case["expect"]

    # library
    try:
        verify_artifact(case["artifact"], lambda uri: pytest.fail("resolver called for a structural receipt"))
        library = "pass"
    except MeshError:
        library = "reject"

    # standalone
    try:
        STANDALONE.verify(case["artifact"])
        standalone = "pass"
    except STANDALONE.Refused:
        standalone = "reject"

    assert library == expected, f"library disagreed on {case['name']}: {library} != {expected}"
    assert standalone == expected, f"standalone disagreed on {case['name']}: {standalone} != {expected}"
    assert library == standalone


def test_the_standalone_tool_is_runnable_and_agrees_on_the_wire(tmp_path):
    """The module-level checks above bypass the CLI, so drive it once for real."""
    good = next(c for c in _cases() if c["name"] == "valid_structural")
    bad = next(c for c in _cases() if c["name"] == "content_hash_mismatch")

    ok_file = tmp_path / "ok.json"
    ok_file.write_text(json.dumps(good["artifact"]), encoding="utf-8")
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps(bad["artifact"]), encoding="utf-8")

    run = subprocess.run([sys.executable, str(TOOL), str(ok_file), "--json"],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    report = json.loads(run.stdout)
    assert report["verified"] is True
    assert report["levels"]["integrity"] == "pass"
    assert "not checked" in report["levels"]["signature"]

    run = subprocess.run([sys.executable, str(TOOL), str(bad_file)],
                         capture_output=True, text=True)
    assert run.returncode == 1, run.stdout + run.stderr
    assert "REFUSED" in run.stdout

    run = subprocess.run([sys.executable, str(TOOL)], capture_output=True, text=True)
    assert run.returncode == 2
    assert "usage" in run.stderr


def test_the_tool_imports_nothing_from_algovoi():
    """The point of a standalone verifier is that it does not depend on us."""
    source = TOOL.read_text(encoding="utf-8")
    for forbidden in ("import avm_mesh", "from avm_mesh", "import avm_proofpack", "from avm_proofpack"):
        assert forbidden not in source, forbidden


def test_help_is_exact_not_a_substring():
    """`--helpful` is an unknown argument, not a request for help.

    A substring test (`"-h" in argv`) swallows both, and would also swallow a filename
    containing "-h". The distinction matters because a mistyped flag should reach the
    usage-error path, not print help and exit 0 as though it had been understood.
    """
    for flag in ("--help", "-h"):
        run = subprocess.run([sys.executable, str(TOOL), flag], capture_output=True, text=True)
        assert run.returncode == 0, f"{flag} exited {run.returncode}"
        assert "usage:" in run.stdout

    for not_help in ("--helpful", "-hh", "--hel"):
        run = subprocess.run([sys.executable, str(TOOL), not_help],
                             capture_output=True, text=True)
        assert run.returncode == 2, f"{not_help} should be a usage error, got {run.returncode}"
        assert "usage:" in run.stderr, f"{not_help} printed no usage line on stderr"


def test_an_oversized_canonical_blob_is_refused_before_decoding():
    """The bound must bite before base64 decode, not after.

    A vector file cannot carry a multi-megabyte case, so this one is built in
    memory: a declared field just over the cap, with a well-formed envelope.
    """
    oversized = "A" * (STANDALONE.MAX_CANONICAL_B64_CHARS + 4)
    artifact = {"artifact_id": "x", "parts": [{
        "data": {"avm_mesh_receipt": {"canonical_bytes_b64": oversized, "content_hash": "0" * 64},
                 "extension": EXTENSION_URI},
        "mediaType": "application/json"}]}
    with pytest.raises(STANDALONE.Refused, match="over the limit"):
        STANDALONE.verify(artifact)
