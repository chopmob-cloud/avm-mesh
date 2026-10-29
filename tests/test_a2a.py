"""A2A settlement-evidence extension tests."""
import copy
import gzip
import json
import os
import pathlib

import pytest

from avm_mesh import MeshError, seal
from avm_mesh.a2a import (
    ARTIFACT_NAME,
    EXTENSION_URI,
    advertise,
    as_artifact,
    extension_descriptor,
    verify_artifact,
    wants_extension,
)

DEFAULT_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "avm-proofpack" / "tests" / "fixtures"
    / "stake_attested_algorand_66457600.json.gz"
)
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="


@pytest.fixture(scope="module")
def sealed(bundle, anchor):
    return seal({"settlement": {"chain": "mainnet-v1.0",
                                "txid": bundle["transaction"]["txid"],
                                "round": bundle["transaction"]["round"]}},
                bundle, "file://proofpack.json", trusted_voters=anchor)


def _resolver(b):
    return lambda uri: copy.deepcopy(b)


def test_descriptor_is_not_required():
    """An optional extension, so peers without it still interoperate."""
    d = extension_descriptor()
    assert d["uri"] == EXTENSION_URI
    assert d["required"] is False


def test_advertise_adds_the_extension_without_mutating_the_card():
    card = {"name": "merchant", "capabilities": {"streaming": False}}
    out = advertise(card)
    uris = [e["uri"] for e in out["capabilities"]["extensions"]]
    assert EXTENSION_URI in uris
    assert "extensions" not in card["capabilities"]


def test_advertise_is_idempotent():
    card = advertise({"name": "m"})
    twice = advertise(card)
    uris = [e["uri"] for e in twice["capabilities"]["extensions"]]
    assert uris.count(EXTENSION_URI) == 1


def test_advertise_preserves_existing_extensions():
    card = {"capabilities": {"extensions": [{"uri": "https://example/ext", "required": True}]}}
    out = advertise(card)
    uris = [e["uri"] for e in out["capabilities"]["extensions"]]
    assert "https://example/ext" in uris
    assert EXTENSION_URI in uris


def test_wants_extension_reads_both_shapes():
    assert wants_extension({"extensions": [EXTENSION_URI]})
    assert wants_extension({"params": {"extensions": [EXTENSION_URI]}})
    assert not wants_extension({"extensions": []})
    assert not wants_extension({})
    assert not wants_extension(None)


def test_artifact_round_trips_and_verifies(sealed, bundle, anchor):
    art = as_artifact(sealed)
    assert art["name"] == ARTIFACT_NAME
    out = verify_artifact(art, _resolver(bundle), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS)
    assert out["trust_root"] == "stake_attested"


def test_artifact_without_payload_fails_closed(sealed):
    """No evidence is an error, not an empty pass."""
    art = {"artifact_id": "x", "parts": [{"kind": "text", "text": "paid, honest"}]}
    with pytest.raises(MeshError, match="no settlement-evidence payload"):
        verify_artifact(art, lambda uri: {})


def test_peer_advertising_another_extension_is_refused(sealed, bundle, anchor):
    art = as_artifact(sealed)
    art["parts"][0]["data"]["extension"] = "https://example/other/v1"
    with pytest.raises(MeshError, match="no settlement-evidence payload"):
        verify_artifact(art, _resolver(bundle), trusted_voters=anchor)


def test_tampered_receipt_from_a_peer_is_refused(sealed, bundle, anchor):
    art = as_artifact(sealed)
    tampered = copy.deepcopy(sealed)
    tampered["content_hash"] = "0" * 64
    art["parts"][0]["data"]["avm_mesh_receipt"] = tampered
    with pytest.raises(MeshError, match="content hash mismatch"):
        verify_artifact(art, _resolver(bundle), trusted_voters=anchor, expected_genesis_hash_b64=GENESIS)


def test_malformed_artifacts_are_refused(sealed):
    with pytest.raises(MeshError, match="no parts"):
        verify_artifact({}, lambda uri: {})
    with pytest.raises(MeshError, match="missing canonical_bytes_b64"):
        as_artifact({"content_hash": "a" * 64})
