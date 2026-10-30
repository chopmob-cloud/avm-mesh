"""Fail-closed on hostile input: the module's own error, never a surprise.

Most of these refusals are type guards, and testing each message individually
would be noise. What actually matters is the property they exist to guarantee:
malformed input raises ``MeshError`` and never ``TypeError``, ``AttributeError``
or ``KeyError`` -- because an unexpected exception type is what a caller's
``except Exception`` swallows into a pass.

This module pins the property across every public entry point. It is the
cheapest coverage that still fails when a guard is removed.
"""
import base64

import pytest

from avm_mesh import MeshError
from avm_mesh.attestation import ConsensusAttestation, verify_attestation
from avm_mesh.bond import BondError, Witness, WitnessSet, validate_corroboration
from avm_mesh.receipt import (
    ProofpackPointer,
    SettlementReceipt,
    bundle_digest,
    create_receipt,
    verify_receipt,
)
from avm_mesh.sealed import canonical_bytes, seal, verify_sealed
from avm_mesh.service import Store, WitnessInfo
from avm_mesh.trust import TrustPolicy, load_policy, verify_with_policy
from avm_mesh import a2a

#: Values an attacker or a buggy peer might send.
HOSTILE = [
    None,
    42,
    "a string",
    b"bytes",
    [],
    [1, 2],
    {},
    {"unexpected": "shape"},
    True,
]

#: Values that are wrong for a parameter expecting a mapping.
NOT_A_MAPPING = [None, 42, "a string", b"bytes", [], [1, 2], True]

#: Values that are wrong for a parameter expecting a string.
NOT_A_STRING = [None, 42, b"bytes", [], {}, True]

#: Values that are wrong for a parameter expecting an integer amount.
#: 42 is NOT here: it is a valid (if too small) bond.
NOT_A_NUMBER = [None, "a string", b"bytes", [], {}, True]

#: Error types a caller is entitled to catch. Anything else escaping is a defect.
EXPECTED = (MeshError, BondError)


def _assert_fails_closed(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except EXPECTED:
        return
    except Exception as exc:  # noqa: BLE001 - that is the point of the test
        pytest.fail(f"{fn.__name__} raised {type(exc).__name__} instead of MeshError: {exc}")
    pytest.fail(f"{fn.__name__} accepted hostile input without raising")


@pytest.mark.parametrize("bad", HOSTILE)
def test_receipt_parsing_fails_closed(bad):
    _assert_fails_closed(SettlementReceipt.from_dict, bad)
    _assert_fails_closed(ProofpackPointer.from_dict, bad)


@pytest.mark.parametrize("bad", NOT_A_MAPPING)
def test_bundle_digest_fails_closed(bad):
    _assert_fails_closed(bundle_digest, bad)


@pytest.mark.parametrize("bad", HOSTILE)
def test_attestation_parsing_fails_closed(bad):
    _assert_fails_closed(ConsensusAttestation.from_dict, bad)


@pytest.mark.parametrize("bad", HOSTILE)
def test_policy_parsing_fails_closed(bad):
    _assert_fails_closed(TrustPolicy.from_dict, bad)


@pytest.mark.parametrize("bad", NOT_A_MAPPING)
def test_canonical_bytes_fails_closed(bad):
    _assert_fails_closed(canonical_bytes, bad)


@pytest.mark.parametrize("bad", HOSTILE)
def test_a2a_artifact_parsing_fails_closed(bad):
    _assert_fails_closed(a2a.verify_artifact, bad, lambda uri: {})
    _assert_fails_closed(a2a.as_artifact, bad)


@pytest.mark.parametrize("bad", HOSTILE)
def test_verify_paths_fail_closed_on_hostile_receipt(bad, tmp_path):
    """A hostile receipt must not reach the evidence before being refused."""
    store = Store(tmp_path)
    _assert_fails_closed(verify_receipt, bad, store.resolve, trusted_voters=None)
    _assert_fails_closed(verify_sealed, bad, store.resolve, trusted_voters=None)


@pytest.mark.parametrize("bad", NOT_A_STRING)
def test_witness_info_fails_closed(bad):
    _assert_fails_closed(WitnessInfo, bad, "op", "mainnet-v1.0", "ESC", "", 0)


@pytest.mark.parametrize("bad", NOT_A_STRING)
def test_bond_construction_fails_closed(bad):
    _assert_fails_closed(Witness, bad, "op", "mainnet-v1.0", 1_000_000, "E")


@pytest.mark.parametrize("bad", NOT_A_NUMBER)
def test_bond_amount_must_be_a_number(bad):
    _assert_fails_closed(Witness, "w1", "op", "mainnet-v1.0", bad, "E")


@pytest.mark.parametrize("bad", HOSTILE)
def test_corroboration_validation_fails_closed(bad):
    ws = WitnessSet((Witness("w1", "op-1", "mainnet-v1.0", 1_000_000, "E1"),))
    _assert_fails_closed(validate_corroboration, bad, ws, "mainnet-v1.0", 1)


# --- specific refusals that carry security meaning -------------------------

def test_service_rejects_non_segment_names(tmp_path):
    """The traversal guard: a name is a single segment, never a path."""
    store = Store(tmp_path)
    for hostile in ("../escape", "a/b", "..", ".", "name\x00", "x" * 200, ""):
        with pytest.raises(MeshError):
            store.get_receipt(hostile)
        with pytest.raises(MeshError):
            store.get_proofpack(hostile)


def test_service_uri_must_name_a_digest(tmp_path):
    store = Store(tmp_path)
    with pytest.raises(MeshError, match="does not name a proofpack digest"):
        store.resolve("file://proofpack.json")


def test_policy_rejects_short_genesis_and_commitment():
    with pytest.raises(MeshError, match="genesis hash must be 32 bytes"):
        TrustPolicy.from_dict({"chain": "mainnet-v1.0", "genesis_hash_b64": "AAAA",
                               "anchor_voters_commitment_b64": "A" * 86 + "==",
                               "anchor_ln_proven_weight": 1, "witnesses": []})


def test_policy_rejects_negative_weight():
    with pytest.raises(MeshError, match="proven weight cannot be negative"):
        TrustPolicy.from_dict({"chain": "mainnet-v1.0",
                               "genesis_hash_b64": base64.b64encode(bytes(32)).decode(),
                               "anchor_voters_commitment_b64": base64.b64encode(bytes(64)).decode(),
                               "anchor_ln_proven_weight": -1, "witnesses": []})


def test_sealed_rejects_a_signer_that_returns_junk(bundle, anchor):
    with pytest.raises(MeshError, match="signer must return a signature object"):
        seal({"a": 1}, bundle, "proofpack:" + "0" * 64, trusted_voters=anchor,
             sign=lambda digest: "not a dict")


def test_sealed_rejects_bad_base64():
    with pytest.raises(MeshError, match="canonical_bytes_b64 is not valid base64"):
        verify_sealed({"version": 1, "canonical_bytes_b64": "!!!", "content_hash": "0" * 64},
                      lambda uri: {}, trusted_voters=None)


def test_attestation_rejects_v1_scheme():
    with pytest.raises(MeshError, match="v1 attestations were forgeable"):
        ConsensusAttestation(
            scheme="avm-stateproof-falcon1024", chain="mainnet-v1.0",
            genesis_hash_b64="wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
            txid="A" * 52, round=1, trust_root="stake_attested", evidence_uri="x",
            evidence_digest="a" * 64, first_attested_round=0, last_attested_round=1,
            anchor_voters_commitment_b64="A" * 86 + "==", anchor_ln_proven_weight=1,
        )


def test_verify_with_policy_requires_a_policy(bundle, anchor, tmp_path):
    store = Store(tmp_path)
    digest = store.put_proofpack(bundle)
    receipt = create_receipt(bundle, store.uri_for(digest), trusted_voters=anchor)
    with pytest.raises(MeshError, match="needs a TrustPolicy"):
        verify_with_policy(receipt, store.resolve, {"chain": "mainnet-v1.0"})


def test_load_policy_missing_file_fails_loudly(tmp_path):
    with pytest.raises(OSError):
        load_policy(str(tmp_path / "nope.json"))
