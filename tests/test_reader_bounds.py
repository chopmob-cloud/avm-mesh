"""Every reader of an externally supplied file is bounded, not just the ones we remembered.

`_file_resolver` was hardened in 0.10.1 and the receipt read beside it was missed, which
left the CLI swallowing an arbitrary file from a counterparty whole while carefully capping
the evidence it pointed at. That is the shape of the mistake this file exists to prevent:
the guard was written for the path someone was thinking about, not for the category.

The rule asserted here: a file that arrives from outside is read through a bounded reader,
and the refusal says which bound was hit so an operator is not sent hunting for a syntax
error that is not there.
"""
import json
import pathlib

import pytest

from avm_mesh import cli
from avm_mesh.receipt import MeshError
from avm_mesh.service import Store


# ------------------------------------------------------------------ the CLI receipt


def test_an_oversized_receipt_is_refused_before_parsing(tmp_path, monkeypatch, capsys):
    """A receipt is metadata; 1 MiB is already generous. It must not be read whole."""
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"pad": "' + "x" * (cli.MAX_RECEIPT_BYTES + 1) + '"}',
                       encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    code = cli.main(["verify", str(receipt), "--evidence", str(evidence)])
    assert code == 3
    err = capsys.readouterr().err
    assert "refused on size" in err
    # The distinction matters: this is not a malformed document.
    assert "not valid JSON" not in err


def test_a_receipt_exactly_at_the_cap_is_attempted_rather_than_refused(tmp_path, capsys):
    """The bound is a limit, not an off-by-one that rejects the largest legal file."""
    receipt = tmp_path / "receipt.json"
    body = "{}"
    padded = body + " " * (cli.MAX_RECEIPT_BYTES - len(body))
    receipt.write_text(padded, encoding="utf-8")
    assert receipt.stat().st_size == cli.MAX_RECEIPT_BYTES
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    code = cli.main(["verify", str(receipt), "--evidence", str(evidence)])
    # It gets past the read and fails for a different reason (an empty receipt is not a
    # valid sealed receipt). What must not happen is a size refusal.
    assert "refused on size" not in capsys.readouterr().err


def test_a_malformed_receipt_is_still_reported_as_malformed(tmp_path, capsys):
    """The other half of the distinction: a real syntax error must not read as a size."""
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{not json", encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    code = cli.main(["verify", str(receipt), "--evidence", str(evidence)])
    assert code == 3
    assert "not valid JSON" in capsys.readouterr().err


def test_the_receipt_cap_is_smaller_than_the_evidence_cap():
    """Deliberate: a receipt names a bundle, so it should never rival one in size."""
    assert cli.MAX_RECEIPT_BYTES < cli.MAX_PROOF_BYTES_DEFAULT


def test_the_cli_and_the_store_share_one_receipt_bound():
    """Two caps for one shape is how a witness produces receipts no client can open.

    Reproduced before this was fixed: the store allowed 8 MiB and the CLI 1 MiB, so a
    2 MiB receipt was writable, servable over HTTP, and unreadable by the CLI that
    consumes it. They now come from the same constant.
    """
    from avm_mesh.service import DEFAULT_MAX_RECEIPT_BYTES

    assert cli.MAX_RECEIPT_BYTES == DEFAULT_MAX_RECEIPT_BYTES
    assert Store.__init__.__defaults__[-1] == DEFAULT_MAX_RECEIPT_BYTES


def test_the_store_refuses_to_write_a_receipt_it_could_not_serve(tmp_path):
    """Refused at write time, so the unservable state cannot be created at all."""
    from avm_mesh.receipt import ProofpackPointer, SettlementReceipt

    store = Store(tmp_path / "store", max_receipt_bytes=200)
    digest = "a" * 64
    # A valid name and a valid pointer: the size must be the ONLY reason this is refused,
    # or the test proves the name guard rather than the size guard.
    receipt = SettlementReceipt(
        version=1, chain="mainnet-v1.0", txid="TX-BIG", round=66457600,
        trust_root="structural",
        pointer=ProofpackPointer(uri=f"proofpack:{digest}" + "/" + "u" * 300,
                                 digest=digest,
                                 first_attested_round=66457344,
                                 last_attested_round=66457600))

    with pytest.raises(MeshError, match="byte limit"):
        store.put_receipt(receipt)
    # and nothing was left behind by the refusal
    assert not (store.receipts / f"{receipt.txid}.json").exists()


# ------------------------------------------------------- the served store (reads)


def test_the_store_refuses_to_serve_an_oversized_receipt(tmp_path):
    """`put_receipt` is not the only way a file reaches this directory."""
    store = Store(tmp_path / "store", max_receipt_bytes=1024)
    path = store.receipts / "TX1.json"
    path.write_text('{"pad": "' + "x" * 2000 + '"}', encoding="utf-8")

    with pytest.raises(MeshError, match="over the 1024 byte limit"):
        store.get_receipt("TX1")


def test_the_store_still_serves_a_normal_receipt(tmp_path):
    """The guard must not have costs for the ordinary case."""
    store = Store(tmp_path / "store")
    path = store.receipts / "TX2.json"
    path.write_text(json.dumps({"txid": "TX2", "round": 1}), encoding="utf-8")
    got = store.get_receipt("TX2")
    assert got["txid"] == "TX2"


# ----------------------------------------------------- the capture-time probe


def test_a_bug_in_the_probe_is_not_reported_as_a_pruned_interval(tmp_path):
    """The probe must only swallow the ways an interval can be ABSENT.

    `except Exception: return False` reads a NameError, a TypeError or a typo in this very
    module as "the operator has pruned that interval" -- a wrong diagnosis rather than a
    missing one, and the operator gets blamed for our defect. Narrowing the catch means a
    real bug propagates; this pins that.
    """
    import importlib.util

    tool = pathlib.Path(__file__).resolve().parents[1] / "tools" / "fetch_corroborated_walk.py"
    spec = importlib.util.spec_from_file_location("fcw", tool)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def boom(endpoint, path, timeout=25.0):
        raise NameError("a bug in this module, not a network condition")

    original, module._get = module._get, boom
    try:
        with pytest.raises(NameError):
            module._probe("https://example.invalid", 66647808, 25.0)
    finally:
        module._get = original

    # and the absence cases still return False rather than raising
    def missing(endpoint, path, timeout=25.0):
        raise OSError("connection refused")

    original, module._get = module._get, missing
    try:
        assert module._probe("https://example.invalid", 66647808, 25.0) is False
    finally:
        module._get = original


# ----------------------------------------------------------- the policy document


def test_an_oversized_policy_is_refused_before_parsing(tmp_path):
    """`load_policy` is public API and reads a file a counterparty may have chosen.

    Bounded before parse, so the string is never built. Same defect class as the receipt
    read that shipped unbounded until 0.13.1: the guard was written for the path someone
    was thinking about, not for every path a stranger's file can arrive through.
    """
    from avm_mesh.trust import MAX_POLICY_BYTES, load_policy

    path = tmp_path / "policy.json"
    path.write_text('{"pad": "' + "x" * (MAX_POLICY_BYTES + 1) + '"}', encoding="utf-8")

    with pytest.raises(MeshError, match="byte cap"):
        load_policy(str(path))


def test_a_policy_exactly_at_the_cap_is_attempted(tmp_path):
    """The bound must not be an off-by-one that rejects the largest legal document."""
    from avm_mesh.trust import MAX_POLICY_BYTES, load_policy

    path = tmp_path / "policy.json"
    body = "{}"
    path.write_text(body + " " * (MAX_POLICY_BYTES - len(body)), encoding="utf-8")
    assert path.stat().st_size == MAX_POLICY_BYTES

    # It reaches the parser and fails there, which is a different error.
    with pytest.raises(MeshError, match="not valid UTF-8 JSON|required|missing"):
        load_policy(str(path))


def test_a_missing_policy_is_a_MeshError_not_an_OSError(tmp_path):
    """The library promises never to leak OSError to callers."""
    from avm_mesh.trust import load_policy

    with pytest.raises(MeshError, match="cannot read policy"):
        load_policy(str(tmp_path / "absent.json"))


def test_a_malformed_policy_names_the_file(tmp_path):
    from avm_mesh.trust import load_policy

    path = tmp_path / "policy.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(MeshError, match="not valid UTF-8 JSON"):
        load_policy(str(path))
