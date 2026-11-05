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


# ------------------------------------------------------------------ the served store


def test_the_store_refuses_to_serve_an_oversized_receipt(tmp_path):
    """`put_receipt` is not the only way a file reaches this directory."""
    store = Store(tmp_path / "store", max_proofpack_bytes=1024)
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
