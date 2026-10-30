"""Witness service: the node-side component.

The service is a courier, so the tests are about it being unable to help an
attacker even if it tried: content-addressed storage, corruption detected on
read, and an end-to-end verification that never trusts the server's word.
"""
import json
import urllib.error
import urllib.request

import pytest

from avm_mesh.receipt import MeshError, create_receipt, verify_receipt
from avm_mesh.service import Store, WitnessInfo, run_in_thread


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, json.loads(r.read().decode())


def test_proofpacks_are_content_addressed(store_dir):
    s = Store(store_dir)
    bundle = {"a": 1}
    d1 = s.put_proofpack(bundle)
    d2 = s.put_proofpack(dict(bundle))
    assert d1 == d2
    assert s.get_proofpack(d1) == bundle


def test_a_tampered_blob_is_detected_on_read(store_dir):
    """The filename is the digest; content that disagrees is corruption, not data."""
    s = Store(store_dir)
    d = s.put_proofpack({"a": 1})
    (s.proofpacks / f"{d}.json").write_text(json.dumps({"a": 2}), encoding="utf-8")
    with pytest.raises(MeshError, match="no longer matches its name"):
        s.get_proofpack(d)


def test_missing_proofpack_raises(store_dir):
    with pytest.raises(FileNotFoundError):
        Store(store_dir).get_proofpack("0" * 64)


def test_witness_info_requires_identity(store_dir):
    with pytest.raises(MeshError, match="operator_id is required"):
        WitnessInfo("w1", "", "mainnet-v1.0", "ESC", "", 0)


def test_endpoints_serve_receipt_and_proofpack(bundle, anchor, tmp_path):
    store = Store(tmp_path)
    receipt = create_receipt(bundle, "file://proofpack.json", trusted_voters=anchor)
    digest = store.put_proofpack(bundle)
    store.put_receipt(receipt)

    info = WitnessInfo("w1", "op-1", "mainnet-v1.0", "ESC-1",
                       receipt.pointer.digest, receipt.pointer.last_attested_round)
    server, _ = run_in_thread(store, info)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert _get(f"{base}/healthz") == (200, {"ok": True})

        status, w = _get(f"{base}/witness")
        assert status == 200 and w["witness_id"] == "w1"
        assert "courier" in w["note"]

        status, served_receipt = _get(f"{base}/receipts/{receipt.txid}")
        assert status == 200 and served_receipt["txid"] == receipt.txid

        status, served_bundle = _get(f"{base}/proofpacks/{digest}")
        assert status == 200 and served_bundle == bundle
    finally:
        server.shutdown()
        server.server_close()


def test_end_to_end_verification_over_the_service(bundle, anchor, tmp_path):
    """Fetch from the witness, then verify offline against the anchor."""
    store = Store(tmp_path)
    digest = store.put_proofpack(bundle)
    receipt = create_receipt(bundle, store.uri_for(digest), trusted_voters=anchor)
    store.put_receipt(receipt)

    server, _ = run_in_thread(store)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _, served = _get(f"{base}/receipts/{receipt.txid}")
        from avm_mesh.receipt import SettlementReceipt

        report = verify_receipt(SettlementReceipt.from_dict(served),
                                store.resolve, trusted_voters=anchor)
        assert report.trust_root == "stake_attested"
        assert report.txid == receipt.txid

        # A URI that does not name a digest is refused: the courier must not choose.
        with pytest.raises(MeshError, match="does not name a proofpack digest"):
            store.resolve("file://proofpack.json")
    finally:
        server.shutdown()
        server.server_close()


def test_unknown_paths_are_404(store_dir):
    server, _ = run_in_thread(Store(store_dir))
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(f"{base}/receipts/DOESNOTEXIST")
        assert exc.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def store_dir(tmp_path):
    return tmp_path / "store"
