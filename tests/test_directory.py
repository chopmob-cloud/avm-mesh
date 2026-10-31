"""Directories are leads, and a lead that disagrees with the witness loses."""
import json

import pytest

from avm_mesh import MeshError
from avm_mesh.corroborate import collect
from avm_mesh.directory import (
    DIRECTORY_VERSION,
    WELL_KNOWN_PATH,
    load_directory,
    parse_directory,
    urls_from_directories,
)
from avm_mesh.receipt import ProofpackPointer, SettlementReceipt, bundle_digest
from avm_mesh.service import Store, WitnessInfo, run_in_thread

BUNDLE = {"transaction": {"txid": "DIRTEST", "round": 66457600}, "state_proof_message": {}}
DIGEST = bundle_digest(BUNDLE)


def _witness(tmp_path, name, operator, chain="mainnet-v1.0"):
    store = Store(tmp_path / name)
    store.put_proofpack(BUNDLE)
    store.put_receipt(SettlementReceipt(
        version=1, chain=chain, txid="DIRTEST", round=66457600, trust_root="structural",
        pointer=ProofpackPointer(uri="proofpack:" + DIGEST, digest=DIGEST,
                                 first_attested_round=66457344, last_attested_round=66457600)))
    info = WitnessInfo(witness_id=name, operator_id=operator, chain=chain,
                       escrow_txid="ESC", anchor_voters_commitment_b64="A" * 44,
                       anchor_ln_proven_weight=2230418)
    server, _ = run_in_thread(store, info)
    return "http://127.0.0.1:%d" % server.server_address[1]


def _doc(*entries):
    return {"version": DIRECTORY_VERSION, "witnesses": list(entries)}


def test_well_known_path_is_a_constant_clients_and_servers_share():
    assert WELL_KNOWN_PATH.startswith("/.well-known/")
    assert WELL_KNOWN_PATH.endswith(".json")


def test_parses_a_minimal_directory():
    entries = parse_directory(_doc({"url": "https://w1.example"}, {"url": "https://w2.example"}))
    assert [e["url"] for e in entries] == ["https://w1.example", "https://w2.example"]


def test_unknown_fields_are_refused():
    with pytest.raises(MeshError, match="unknown field"):
        parse_directory(_doc({"url": "https://w1.example", "trusted": True}))


def test_wrong_version_is_refused():
    with pytest.raises(MeshError, match="unsupported directory version"):
        parse_directory({"version": 99, "witnesses": [{"url": "https://w1.example"}]})


def test_missing_or_bad_urls_are_refused():
    for bad in ({}, {"url": "ftp://w1.example"}, {"url": ""}, {"url": 42}):
        with pytest.raises(MeshError, match="url must be an http"):
            parse_directory(_doc(bad))


def test_duplicate_urls_are_refused():
    with pytest.raises(MeshError, match="appears twice"):
        parse_directory(_doc({"url": "https://w1.example"}, {"url": "https://w1.example"}))


def test_empty_directory_is_refused():
    with pytest.raises(MeshError, match="at least one witness"):
        parse_directory({"version": DIRECTORY_VERSION, "witnesses": []})


def test_loads_from_a_local_path(tmp_path):
    path = tmp_path / "dir.json"
    path.write_text(json.dumps(_doc({"url": "https://w1.example"})), encoding="utf-8")
    assert load_directory(str(path))[0]["url"] == "https://w1.example"


def test_invalid_json_is_refused(tmp_path):
    path = tmp_path / "dir.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(MeshError, match="not valid JSON"):
        load_directory(str(path))


def test_missing_file_is_refused(tmp_path):
    with pytest.raises(MeshError, match="cannot read directory"):
        load_directory(str(tmp_path / "absent.json"))


def test_a_loopback_directory_is_refused_by_the_address_guard():
    """New behaviour: loopback is refused before a connection is attempted."""
    with pytest.raises(MeshError, match="not a public address"):
        load_directory("http://127.0.0.1:1/dir.json", timeout=1)


def test_an_unreachable_directory_is_refused_once_the_guard_is_opted_out_of():
    """The original behaviour, reachable only when loopback is explicitly allowed."""
    with pytest.raises(MeshError, match="cannot reach"):
        load_directory("http://127.0.0.1:1/dir.json", timeout=1, allow_private=True)


def test_urls_are_deduplicated_in_order():
    entries = parse_directory(_doc({"url": "https://a"}, {"url": "https://b"}))
    assert urls_from_directories(entries) == ["https://a", "https://b"]


def test_directory_hint_matching_the_card_is_accepted(tmp_path):
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b")
    hints = {a: {"operator_id": "op-a", "chain": "mainnet-v1.0"},
             b: {"operator_id": "op-b", "chain": "mainnet-v1.0"}}
    result = collect("DIRTEST", [a, b], min_operators=2, hints=hints, allow_private=True)
    assert result.agreed, result.problems


def test_directory_claiming_the_wrong_operator_does_not_promote_the_witness(tmp_path):
    """A directory cannot make one operator look like two."""
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-a2", "op-a")
    hints = {a: {"operator_id": "op-a"}, b: {"operator_id": "op-b"}}
    result = collect("DIRTEST", [a, b], min_operators=2, hints=hints, allow_private=True)
    assert not result.agreed
    bad = [v for v in result.views if v.url == b][0]
    assert "disagrees with the directory" in (bad.problem or "")
    assert not bad.counts
    assert result.operators == ("op-a",)


def test_cli_accepts_a_directory(tmp_path):
    import subprocess, sys
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b")
    directory = tmp_path / "dir.json"
    directory.write_text(json.dumps(_doc({"url": a}, {"url": b})), encoding="utf-8")

    proc = subprocess.run([sys.executable, "-m", "avm_mesh", "corroborate",
                           "--txid", "DIRTEST", "--directory", str(directory), "--allow-private",
                           "--min-operators", "2", "--allow-private"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "AGREED" in proc.stdout


def test_cli_without_witness_or_directory_is_a_usage_error():
    import subprocess, sys
    proc = subprocess.run([sys.executable, "-m", "avm_mesh", "corroborate", "--txid", "X"],
                          capture_output=True, text=True)
    assert proc.returncode == 3
    assert "needs --witness or --directory" in proc.stderr
