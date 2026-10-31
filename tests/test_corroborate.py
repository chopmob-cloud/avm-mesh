"""Corroboration across witnesses: agreement, and the three ways it gets faked."""
import json

import pytest

from avm_mesh import MeshError
from avm_mesh.corroborate import collect
from avm_mesh.receipt import ProofpackPointer, SettlementReceipt, bundle_digest
from avm_mesh.service import Store, WitnessInfo, run_in_thread

BUNDLE = {"transaction": {"txid": "CORROB", "round": 66457600},
          "state_proof_message": {"note": "fixture"}}
DIGEST = bundle_digest(BUNDLE)


def _receipt(txid="CORROB", digest=DIGEST, tier="structural"):
    return SettlementReceipt(
        version=1, chain="mainnet-v1.0", txid=txid, round=66457600,
        trust_root=tier,
        pointer=ProofpackPointer(uri=f"proofpack:{digest}", digest=digest,
                                 first_attested_round=66457344,
                                 last_attested_round=66457600))


def _witness(tmp_path, name, operator, *, bundle=None, receipt=None,
             tamper_proofpack=False, with_card=True):
    store = Store(tmp_path / name)
    store.put_proofpack(bundle or BUNDLE)
    store.put_receipt(receipt or _receipt())
    if tamper_proofpack:
        # The pointer stays honest and the bytes behind it are swapped: exactly the
        # substitution a witness could attempt, and invisible to a shape check.
        (store.proofpacks / f"{DIGEST}.json").write_text(
            json.dumps({"transaction": {"txid": "OTHER"}}), encoding="utf-8")
    info = None
    if with_card:
        info = WitnessInfo(witness_id=name, operator_id=operator, chain="mainnet-v1.0",
                           escrow_txid="ESC", anchor_voters_commitment_b64="A" * 44,
                           anchor_ln_proven_weight=2230418)
    server, _thread = run_in_thread(store, info)
    return f"http://127.0.0.1:{server.server_address[1]}"


def test_two_independent_operators_agreeing_counts(tmp_path):
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b")
    result = collect("CORROB", [a, b], min_operators=2)
    assert result.agreed, result.problems
    assert result.agreed_digest == DIGEST
    assert result.operators == ("op-a", "op-b")


def test_two_endpoints_of_one_operator_do_not_agree(tmp_path):
    """The cheapest way to fake a mesh: run the same operator twice."""
    a = _witness(tmp_path, "w-a1", "op-a")
    b = _witness(tmp_path, "w-a2", "op-a")
    result = collect("CORROB", [a, b], min_operators=2)
    assert not result.agreed
    assert any("one voice" in p for p in result.problems)
    assert result.operators == ("op-a",)


def test_witnesses_pointing_at_different_evidence_do_not_agree(tmp_path):
    other = dict(BUNDLE, state_proof_message={"note": "different"})
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b", bundle=other,
                 receipt=_receipt(digest=bundle_digest(other)))
    result = collect("CORROB", [a, b], min_operators=2)
    assert not result.agreed
    assert any("which proofpack" in p for p in result.problems)


def test_a_tampered_store_refuses_to_serve_at_all(tmp_path):
    """Our own service catches this first: the store is content-addressed.

    The filename IS the digest, so bytes that no longer hash to it are a fault on
    the witness side, not a client-side judgement call. 500, not 200-with-wrong-data.
    """
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b", tamper_proofpack=True)
    result = collect("CORROB", [a, b], min_operators=2)
    assert not result.agreed
    bad = [v for v in result.views if v.url == b][0]
    assert bad.problem == "proofpack not served (HTTP 500)"
    assert not bad.counts


def test_client_rejects_a_witness_that_serves_the_wrong_bytes(tmp_path, monkeypatch):
    """Defence in depth: another implementation may not verify what it serves.

    Ours does, so the client-side check cannot be reached through our service. It
    is exercised here directly, because it is the only thing standing between a
    peer's dishonest store and this client.
    """
    import avm_mesh.corroborate as corroborate

    witness_url = "http://127.0.0.1:9"
    honest_receipt = json.dumps(_receipt().to_dict()).encode()
    wrong_bundle = json.dumps({"transaction": {"txid": "OTHER"}}).encode()

    # The real _get takes a per-endpoint byte limit; a double must mirror the
    # signature or it fails with "unexpected keyword argument", not the condition
    # the test is about.
    def fake_get(url, timeout, limit=None, **kwargs):
        if url.endswith("/witness"):
            return 200, json.dumps({"witness_id": "w-x",
                                    "operator_id": "op-x"}).encode()
        if "/receipts/" in url:
            return 200, honest_receipt
        return 200, wrong_bundle

    monkeypatch.setattr(corroborate, "_get", fake_get)
    result = collect("CORROB", [witness_url], min_operators=1)
    assert not result.agreed
    assert result.views[0].problem == "proofpack bytes do not match the pointer digest"
    assert not result.views[0].counts


def test_a_witness_without_a_card_cannot_corroborate(tmp_path):
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b", with_card=False)
    result = collect("CORROB", [a, b], min_operators=2)
    assert not result.agreed
    assert result.operators == ("op-a",)


def test_disagreeing_tiers_are_reported(tmp_path):
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b", receipt=_receipt(tier="stake_attested"))
    result = collect("CORROB", [a, b], min_operators=2)
    assert not result.agreed
    assert any("trust tier" in p for p in result.problems)


def test_missing_receipt_is_reported_not_raised(tmp_path):
    a = _witness(tmp_path, "w-a", "op-a")
    result = collect("ABSENT", [a], min_operators=1)
    assert not result.agreed
    assert "receipt not served" in result.views[0].problem


def test_unreachable_witness_is_reported_not_raised():
    result = collect("CORROB", ["http://127.0.0.1:1"], min_operators=1)
    assert not result.agreed
    assert result.views[0].problem


def test_bad_arguments_are_refused():
    with pytest.raises(MeshError):
        collect("", ["http://x"])
    with pytest.raises(MeshError):
        collect("CORROB", [])
    with pytest.raises(MeshError):
        collect("CORROB", ["http://x"], min_operators=0)


# --- the command an operator actually runs --------------------------------

def _cli(*args):
    import subprocess, sys
    return subprocess.run([sys.executable, "-m", "avm_mesh", *args],
                          capture_output=True, text=True)


def test_cli_reports_agreement_and_exits_zero(tmp_path):
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b")
    proc = _cli("corroborate", "--txid", "CORROB",
                "--witness", a, "--witness", b, "--min-operators", "2")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "AGREED" in proc.stdout
    assert "op-a" in proc.stdout and "op-b" in proc.stdout


def test_cli_refuses_one_operator_twice_with_exit_two(tmp_path):
    a = _witness(tmp_path, "w-a1", "op-a")
    b = _witness(tmp_path, "w-a2", "op-a")
    proc = _cli("corroborate", "--txid", "CORROB",
                "--witness", a, "--witness", b, "--min-operators", "2")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "one voice" in proc.stdout


def test_cli_json_output_is_machine_readable(tmp_path):
    import json as _json
    a = _witness(tmp_path, "w-a", "op-a")
    b = _witness(tmp_path, "w-b", "op-b")
    proc = _cli("corroborate", "--txid", "CORROB", "--witness", a,
                "--witness", b, "--json")
    payload = _json.loads(proc.stdout)
    assert payload["agreed"] is True
    assert payload["agreed_digest"] == DIGEST
    assert len(payload["witnesses"]) == 2
