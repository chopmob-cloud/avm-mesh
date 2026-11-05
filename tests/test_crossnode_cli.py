"""`crossnode` refuses honestly and reports the refusal in its exit code.

The network is not exercised here: a test that depends on a public endpoint's current
retention would break within minutes, and the round named in the README already expires.
Everything checked here is local and deterministic.
"""
import pytest

from avm_mesh import cli
from avm_mesh.crossnode import CorroborationError, corroborate_captures, corroborate_round


def test_a_round_off_the_interval_grid_is_refused():
    with pytest.raises(CorroborationError, match="interval boundary"):
        corroborate_round(1234)


def test_a_single_operator_is_refused_as_theatre():
    with pytest.raises(CorroborationError, match="at least 2"):
        corroborate_round(66647808, min_operators=1)


def test_a_capture_directory_with_no_rounds_is_refused(tmp_path):
    (tmp_path / "provenance.json").write_text("{}", encoding="utf-8")
    with pytest.raises(CorroborationError, match="no round-named captures"):
        corroborate_captures(tmp_path)


def test_a_missing_capture_directory_is_refused(tmp_path):
    with pytest.raises(CorroborationError, match="does not exist"):
        corroborate_captures(tmp_path / "nope")


def test_the_cli_refuses_with_a_usage_exit_code_when_given_nothing(capsys):
    """Exit 3 means malformed input; exit 2 means a real refusal. They must not blur."""
    code = cli.main(["crossnode"])
    assert code == 3
    assert "give --round, --bundles, or both" in capsys.readouterr().err


def test_the_cli_refuses_a_malformed_operator_spec(capsys):
    code = cli.main(["crossnode", "--round", "66647808", "--operator", "nonsense"])
    assert code == 3
    assert "NAME=URL" in capsys.readouterr().err


def test_the_cli_reports_a_disagreement_as_exit_2(monkeypatch, capsys):
    """Refusal (2) is a verdict about the network; malformed input (3) is about the call."""
    from avm_mesh.crossnode import Corroboration, OperatorResponse

    def fake(round_number, **kwargs):
        return Corroboration(
            round=round_number, agreed=False,
            responders=[
                OperatorResponse(name="a", endpoint="http://a", ok=True,
                                 voters_commitment="x", ln_proven_weight=1),
                OperatorResponse(name="b", endpoint="http://b", ok=True,
                                 voters_commitment="y", ln_proven_weight=1),
            ],
            agreement={"voters_commitment": {"agreed": False,
                                            "values": {"a": "x", "b": "y"}}},
            failure="operators disagree on voters_commitment")

    monkeypatch.setattr("avm_mesh.crossnode.corroborate_round", fake)
    code = cli.main(["crossnode", "--round", "66647808"])
    out = capsys.readouterr().out
    assert code == 2
    assert "REFUSED" in out
    assert "disagree on voters_commitment" in out


def test_both_round_and_bundles_are_honoured(monkeypatch, capsys, tmp_path):
    """`--round` used to be required and then silently dropped when `--bundles` was given.

    A user asking about one specific interval got answers about whichever rounds happened
    to be in the directory, with no indication that their round was ignored.
    """
    from avm_mesh.crossnode import Corroboration

    asked = []

    def fake_round(round_number, **kwargs):
        asked.append(round_number)
        return Corroboration(round=round_number, agreed=True,
                             responders=[], agreement={})

    def fake_caps(directory, **kwargs):
        return [Corroboration(round=66647552, agreed=True, responders=[], agreement={})]

    monkeypatch.setattr("avm_mesh.crossnode.corroborate_round", fake_round)
    monkeypatch.setattr("avm_mesh.crossnode.corroborate_captures", fake_caps)
    code = cli.main(["crossnode", "--round", "66647808",
                     "--bundles", str(tmp_path)])
    assert code == 0
    assert asked == [66647808], "the round the user named was dropped"
    out = capsys.readouterr().out
    assert "66647808" in out and "66647552" in out


def test_a_round_named_twice_is_checked_once(monkeypatch, tmp_path):
    from avm_mesh.crossnode import Corroboration

    asked = []

    def fake_round(round_number, **kwargs):
        asked.append(round_number)
        return Corroboration(round=round_number, agreed=True, responders=[], agreement={})

    def fake_caps(directory, **kwargs):
        return [Corroboration(round=66647808, agreed=True, responders=[], agreement={})]

    monkeypatch.setattr("avm_mesh.crossnode.corroborate_round", fake_round)
    monkeypatch.setattr("avm_mesh.crossnode.corroborate_captures", fake_caps)
    code = cli.main(["crossnode", "--round", "66647808", "--bundles", str(tmp_path)])
    assert code == 0
    assert asked == [], "a round covered by the directory was fetched again"
