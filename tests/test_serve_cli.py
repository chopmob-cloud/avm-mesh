"""The `serve` command the README documents must exist and behave."""
import pathlib

import pytest

from avm_mesh.cli import _build_parser, main


def _serve_args(parser):
    for action in parser._actions:
        if action.dest == "cmd" and action.choices:
            return action.choices["serve"]
    raise AssertionError("no serve subparser")


def test_serve_is_a_documented_command_with_its_flags():
    parser = _build_parser()
    serve = _serve_args(parser)
    flags = {opt for action in serve._actions for opt in action.option_strings}
    for expected in ("--root", "--port", "--host", "--witness-id", "--operator-id",
                     "--escrow-txid", "--anchor-voters-commitment-b64",
                     "--anchor-ln-proven-weight"):
        assert expected in flags, f"README-documented flag {expected} missing"


def test_readme_example_parses():
    """The exact invocation in the README must be accepted by the parser."""
    args = _build_parser().parse_args(
        ["serve", "--root", "./store", "--port", "8080", "--witness-id", "w1",
         "--operator-id", "op-a", "--escrow-txid", "ESC"])
    assert args.cmd == "serve"
    assert args.port == 8080


def test_unopenable_store_is_a_usage_error_not_a_traceback(tmp_path):
    target = tmp_path / "not-a-dir"
    target.write_text("x", encoding="utf-8")
    assert main(["serve", "--root", str(target)]) == 3


def test_partial_witness_card_is_refused_rather_than_published(tmp_path, capsys):
    """Half a card would advertise an anchor the witness does not hold."""
    from avm_mesh.service import Store

    root = tmp_path / "store"
    Store(str(root))  # creates the layout
    code = main(["serve", "--root", str(root), "--witness-id", "w1", "--port", "0"])
    err = capsys.readouterr().err
    assert "incomplete witness card" in err
    assert "operator_id" in err
    assert code == 3, "must refuse to start, not serve under a half-configured identity"
