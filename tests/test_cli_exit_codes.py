"""The CLI's documented exit codes, and the rails drop-in's translation of them.

`cli.py` says "Exit codes: 0 verified, 2 failed, 3 usage error" and the README repeats
it. That was not true: argparse exits 2 on a usage error, so a caller could not tell a
bad argument from a failed verification, and the rails wrapper's 3 -> 2 mapping (which
exists so a drop-in matches the tool it replaces) could never fire.

These tests pin the contract at both entry points, through subprocesses, because the
distinction only exists at the process boundary.
"""
import subprocess
import sys

import pytest


def _run(module: str, *args: str) -> int:
    return subprocess.run([sys.executable, "-m", module, *args],
                          capture_output=True, text=True, timeout=120).returncode


# ---------------------------------------------------------------- the shared CLI


def test_help_exits_zero():
    assert _run("avm_mesh", "--help") == 0


def test_a_missing_required_argument_is_a_usage_error_three():
    """Documented as 3 -- argparse's own 2 is not the documented contract."""
    assert _run("avm_mesh", "verify") == 3


def test_an_unknown_subcommand_is_a_usage_error_three():
    assert _run("avm_mesh", "not-a-command") == 3


def test_a_missing_receipt_file_is_a_usage_error_not_a_failed_verification(tmp_path):
    """A file that is not there is the caller's mistake, not a failed verification.

    This is the distinction that matters: 2 means "the receipt did not verify", which
    an operator may alert on; 3 means "you invoked this wrongly".
    """
    assert _run("avm_mesh", "verify", str(tmp_path / "absent.json")) == 3


def test_a_receipt_that_does_not_verify_is_two(tmp_path):
    bad = tmp_path / "receipt.json"
    bad.write_text('{"version": 1, "chain": "mainnet-v1.0", "txid": "A", "round": 1,'
                   ' "trust_root": "structural", "pointer": {"uri": "x",'
                   ' "digest": "' + "0" * 64 + '", "first_attested_round": 1,'
                   ' "last_attested_round": 2}}', encoding="utf-8")
    assert _run("avm_mesh", "verify", str(bad), "--evidence", str(tmp_path)) == 2


# ------------------------------------------------------- the rails drop-in


def test_rails_help_exits_zero():
    assert _run("avm_mesh.rails", "--help") == 0


def test_rails_translates_a_usage_error_to_two():
    """The rails verifier uses 2 for usage, so 3 must become 2 here.

    Before the translation was reachable, this returned 2 by accident -- argparse's own
    code -- which meant the mapping was never exercised and a real usage error was
    reported in the same space as a failed verification.
    """
    assert _run("avm_mesh.rails", "verify") == 2


def test_rails_reports_a_missing_receipt_as_a_usage_error_too():
    assert _run("avm_mesh.rails", "verify", "/nonexistent/receipt.json") == 2


def test_the_two_entry_points_disagree_by_design_on_usage_errors():
    """Shared 3, rails 2: the drop-in has to match the tool it replaces."""
    assert _run("avm_mesh", "verify") != _run("avm_mesh.rails", "verify")


@pytest.mark.parametrize("module", ["avm_mesh", "avm_mesh.rails"])
def test_both_entry_points_list_the_same_subcommands(module):
    out = subprocess.run([sys.executable, "-m", module, "--help"],
                         capture_output=True, text=True, timeout=120).stdout
    for command in ("verify", "serve", "corroborate", "anchor"):
        assert command in out, f"{module} --help does not list {command}"
