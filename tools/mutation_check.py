"""Mutation checks for the exit-code contract and the tools guard.

A claim that a guard is load-bearing is only worth what can be reproduced. This script
removes each guard, runs the test that should notice, and requires it to fail; then it
restores the file and requires the test to pass again. It prints all three verdicts so a
reader can see the guard is exercised rather than merely present.

    python tools/mutation_check.py            # all checks
    python tools/mutation_check.py cli.py     # only checks touching a path

Exit codes: 0 every guard bit and was restored, 1 a guard did not bite, 2 could not run.

Nothing here is left mutated: each check restores the original bytes in a `finally`, and
the script verifies the restore before moving on.
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PY = sys.executable

#: (label, file, text to replace, replacement, test file, -k selector)
CHECKS: list[tuple[str, str, str, str, str, str]] = [
    (
        "cli: usage-error translation removed (argparse 2 leaks through)",
        "src/avm_mesh/cli.py",
        "    except SystemExit as exc:",
        "    except KeyboardInterrupt as exc:  # MUTATED",
        "tests/test_cli_exit_codes.py",
        "usage_error_three or translates_a_usage_error",
    ),
    (
        "rails: exit map emptied",
        "src/avm_mesh/rails/__main__.py",
        "_EXIT_MAP = {0: 0, 2: 1, 3: 2}",
        "_EXIT_MAP = {}  # MUTATED",
        "tests/test_cli_exit_codes.py",
        "translates_a_usage_error",
    ),
    (
        "rails: signing convention hex -> raw",
        "src/avm_mesh/rails/__main__.py",
        'signature_style="hex"',
        'signature_style="raw"  # MUTATED',
        "tests/test_cli_exit_codes.py",
        "translates_a_usage_error",
    ),
    (
        "exercise_serve: __main__ guard removed",
        "tools/exercise_serve.py",
        'if __name__ == "__main__":\n    raise SystemExit(main(sys.argv[1:]))',
        "main(sys.argv[1:])  # MUTATED",
        "tests/test_tools.py",
        "guards_its_entry_point",
    ),
    (
        # NOT a mutation of correctness: `"-h" in argv` was already list membership,
        # never a substring match, so the historical form behaved identically. Kept as
        # a check that the *test* pins the behaviour, not as a claim that the old code
        # was wrong -- an earlier version of this file asserted otherwise and would
        # have reported a false positive.
        "standalone verifier: help flag dropped entirely",
        "tools/verify_settlement_artifact.py",
        '    for flag in argv:\n        if flag in ("-h", "--help"):',
        '    for flag in argv:\n        if False:  # MUTATED',
        "tests/test_extension_vectors.py",
        "help_is_exact",
    ),
]

def _run_tests(targets: list[str], selector: str) -> tuple[int, str]:
    proc = subprocess.run([PY, "-m", "pytest", *targets, "-q", "--tb=no", "-k", selector],
                          cwd=str(ROOT), capture_output=True, text=True, timeout=900)
    tail = [line for line in proc.stdout.strip().splitlines() if line.strip()][-1:]
    return proc.returncode, (tail[0] if tail else proc.stdout[-200:])


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce the mutation evidence: remove each guard, require its test "
                    "to fail, restore the file, require it to pass.")
    parser.add_argument("only", nargs="?", default=None,
                        help="limit to checks whose file path contains this substring")
    args = parser.parse_args(argv[1:])

    only = args.only
    failures = 0

    for label, rel, old, new, test_file, selector in CHECKS:
        if only and only not in rel:
            continue
        path = ROOT / rel
        if not path.exists():
            print(f"SKIP  {label}: {rel} does not exist")
            failures += 1
            continue
        original = path.read_text(encoding="utf-8")
        # Normalise to LF for matching and restore the exact original bytes afterward.
        # A CRLF checkout made every multi-line anchor miss, which silently turned the
        # mutation into a no-op and reported "STILL GREEN" -- the same CRLF trap that
        # once made the clean-room gate read "0.4.0\r" and pass a failing comparison.
        normalised = original.replace("\r\n", "\n")
        if old not in normalised:
            print(f"SKIP  {label}: anchor not found in {rel} (the code moved; update this script)")
            failures += 1
            continue

        print(f"\n{label}")
        try:
            code, line = _run_tests([test_file], selector)
            print(f"  baseline   {'PASS' if code == 0 else 'FAIL'}  {line}")
            if code != 0:
                failures += 1
                continue

            mutated_text = normalised.replace(old, new, 1)
            assert mutated_text != normalised, "MUTATION DID NOT APPLY"
            path.write_text(mutated_text, encoding="utf-8")
            code, line = _run_tests([test_file], selector)
            if code == 0:
                print(f"  mutated    STILL GREEN  {line}  <- guard is not load-bearing")
                failures += 1
            else:
                print(f"  mutated    RED (bites)  {line}")
        finally:
            path.write_text(original, encoding="utf-8")

        restored = path.read_text(encoding="utf-8")
        if restored != original:
            print(f"  FAIL restore: {rel} differs from the original after restore")
            failures += 1
            continue
        code, line = _run_tests([test_file], selector)
        print(f"  restored   {'PASS' if code == 0 else 'FAIL'}  {line}")
        if code != 0:
            failures += 1

    print()
    if failures:
        print(f"MUTATION CHECK FAILED: {failures} problem(s)")
        return 1
    print("MUTATION CHECK PASSED: every guard bit and every file was restored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
