"""Are the two new guards load-bearing, or merely present?

Each entry removes one guard from the installed module and requires the named test to go
red. A guard nobody tests is a guard that can be deleted unnoticed, which is exactly how
0.13.4 shipped comparing a load-balanced label.

    python tools/mutation_independence.py

Exits 0 when every mutant was killed and the restored module still passes, 1 otherwise.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys

import avm_mesh

MODULE = pathlib.Path(avm_mesh.__file__).parent / "crossnode.py"
BACKUP = MODULE.with_suffix(".mutbak")

MUTANTS = [
    (
        "datacentre projection removed (compare the raw load-balanced value)",
        '    if header == "x-and-nl" and "@" in value:\n        return value.rsplit("@", 1)[1]\n',
        "    if False:\n        return value.rsplit('@', 1)[1]\n",
        "test_crossnode.py::test_two_nodes_of_one_datacentre_are_one_operator",
    ),
    (
        "rate header re-admitted as an identity (false-positive path)",
        'FINGERPRINT_HEADERS = ("x-and-nl",)',
        'FINGERPRINT_HEADERS = ("x-and-nl", "x-and-dl")',
        "test_crossnode.py::test_different_provider_headers_still_corroborate",
    ),
    # --- the three findings from the independent review of 0.13.4 ---
    (
        "finding 1: silence read as independence again (unknown -> corroborated)",
        "            and self.independence_state in (INDEPENDENCE_EVIDENCED, "
        "INDEPENDENCE_ASSERTED)",
        "            and self.independence_state != INDEPENDENCE_SAME",
        "test_independence_claim.py::test_silence_is_not_independence",
    ),
    (
        "finding 1b: the unknown state no longer withholds the claim",
        "        if state == INDEPENDENCE_UNKNOWN and not declared_independent:",
        "        if False:",
        "test_independence_claim.py::test_silence_is_not_independence",
    ),
    (
        "finding 2: waiving the witness reports corroboration again",
        "        result.independence_state = INDEPENDENCE_WAIVED",
        "        result.independence_state = INDEPENDENCE_EVIDENCED",
        "test_independence_claim.py::test_waiving_the_witness_never_reports_corroboration",
    ),
    (
        "finding 2b: CLI exit code follows agreed again, not corroborated",
        "    return 0 if all(r.corroborated for r in results) else 2",
        "    return 0 if all(r.agreed for r in results) else 2",
        "test_independence_claim.py::test_agreement_alone_is_not_enough_to_exit_zero",
        "src/avm_mesh/cli.py",
    ),
    (
        "endpoint identity back to string comparison",
        '    raw = endpoint.strip().lower()\n',
        '    return endpoint\n    raw = endpoint.strip().lower()\n',
        "test_independence_claim.py::"
        "test_duplicate_detection_fires_on_a_really_reachable_duplicate",
    ),
    (
        "the capture tool stops refusing a same-operator pair",
        "            if key in seen:\n                return (f\"operators {seen[key]!r} and {name!r} returned the same provider \"",
        "            if False:\n                return (f\"operators {seen[key]!r} and {name!r} returned the same provider \"",
        "test_independence_claim.py::test_the_capture_tool_refuses_a_same_operator_pair",
        "tools/fetch_corroborated_walk.py",
    ),
]


def run(test: str) -> tuple[int, str, bool]:
    """Run one test against the SAME module this script mutates.

    PYTHONPATH is deliberately PRESERVED. An earlier version stripped it, so pytest
    imported the installed avm_mesh while the mutations were applied to the source tree —
    every mutant appeared KILLED because the installed copy was the older, broken release,
    and the restore-baseline then failed for the same reason. Mutating one file while
    testing another measures nothing.
    """
    env = dict(os.environ)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", f"tests/{test}", "-q", "-p", "no:cacheprovider"],
        capture_output=True, text=True, env=env,
    )
    # pytest exits 4 for a usage/collection error and 5 for "no tests collected". Either
    # means the test did not run at all, which is NOT the same as the test failing: counting
    # it as a kill reports a guard as pinned when nothing was exercised. This harness
    # reached that state once (a doubled `tests/` prefix), and every mutant read KILLED.
    void = proc.returncode in (4, 5) or "no tests ran" in (proc.stdout + proc.stderr)
    return proc.returncode, (proc.stdout + proc.stderr)[-300:], void


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce the independence-mutation evidence: remove each guard, "
                    "require its test to fail, restore the file, require it to pass.")
    parser.add_argument("--verbose", action="store_true",
                        help="print each mutant's pytest tail even when it is killed")
    args = parser.parse_args(argv[1:])

    shutil.copy2(MODULE, BACKUP)
    original = MODULE.read_text(encoding="utf-8")
    failures = 0
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        for entry in MUTANTS:
            label, old, new, test = entry[:4]
            # Most mutants target crossnode.py; the capture tool is a separate file, and
            # applying its mutant to the wrong file would report a surviving mutant that
            # was never actually introduced into the code under test.
            target = pathlib.Path(root / entry[4]) if len(entry) > 4 else MODULE
            before = target.read_text(encoding="utf-8")
            if old not in before:
                print(f"  ANCHOR-MISSING  {label}")
                failures += 1
                continue
            target.write_text(before.replace(old, new, 1), encoding="utf-8")
            subprocess.run([sys.executable, "-m", "py_compile", str(target)], check=False)
            code, tail, void = run(test)
            if void:
                # Not a kill and not a survival: the test never executed.
                verdict = "VOID"
                failures += 1
            else:
                verdict = "KILLED" if code != 0 else "SURVIVED"
                if code == 0:
                    failures += 1
            print(f"  {verdict:8} {label}")
            if code == 0 or void or args.verbose:
                print(f"           {tail.strip().splitlines()[-1][:120]}")
            target.write_text(before, encoding="utf-8")
    finally:
        MODULE.write_text(original, encoding="utf-8")
        BACKUP.unlink(missing_ok=True)
        restored = MODULE.read_text(encoding="utf-8")
        print(f"  restore byte-identical: {restored == original}")

    code, tail, void = run("test_crossnode.py::test_two_nodes_of_one_datacentre_are_one_operator")
    if void:
        print("  baseline after restore: VOID -- the test did not run; every verdict above "
              "is meaningless")
        return 1
    print(f"  baseline after restore: {'green' if code == 0 else 'RED'}  {tail.strip().splitlines()[-1][:90]}")
    return 1 if failures or code != 0 else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
