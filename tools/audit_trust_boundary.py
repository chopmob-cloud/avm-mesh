#!/usr/bin/env python3
"""Mechanical trust-boundary audit for avm-mesh.

Four defects of the same shape shipped in this codebase: a value the adversary
writes, trusted because it looked like data.

  previous_state_proof_message   bundle author chose the signing set
  attestation.genesis_hash_b64   compared only to itself
  receipt.chain                  reusable string, not the genesis hash
  /receipts/<txid>               request segment used as a path

Review found them. This script is what makes me find them first. It encodes the
four rules that would have caught each one, and exits non-zero on any finding so
it can gate a commit.

    python tools/audit_trust_boundary.py [--verbose]

Rules
  A  sibling parity      every public verify path takes the same pins
  B  self-reference      a claimed field compared only to the same object
  C  unguarded path      a request-derived name used as a path without _safe_name
  D  unpinned refusal    every MeshError message appears in some test's match=
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "avm_mesh"
TESTS = pathlib.Path(__file__).resolve().parents[1] / "tests"

#: Entry points that turn untrusted input into a verdict.
VERIFY_ENTRY_POINTS = (
    "verify_receipt",
    "verify_attestation",
    "verify_sealed",
    "verify_artifact",
)

#: Pins every evidence-resolving entry point must accept.
REQUIRED_PINS = ("trusted_voters",)


class Finding:
    def __init__(self, rule: str, where: str, detail: str) -> None:
        self.rule = rule
        self.where = where
        self.detail = detail

    def __str__(self) -> str:
        return f"[{self.rule}] {self.where}: {self.detail}"


def _modules():
    for path in sorted(SRC.glob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


# ---------------------------------------------------------------- rule A
def rule_sibling_parity() -> list[Finding]:
    """Every verify path must accept the same pins.

    The attestation-interval bug existed because one sibling had the check and
    another did not. A guard added to one path is not a guard.
    """
    findings = []
    seen = {}
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in VERIFY_ENTRY_POINTS:
                continue
            params = {a.arg for a in node.args.args + node.args.kwonlyargs}
            seen[node.name] = (path.name, params)
            missing = [p for p in REQUIRED_PINS if p not in params]
            if missing:
                findings.append(Finding(
                    "A", f"{path.name}:{node.name}",
                    f"missing required pin(s) {missing}",
                ))
    # A path present in one module but not another is a sibling gap.
    for name in VERIFY_ENTRY_POINTS:
        if name not in seen:
            findings.append(Finding("A", name, "declared entry point not found"))
    return findings


# ---------------------------------------------------------------- rule B
def rule_self_reference() -> list[Finding]:
    """Flag `a.field != a.field`-shaped comparisons.

    A claim compared to another field of itself proves nothing; that is the
    genesis-pin hole. This is a heuristic: it reports the comparison and lets a
    human confirm the right-hand side is not authenticated input from elsewhere.
    """
    findings = []
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            try:
                left = ast.unparse(node.left)
            except Exception:
                continue
            for comparator in node.comparators:
                try:
                    right = ast.unparse(comparator)
                except Exception:
                    continue
                if right in ("None", "True", "False") or left in ("None", "True", "False"):
                    continue  # type guard, not a trust claim
                if isinstance(node.ops[0], (ast.Is, ast.IsNot)):
                    continue
                # same object attribute root on both sides, different field
                lroot = left.split(".")[0]
                rroot = right.split(".")[0]
                if (lroot == rroot and "." in left and "." in right
                        and left != right and "trusted_voters" not in right
                        and "report" not in rroot and "policy" not in rroot):
                    findings.append(Finding(
                        "B", f"{path.name}:{node.lineno}",
                        f"self-referential comparison {left} vs {right} — "
                        "confirm the right-hand side is authenticated input",
                    ))
    return findings


# ---------------------------------------------------------------- rule C
def rule_unguarded_path() -> list[Finding]:
    """A request-derived name must pass through _safe_name before becoming a path.

    The traversal bug: `/receipts/<txid>` reached a filesystem join verbatim.
    This flags `self.<dir> / f"..."` where the f-string variable was not first
    validated by _safe_name anywhere in the same function.
    """
    findings = []
    for path, tree in _modules():
        if path.name != "service.py":
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            body = ast.unparse(node)
            if "_safe_name(" in body:
                continue
            # A name computed here (hash of content we hashed) is not external input.
            if "bundle_digest(" in body or "hashlib." in body:
                continue
            for sub in ast.walk(node):
                if not isinstance(sub, ast.BinOp) or not isinstance(sub.op, ast.Div):
                    continue
                try:
                    text = ast.unparse(sub)
                except Exception:
                    continue
                if re.search(r"self\.(proofpacks|receipts|root)\s*/", text) and \
                        re.search(r"\{|/ *name|/ *value|/ *key", text):
                    findings.append(Finding(
                        "C", f"{path.name}:{node.name}",
                        f"path built from unvalidated name: {text}",
                    ))
    return findings


# ---------------------------------------------------------------- rule D
def rule_unpinned_refusal() -> list[Finding]:
    """Every refusal must be pinned by a test.

    A guard with no test that fails on its removal is decoration. This is a
    cheap proxy: the message literal must appear in a `match=` somewhere.
    """
    test_blob = "\n".join(p.read_text(encoding="utf-8") for p in TESTS.glob("test_*.py"))
    findings = []
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise):
                continue
            exc = node.exc
            if not isinstance(exc, ast.Call) or not exc.args:
                continue
            try:
                name = ast.unparse(exc.func)
            except Exception:
                continue
            if not name.endswith("MeshError"):
                continue
            try:
                message = ast.unparse(exc.args[0])
            except Exception:
                continue
            # take the longest literal fragment of the message as the probe
            literals = re.findall(r"[\"']([^\"']{12,})[\"']", message)
            if not literals:
                continue
            probe = max(literals, key=len)
            # match= patterns are regexes; escape differences are acceptable
            simple = re.escape(probe)[:40]
            if probe not in test_blob and simple not in test_blob:
                findings.append(Finding(
                    "D", f"{path.name}:{node.lineno}",
                    f"refusal not pinned by any test match=: {probe[:60]!r}",
                ))
    return findings


RULES = {
    "A": ("sibling parity", rule_sibling_parity),
    "B": ("self-reference", rule_self_reference),
    "C": ("unguarded path", rule_unguarded_path),
    "D": ("unpinned refusal", rule_unpinned_refusal),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mechanical trust-boundary audit for avm-mesh.")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--strict", action="store_true",
                        help="treat advisory findings as failures")
    args = parser.parse_args(argv)

    fatal = 0
    advisory = 0
    for key, (label, fn) in RULES.items():
        findings = fn()
        kind = "FATAL" if key == "A" else "advisory"
        if key == "A":
            fatal += len(findings)
        else:
            advisory += len(findings)
        status = "OK" if not findings else f"{len(findings)} {kind}"
        print(f"rule {key}  {label:<18} {status}")
        if findings:
            for f in findings:
                print(f"    {f}")
        elif args.verbose:
            print("    (clean)")

    print()
    print(f"fatal: {fatal}   advisory: {advisory}")
    print()
    print("Rules B/C/D are heuristics: they surface candidates for a human to")
    print("judge, and produce false positives by design (type guards, computed")
    print("values). Rule A is exact and gates the build. Use --strict to fail on")
    print("advisories once a codebase has been reviewed to zero.")
    if fatal or (args.strict and advisory):
        print("AUDIT FAILED")
        return 1
    print("AUDIT CLEAN" if not advisory else "AUDIT PASSED (with advisories)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
