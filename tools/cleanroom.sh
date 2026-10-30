#!/bin/sh
# Clean-room gate. Runs INSIDE the container, against the installed wheel.
#
#   sh /work/tools/cleanroom.sh /work
#
# Exits non-zero if anything is unproven rather than merely unsuccessful:
#   - a wheel is missing from the artefact set
#   - any test SKIPS (a skip means an input was not staged, not that the code
#     is fine -- this is how three Falcon KAT tests silently stopped running)
#   - the audit scans zero modules (a rule that examines nothing passes)
#   - any red-team attack is accepted
#
# A stage that could not run must fail. Reporting PASS for work that did not
# happen is worse than a red result, because the run then certifies it.

set -u

WORK="${1:-/work}"
ART="$WORK/artefacts"
SRC="$WORK/src/avm-mesh"
VENV="$WORK/venv"
FIXTURE="$WORK/src/avm-proofpack/tests/fixtures/stake_attested_algorand_66457600.json.gz"

FAILED=0
verdict() {  # verdict <rc> <stage>
    if [ "$1" -eq 0 ]; then
        echo "PASS  $2"
    else
        echo "FAIL  $2"
        FAILED=1
    fi
}

echo "=== 1. artefact set ==="
for wheel in "$ART"/avm_mesh-*.whl "$ART"/avm_proofpack-*.whl; do
    [ -f "$wheel" ] || { echo "MISSING $wheel"; FAILED=1; }
done
[ -f "$FIXTURE" ] || { echo "MISSING $FIXTURE"; FAILED=1; }
ls "$ART" >/dev/null 2>&1; verdict $? "artefacts staged"
[ "$FAILED" -eq 0 ] || { echo "ABORT: install would be meaningless"; exit 1; }

echo "=== 2. offline install ==="
python -m venv "$VENV" >/dev/null 2>&1
"$VENV"/bin/pip install -q --no-index --find-links "$ART" avm_mesh avm_proofpack avm_effectproof pytest >/tmp/install.log 2>&1
verdict $? "offline install from wheels only"

# The installed version must match the source, or the wheel is stale and every
# green number below describes code that is not in the repository. Hardcoded
# versions rot: this check said 0.2.2 after the bump to 0.3.0 and printed a note
# instead of failing.
# CRLF must be stripped: pyproject.toml is edited on Windows and staged to Linux,
# so a naive capture yields "0.4.0\r" and the comparison can never succeed.
EXPECTED_VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/pyproject.toml" | head -1 | tr -d '\r')
[ -n "$EXPECTED_VERSION" ] || { echo "cannot read version from $SRC/pyproject.toml"; exit 1; }
INSTALLED_VERSION=$("$VENV"/bin/pip show avm-mesh 2>/dev/null | sed -n 's/^Version: //p' | tr -d '\r')
if [ "$INSTALLED_VERSION" = "$EXPECTED_VERSION" ]; then
    verdict 0 "installed wheel matches source version $EXPECTED_VERSION"
else
    echo "      expected $EXPECTED_VERSION, installed ${INSTALLED_VERSION:-<none>}"
    verdict 1 "installed wheel does not match source version"
fi

echo "=== 3. suite (skips are failures) ==="
"$VENV"/bin/python -m pytest "$SRC/tests" -q --junitxml=/tmp/j.xml >/tmp/pytest.log 2>&1
verdict $? "suite passed"
"$VENV"/bin/python - <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse("/tmp/j.xml").getroot()
suite = root if root.tag == "testsuite" else root.find("testsuite")
skipped = int(suite.get("skipped", 0))
tests = int(suite.get("tests", 0))
print(f"      {tests} tests, {skipped} skipped")
if tests == 0:
    print("FAIL  pytest collected nothing"); sys.exit(1)
if skipped:
    print("FAIL  tests skipped: an input was not staged"); sys.exit(1)
sys.exit(0)
PY
verdict $? "no tests skipped"

echo "=== 4. trust audit ==="
"$VENV"/bin/python "$SRC/tools/audit_trust_boundary.py" >/tmp/audit.log 2>&1
AUDIT_RC=$?
grep -E "^rule" /tmp/audit.log
verdict $AUDIT_RC "audit rule A (sibling parity)"

echo "=== 5. red team ==="
"$VENV"/bin/python "$SRC/tools/red_team.py" --fixture "$FIXTURE" >/tmp/redteam.log 2>&1
verdict $? "red team refused every attack"
tail -2 /tmp/redteam.log

echo
if [ "$FAILED" -ne 0 ]; then
    echo "CLEAN-ROOM FAILED"
    exit 1
fi
echo "CLEAN-ROOM GREEN"
