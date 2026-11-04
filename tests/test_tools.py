"""Every tool in `tools/` runs, and takes `--help`.

Three tools had rotted without anyone noticing, because nothing ran them:
`exercise_serve.py` crashed with an uncaught traceback on `--help` (it had no `__main__`
guard and executed a server on import), `check_artifacts.py` and `make_example.py`
treated `--help` as a path and printed "no such directory"/"fixture not found" before
exiting 0. A tool that is never invoked does not fail; it just stops being true.

These tests are deliberately shallow -- they check that each script is a program with a
usage line, not that it works -- because the deeper checks live where the script is
actually exercised (the cleanroom gate and CI). What they prevent is a script silently
becoming a file that does something unintended when run.
"""
import pathlib
import subprocess
import sys

import pytest

TOOLS = pathlib.Path(__file__).resolve().parents[1] / "tools"

#: Scripts that are a server or a library rather than a one-shot program: `--help`
#: either blocks (the A2A SUT binds a socket) or is meaningless.
NOT_PROGRAMS = {"sut/avm_sut.py"}


def _scripts() -> list[pathlib.Path]:
    found = [p for p in TOOLS.rglob("*.py") if "__pycache__" not in p.parts]
    return sorted(p for p in found
                  if p.relative_to(TOOLS).as_posix() not in NOT_PROGRAMS)


def test_there_are_scripts_to_check():
    assert len(_scripts()) >= 6, [str(p.name) for p in _scripts()]


def test_the_exclusion_list_still_matches_a_real_file():
    """A stale exclusion silently stops checking a script."""
    for name in NOT_PROGRAMS:
        assert (TOOLS / name).exists(), f"{name} is excluded but no longer exists"


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.name)
def test_the_script_prints_usage_for_help(script):
    """`--help` must be a usage line, not a path the script tried to open."""
    run = subprocess.run([sys.executable, str(script), "--help"],
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, f"{script.name} --help exited {run.returncode}: {run.stderr[-400:]}"
    assert "usage:" in run.stdout.lower(), f"{script.name} printed no usage line: {run.stdout[:200]}"
    # The two shapes that were wrong before: a traceback, or a path complaint.
    for wrong in ("Traceback (most recent call last)", "no such directory",
                  "fixture not found"):
        assert wrong not in run.stdout and wrong not in run.stderr, \
            f"{script.name} still treats --help as an argument: {wrong}"


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.name)
def test_the_script_guards_its_entry_point(script):
    """Importing a tool must not run it.

    `exercise_serve.py` started a server at import time, with no `if __name__` guard,
    so importing it from a test or a REPL bound a port. The probe asserts the *import*
    completes and that no process was started: `subprocess.Popen` is stubbed to explode,
    which is the one side effect that matters for these scripts. It does not prove the
    absence of every possible side effect (file writes, sockets) — the claim is narrow
    on purpose, and the honest wording here is what a future reader relies on.
    """
    probe = (
        "import importlib.util, sys\n"
        "import subprocess\n"
        "class Boom:\n"
        "    def __init__(self, *a, **k):\n"
        "        raise AssertionError('the tool ran its job on import')\n"
        "subprocess.Popen = Boom\n"
        f"spec = importlib.util.spec_from_file_location('probe', r'{script}')\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "print('imported')\n"
    )
    run = subprocess.run([sys.executable, "-c", probe],
                         capture_output=True, text=True, timeout=120,
                         cwd=str(script.parent))
    assert run.returncode == 0, \
        f"{script.name} did work on import: {run.stderr[-600:]}"
    assert "imported" in run.stdout


def test_exercise_serve_exits_non_zero_when_a_probe_fails():
    """It must be usable as a test, not only readable as a report.

    Asserted structurally rather than by running a failing server: the script has a
    FAILURES list and returns 1 when it is non-empty.
    """
    source = (TOOLS / "exercise_serve.py").read_text(encoding="utf-8")
    assert "FAILURES" in source
    assert "return 1" in source
    assert "return 2" in source, "a script that cannot run must say so distinctly"
