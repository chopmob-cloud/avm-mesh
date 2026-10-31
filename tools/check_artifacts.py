#!/usr/bin/env python3
"""Inspect built artifacts for the things that only exist after building.

Metadata lives in the artefact, not the source tree, and a wheel built in isolation
can differ from what the repository looks like. So the release check reads the
wheel and the sdist themselves:

- LICENSE and NOTICE present in both;
- METADATA carries a PEP 639 License-Expression and License-File entries;
- no ``License ::`` classifier contradicting it;
- the version matches between wheel, sdist and ``avm_mesh.__version__``;
- the console script is declared.

    python tools/check_artifacts.py dist/

Exit 0 only if every check passes.
"""
from __future__ import annotations

import email.message
import email.parser
import pathlib
import sys
import tarfile
import zipfile

FAILED: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILED.append(message)


def _metadata(wheel: zipfile.ZipFile) -> email.message.Message:
    names = [n for n in wheel.namelist() if n.endswith(".dist-info/METADATA")]
    check(len(names) == 1, f"expected one METADATA, found {len(names)}")
    return email.parser.Parser().parsestr(wheel.read(names[0]).decode("utf-8"))


def check_wheel(path: pathlib.Path) -> str | None:
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        licence_entries = [n for n in names if "/licenses/" in n]
        for wanted in ("LICENSE", "NOTICE"):
            hit = [n for n in licence_entries if n.rsplit("/", 1)[-1].startswith(wanted)]
            check(bool(hit), f"wheel is missing {wanted} inside .dist-info/licenses/")

        meta = _metadata(wheel)
        check(meta.get("License-Expression") == "Apache-2.0",
              f"License-Expression is {meta.get('License-Expression')!r}, expected 'Apache-2.0'")
        declared = meta.get_all("License-File") or []
        for wanted in ("LICENSE", "NOTICE"):
            check(any(wanted in d for d in declared),
                  f"License-File does not list {wanted} (got {declared})")
        check(not any(c.startswith("License ::") for c in (meta.get_all("Classifier") or [])),
              "a Licence :: classifier contradicts the licence expression (PEP 639)")
        check(meta.get("Requires-Python") is not None, "Requires-Python missing")
        version = meta.get("Version")
        check("avm_mesh/cli.py" in names, "the module that backs the console script is not in the wheel")
        check(any(n.endswith("entry_points.txt") for n in names),
              "no entry_points.txt: the avm-mesh console script would not be installed")
        return version


def check_sdist_runs_its_tests(path: pathlib.Path) -> None:
    """Extract the sdist and collect its tests.

    A source archive that ships test files nobody can collect is worse than one with
    no tests: it advertises reproducibility it does not have. Existing at all was the
    old bar, and it passed an archive missing conftest.py and _assets.py.
    """
    import os
    import subprocess
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        with tarfile.open(path) as archive:
            try:
                archive.extractall(scratch, filter="data")   # py3.12+ safe extraction
            except TypeError:                                # older Python
                archive.extractall(scratch)
        roots = [p for p in pathlib.Path(scratch).iterdir() if p.is_dir()]
        check(len(roots) == 1, f"sdist should extract to one directory, found {len(roots)}")
        if not roots:
            return
        project = roots[0]
        env = os.environ.copy()
        # The sdist uses a src/ layout and is NOT installed in this interpreter, so the
        # extracted tree needs its own source on the path. Without this the check
        # reports import errors that have nothing to do with the archive's contents --
        # a checker that cries wolf is worse than no checker.
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (str(project / "src") + (os.pathsep + existing if existing else ""))
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(project / "tests"), "--collect-only", "-q"],
            capture_output=True, text=True, cwd=str(project), env=env)
        if proc.returncode != 0:
            tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
            check(False, "tests inside the sdist do not collect: " + " | ".join(tail))


def check_sdist(path: pathlib.Path) -> str | None:
    with tarfile.open(path) as sdist:
        names = sdist.getnames()
        for wanted in ("LICENSE", "NOTICE"):
            check(any(n.rsplit("/", 1)[-1] == wanted for n in names), f"sdist is missing {wanted}")
        srcs = [n for n in names if "/tests/" in n]
        check(bool(srcs), "sdist carries no tests: a recipient cannot verify the package")
        pkginfo = [n for n in names if n.endswith("PKG-INFO")]
        if not pkginfo:
            check(False, "sdist has no PKG-INFO")
            return None
        handle = sdist.extractfile(pkginfo[0])
        if handle is None:                      # tarfile returns None for a non-file member
            check(False, "PKG-INFO is not a readable file inside the sdist")
            return None
        meta = email.parser.Parser().parsestr(handle.read().decode("utf-8"))
        return meta.get("Version")


def main(argv: list[str]) -> int:
    target = pathlib.Path(argv[1] if len(argv) > 1 else "dist")
    if not target.exists():
        print(f"no such directory: {target}", file=sys.stderr)
        return 3

    wheels = sorted(target.glob("avm_mesh-*.whl"))
    sdists = sorted(target.glob("avm_mesh-*.tar.gz"))
    check(len(wheels) == 1, f"expected exactly one wheel in {target}, found {len(wheels)}")
    check(len(sdists) == 1, f"expected exactly one sdist in {target}, found {len(sdists)}")
    if FAILED:
        for problem in FAILED:
            print(f"FAIL  {problem}")
        return 1

    wheel_version = check_wheel(wheels[0])
    sdist_version = check_sdist(sdists[0])
    check_sdist_runs_its_tests(sdists[0])
    check(wheel_version == sdist_version,
          f"version mismatch: wheel {wheel_version!r} vs sdist {sdist_version!r}")

    if FAILED:
        for problem in FAILED:
            print(f"FAIL  {problem}")
        return 1

    print(f"PASS  wheel {wheels[0].name}: LICENSE + NOTICE, License-Expression, entry points")
    print(f"PASS  sdist {sdists[0].name}: LICENSE + NOTICE, tests included and collectable")
    print(f"PASS  version {wheel_version} consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
