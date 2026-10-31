"""Packaging guards: what the README promises must exist in the installed package.

These exist because 0.4.2 shipped to PyPI with `avm-mesh verify` documented in the
README and no console script defined, so every install got "command not found".
Every other test imports the module, so none of them could notice.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _pyproject() -> str:
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_console_script_is_declared_and_points_at_a_real_callable():
    body = _pyproject()
    match = re.search(r"(?ms)^\[project\.scripts\]\s*(.*?)(?=^\[|\Z)", body)
    assert match, "no [project.scripts] table: the documented CLI would not be installed"

    entry = re.search(r'^avm-mesh\s*=\s*"([^"]+)"', match.group(1), re.M)
    assert entry, "no avm-mesh console script"

    target = entry.group(1)
    module_name, _, func_name = target.partition(":")
    module = __import__(module_name, fromlist=[func_name])
    assert callable(getattr(module, func_name)), f"{target} is not callable"


def test_every_command_the_readme_documents_exists_on_the_script():
    """The README tells users to run `avm-mesh <cmd>`; those subcommands must parse."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"(?m)^avm-mesh\s+([a-z][a-z-]*)", readme))
    assert documented, "README no longer documents any avm-mesh command"

    from avm_mesh import cli

    parser = cli._build_parser()
    choices = set()
    for action in parser._actions:
        if action.dest == "cmd":
            choices = set(action.choices or {})
    missing = documented - choices
    assert not missing, f"README documents commands the CLI rejects: {sorted(missing)}"


# --- licence and metadata: the estate standard, enforced not remembered ------
# Memory-graph claims 11229 (licence files normalised estate-wide, PEP 639 SPDX)
# and 4594 (Apache-2.0 LICENSE + NOTICE in both artifacts). 0.5.0 shipped without
# either file while declaring the licence, which is why these exist.

def test_licence_files_exist_and_are_real():
    for name in ("LICENSE", "NOTICE"):
        path = ROOT / name
        assert path.exists(), f"{name} missing: the package would declare a licence it does not ship"
        body = path.read_text(encoding="utf-8")
        assert len(body) > 200, f"{name} looks like a placeholder"
    licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in licence and "Version 2.0" in licence


def test_pyproject_uses_pep639_metadata():
    body = _pyproject()
    assert 'license = "Apache-2.0"' in body, "license must be an SPDX string, not a {text=...} table"
    assert "license-files" in body, "license-files must be declared so the files travel in the artifacts"
    for name in ("LICENSE", "NOTICE"):
        assert name in body.split("license-files")[1].split("\n")[0], f"{name} not listed in license-files"


def test_no_classifier_contradicts_the_licence_expression():
    body = _pyproject()
    offending = [line.strip() for line in body.splitlines()
                 if line.strip().startswith('"License ::')]
    assert not offending, f"PEP 639 forbids licence classifiers alongside a licence expression: {offending}"


def test_build_requires_a_setuptools_that_understands_pep639():
    body = _pyproject()
    match = re.search(r"requires\s*=\s*\[([^\]]*)\]", body)
    assert match, "no build-system requires"
    pins = [part.strip().strip('"') for part in match.group(1).split(",") if part.strip()]
    setuptools_pin = next((p for p in pins if p.startswith("setuptools")), None)
    assert setuptools_pin, f"setuptools not pinned: {pins}"
    minimum = int(re.search(r">=\s*(\d+)", setuptools_pin).group(1))
    assert minimum >= 77, f"setuptools>={minimum} predates PEP 639 support (needs >=77)"
