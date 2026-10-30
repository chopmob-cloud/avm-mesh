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
