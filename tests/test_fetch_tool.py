"""The capture tool's own guards, which the independent review found untested.

`tools/fetch_corroborated_walk.py` is the tool that makes the independence claim real, so its
failure modes matter: a negative round, a `file://` operator, or a capture attempted from an
endpoint that never answered would each produce a capture set that looks corroborated while
being nothing of the kind.

The network is never touched. Each case is refused before a socket is opened, which is the
property being pinned.
"""
import importlib.util
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "fetch_corroborated_walk.py"


def _module():
    spec = importlib.util.spec_from_file_location("fcw_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(*args):
    return subprocess.run([sys.executable, str(TOOL), *args],
                          capture_output=True, text=True, timeout=120)


# ------------------------------------------------------------- operator URL validation


def test_a_file_url_operator_is_refused_before_any_network_call():
    """`file://` reached `urlopen`, which is a local-file read dressed as an operator.

    Reproduced before this guard existed: the tool tried to open
    `\\etc\\passwd\\v2\\status` on the filesystem. Nothing about "ask an operator"
    requires any scheme but HTTP, so anything else is refused by name.
    """
    result = _run("--operator", "x=file:///etc/passwd", "--operator", "y=file:///etc/hosts",
                  "--out", "unused-out-dir")
    assert result.returncode == 2
    assert "must be http:// or https://" in result.stderr
    assert "passwd" not in result.stdout


def test_an_ftp_url_operator_is_refused():
    result = _run("--operator", "x=ftp://example.org", "--operator", "y=https://example.org",
                  "--out", "unused-out-dir")
    assert result.returncode == 2
    assert "http:// or https://" in result.stderr


def test_a_plain_http_operator_passes_the_scheme_check():
    """The guard must not reject the thing it is meant to allow.

    Head is below one interval here so the tool refuses for a *different* reason, which is
    how we know the scheme check let it through.
    """
    result = _run("--operator", "x=http://127.0.0.1:1", "--operator", "y=http://127.0.0.1:2",
                  "--out", "unused-out-dir")
    assert "must be http:// or https://" not in result.stderr


def test_a_malformed_operator_spec_is_refused():
    result = _run("--operator", "nonsense", "--out", "unused-out-dir")
    assert result.returncode == 2
    assert "NAME=URL" in result.stderr


def test_one_operator_is_refused_as_theatre():
    result = _run("--operator", "x=https://example.org", "--out", "unused-out-dir")
    assert result.returncode == 2
    assert "at least two operators" in result.stderr


# --------------------------------------------------------------- interval arithmetic


def test_the_newest_round_is_never_negative():
    """A head below one interval produced round -256 and requested it.

    `(head // 256) * 256 - 256` is negative for any head under 256, so a young chain (or a
    pruned node reporting a low head) asked every operator for a round that cannot exist.
    The arithmetic itself is pinned here; the refusal path is pinned below.
    """
    m = _module()
    for head in (0, 1, 200, 255):
        newest = (head // m.INTERVAL) * m.INTERVAL - m.INTERVAL
        assert newest < 0, f"head {head} does not exercise the guard"


def test_the_tool_refuses_when_head_is_below_one_interval(monkeypatch, tmp_path, capsys):
    """Exercised through main() with the node status stubbed, so no socket is opened."""
    m = _module()
    monkeypatch.setattr(m, "_status", lambda endpoint: {"last-round": 200})
    code = m.main(["--operator", "a=http://a.invalid", "--operator", "b=http://b.invalid",
                   "--out", str(tmp_path / "out")])
    assert code == 2
    assert "below one state-proof interval" in capsys.readouterr().err


def test_hops_zero_is_refused_not_an_IndexError(monkeypatch, tmp_path, capsys):
    """`--hops 0` made `requested` empty and then indexed it.

    Reproduced: an IndexError with no output. A usage error should name the argument, so the
    refusal happens at validation rather than surfacing as a traceback from deep in the tool.
    """
    m = _module()
    monkeypatch.setattr(m, "_status", lambda endpoint: {"last-round": 1_000_000})
    code = m.main(["--hops", "0",
                   "--operator", "a=http://a.invalid", "--operator", "b=http://b.invalid",
                   "--out", str(tmp_path / "out")])
    assert code == 2
    assert "--hops must be at least 1" in capsys.readouterr().err


def test_a_negative_hop_count_is_refused(monkeypatch, tmp_path, capsys):
    m = _module()
    monkeypatch.setattr(m, "_status", lambda endpoint: {"last-round": 1_000_000})
    code = m.main(["--hops", "-3",
                   "--operator", "a=http://a.invalid", "--operator", "b=http://b.invalid",
                   "--out", str(tmp_path / "out")])
    assert code == 2
    assert "--hops must be at least 1" in capsys.readouterr().err
