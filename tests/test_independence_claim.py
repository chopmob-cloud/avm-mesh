"""The independence claim is never inferred from silence.

These tests exist because 0.13.4 shipped a false corroboration claim that the suite did not
catch. Three separate gaps, each found by an independent review and each reproduced against
live endpoints before being fixed:

1. ``corroborated`` was ``agreed and not same_operator``. A pair that sent no fingerprint
   header produced no conflict, so silence read as independence — and Voi's two public
   hostnames, which this repository's own documentation calls ONE operator, came back
   ``corroborated: true``. The check was only catching operators careless enough to
   identify themselves.
2. ``--allow-same-operator`` set ``agreed = True`` and left ``same_operator`` False, so
   ``to_dict()['corroborated']`` was True. Four shipped documents said the flag "never
   reports corroboration"; the CLI printed "verdict: corroborated by distinct endpoints"
   and exited 0.
3. ``tools/fetch_corroborated_walk.py`` — the tool that writes the published evidence
   bundle — discarded response headers entirely and had no sameness check at all, while a
   comment in it claimed the pair "is checked for sameness before anything is captured".

Each test below fails against 0.13.4 and passes now. That direction matters: a test that
passes both before and after would not have caught the defect it is named for.
"""
import importlib.util
import pathlib
import sys

import pytest

from avm_mesh import crossnode
from avm_mesh.crossnode import (
    INDEPENDENCE_ASSERTED,
    INDEPENDENCE_EVIDENCED,
    INDEPENDENCE_SAME,
    INDEPENDENCE_UNKNOWN,
    INDEPENDENCE_WAIVED,
    corroborate_round,
)

TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"

#: The fake-algod fixtures are defined in `test_crossnode.py` rather than in `conftest.py`.
#: pytest only shares fixtures declared in a conftest, so importing them here is both the
#: smallest change and the one that keeps a single definition of the fake node — two
#: independently-built fakes would be two different things to keep in step.
from test_crossnode import fake_algod, stamped_algod  # noqa: E402,F401


def _load_tool(name: str):
    """Import a tools/ script, which is an executable rather than a module."""
    spec = importlib.util.spec_from_file_location(f"_tool_{name}", TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_silence_is_not_independence(fake_algod):
    """Finding 1: no headers on either side must NOT read as verified independence.

    This is the Voi shape exactly: two hostnames of one provider, neither sending a stamp.
    0.13.4 answered ``agreed=True, corroborated=True``, which is the claim this release
    exists to make impossible.
    """
    result = corroborate_round(66647808, operators=[("a", fake_algod()),
                                                    ("b", fake_algod())])
    assert result.agreed is True, "the fields genuinely agreed; that part is real"
    assert result.independence_state == INDEPENDENCE_UNKNOWN
    assert result.corroborated is False, (
        "two unstamped endpoints were called corroborated: corroboration was inferred "
        "from the ABSENCE of a measurement")
    assert result.to_dict()["corroborated"] is False
    assert "no evidence either way" in (result.failure or "")
    assert "unknown" in result.to_dict()["independence_state"]


def test_waiving_the_witness_never_reports_corroboration(fake_algod):
    """Finding 2: --allow-same-operator is for re-analysis, not for claiming agreement.

    Four documents promise this flag never claims corroboration. In 0.13.4 the JSON said
    ``corroborated: true`` and the CLI exited 0 with "corroborated by distinct endpoints".
    """
    result = corroborate_round(66647808,
                               operators=[("a", fake_algod()), ("b", fake_algod())],
                               require_witness=False)
    assert result.agreed is True, "agreement comparison still happens in this mode"
    assert result.independence_state == INDEPENDENCE_WAIVED
    assert result.corroborated is False
    assert result.to_dict()["corroborated"] is False, (
        "a machine consumer reading this field was told one provider under two names had "
        "been corroborated")
    assert "not corroboration" in result.to_dict()["independence"]


def test_a_self_run_node_may_be_declared_and_is_recorded_as_an_assertion(fake_algod):
    """The documented ask is "run one of the endpoints yourself". That is knowledge the
    check cannot obtain, so it must be recorded as the caller's assertion — never dressed
    up as measured evidence."""
    result = corroborate_round(66647808,
                               operators=[("mine", fake_algod()), ("theirs", fake_algod())],
                               declared_independent=True)
    assert result.independence_state == INDEPENDENCE_ASSERTED
    assert result.corroborated is True
    assert "assertion" in result.independence
    assert "not on a measurement" in result.independence


def test_a_stamped_pair_with_no_collision_is_evidenced(stamped_algod):
    """The positive path still works: both identify themselves, neither collides."""
    result = corroborate_round(66647808,
                               operators=[("a", stamped_algod(stamp="de1@de_central")),
                                          ("b", stamped_algod(stamp="us1@us_east"))])
    assert result.independence_state == INDEPENDENCE_EVIDENCED
    assert result.corroborated is True


def test_the_same_operator_is_still_positively_caught(stamped_algod):
    """The case that was correctly handled in 0.13.4 must stay handled."""
    result = corroborate_round(66647808,
                               operators=[("a", stamped_algod(stamp="de1@de_central")),
                                          ("b", stamped_algod(stamp="de2@de_central"))])
    assert result.independence_state == INDEPENDENCE_SAME
    assert result.same_operator is True
    assert result.corroborated is False


@pytest.mark.parametrize("left,right", [
    ("https://api.example.com", "https://API.example.com/"),
    ("https://api.example.com", "https://api.example.com:443"),
    ("https://api.example.com", "http://api.example.com:80"),
    ("http://127.0.0.1:8080", "http://localhost:8080"),
])
def test_one_server_named_twice_normalises_to_one_identity(left, right):
    """Endpoint identity is not string identity. Before this, the same server written any
    of these four ways counted as two operators."""
    assert crossnode._endpoint_identity(left) == crossnode._endpoint_identity(right)


def test_duplicate_detection_fires_on_a_really_reachable_duplicate(fake_algod):
    """The normalisation above is worthless unless the refusal uses it, so this drives the
    real code path against one live server named two ways."""
    url = fake_algod()
    spelled = url.replace("127.0.0.1", "localhost")
    assert spelled != url, "precondition: the two spellings differ as strings"
    result = corroborate_round(66647808, operators=[("one", url), ("also-one", spelled)])
    assert result.independence_state == INDEPENDENCE_SAME
    assert result.corroborated is False


def test_a_different_port_really_is_a_different_service():
    """The normalisation must not go so far that it invents collisions."""
    assert (crossnode._endpoint_identity("http://api.example.com:8080")
            != crossnode._endpoint_identity("http://api.example.com:9090"))


def test_the_capture_tool_declares_the_same_constants():
    """Finding 3's root cause: the tool kept its own copy of the rule and the copy drifted.

    The values are asserted equal so the two cannot diverge silently again.
    """
    tool = _load_tool("fetch_corroborated_walk")
    assert tuple(tool.FINGERPRINT_HEADERS) == tuple(crossnode.FINGERPRINT_HEADERS)
    assert tool.INDEPENDENCE_EVIDENCED == crossnode.INDEPENDENCE_EVIDENCED
    assert tool.INDEPENDENCE_UNKNOWN == crossnode.INDEPENDENCE_UNKNOWN
    assert tool.INDEPENDENCE_SAME == crossnode.INDEPENDENCE_SAME


def test_the_capture_tool_refuses_a_same_operator_pair():
    """Finding 3, driven through the tool's own refusal function.

    The tool claimed in a comment to check sameness before capture and did not. This calls
    the extracted check rather than grepping for a string, so deleting the guard fails the
    test instead of leaving it green.
    """
    tool = _load_tool("fetch_corroborated_walk")

    one_provider = {
        "nodely": {"x-and-nl": "de1@de_central"},
        "algonode": {"x-and-nl": "de2@de_central"},
    }
    refusal = tool._same_operator_pair(one_provider)
    assert refusal is not None, (
        "two hostnames of one datacentre must be refused; the tool reported agreement")
    assert "one provider under two names" in refusal

    distinct = {
        "a": {"x-and-nl": "de1@de_central"},
        "b": {"x-and-nl": "us1@us_east"},
    }
    assert tool._same_operator_pair(distinct) is None, (
        "genuinely separate datacentres must be allowed")

    assert tool._same_operator_pair({}) is None
    assert tool._same_operator_pair({"a": {}, "b": {}}) is None, (
        "no stamps is 'unknown', not 'same operator' — the caller decides what to do")


def test_the_capture_tool_reads_headers_at_all():
    """The mechanical cause: `_get` discarded headers, so no check could have existed."""
    tool = _load_tool("fetch_corroborated_walk")
    assert hasattr(tool, "_get_with_fingerprint"), (
        "the capture tool has no way to obtain a fingerprint header, so it cannot check "
        "sameness at all")


def test_the_capture_tool_gates_agreement_on_evidence():
    """`cross_operator_agreement` must not be a synonym for 'the fields matched'."""
    source = (TOOLS / "fetch_corroborated_walk.py").read_text(encoding="utf-8")
    assert "cross_operator_agreement\": bool(all_agreed" in source and (
        "independence_state == INDEPENDENCE_EVIDENCED" in source), (
        "the agreement flag must be gated on independence evidence, not on agreement alone")


def test_agreement_alone_is_not_enough_to_exit_zero():
    """The CLI's exit code is the machine-readable verdict. It must follow `corroborated`,
    not `agreed`, or a script sees success for an unverified pair."""
    source = (pathlib.Path(__file__).resolve().parent.parent
              / "src" / "avm_mesh" / "cli.py").read_text(encoding="utf-8")
    assert "return 0 if all(r.corroborated for r in results) else 2" in source, (
        "the CLI must exit 0 only when corroboration was actually established")
