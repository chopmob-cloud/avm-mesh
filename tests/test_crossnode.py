"""A single lying operator is caught. The property that makes corroboration worth having.

A mechanism that only ever reports agreement is theatre. These tests build a local server
that answers like a real algod, then vary what it says, so the disagreement path is
exercised without depending on a hostile node existing in the wild.

What is deliberately NOT allowed: quorum by majority. Two operators agreeing on a fiction
and one telling the truth must FAIL, not carry a vote, because a vote is exactly what a
coordinated pair can win. Requirement is unanimity on the compared fields, and the tests
below pin that by giving the liar a majority.
"""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from avm_mesh.crossnode import CorroborationError, corroborate_round

REAL_VOTERS = base64.b64encode(bytes(range(64))).decode()
REAL_HEADERS = base64.b64encode(bytes(range(32))).decode()


def _payload(*, voters=REAL_VOTERS, headers=REAL_HEADERS, ln=2230417, proof="AAAA",
             last=66647808):
    """The JSON an algod returns for one interval. Built once so every fake serves the
    same shape; a fixture that hand-writes this per test is where the first version of
    this file went wrong, embedding a header tuple in the body."""
    return json.dumps({
        "Message": {
            "BlockHeadersCommitment": headers,
            "FirstAttestedRound": last - 255,
            "LastAttestedRound": last,
            "LnProvenWeight": ln,
            "VotersCommitment": voters,
        },
        "StateProof": proof,
    }).encode()


class _Handler(BaseHTTPRequestHandler):
    """A fake algod that serves whatever the test tells it to."""

    # NOT `headers`: BaseHTTPRequestHandler.headers is the incoming request's headers,
    # and a class attribute of that name is silently shadowed by it. That shadowing is
    # what broke the first version of this fixture.
    voters = REAL_VOTERS
    headers_commitment = REAL_HEADERS
    ln = 2230417
    proof = "AAAA"
    status = 200

    def do_GET(self):  # noqa: N802 - http.server API
        if self.status != 200:
            self.send_response(self.status)
            self.end_headers()
            self.wfile.write(b'{"message":"no"}')
            return
        body = _payload(voters=self.voters, headers=self.headers_commitment, ln=self.ln,
                        proof=self.proof)
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the test output
        pass


@pytest.fixture
def fake_algod():
    servers = []

    def make(**overrides):
        handler = type("H", (_Handler,), overrides)
        server = HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


def test_two_operators_serving_the_same_interval_agree(fake_algod):
    a = fake_algod()
    b = fake_algod()
    result = corroborate_round(66647808, operators=[("a", a), ("b", b)])
    assert result.agreed, result.failure
    assert result.agreement["voters_commitment"]["agreed"] is True


def test_one_liar_with_the_numbers_against_it_still_fails(fake_algod):
    """Two liars and one honest operator: a majority vote would let the fiction through.

    This is the whole point of refusing to vote. The check requires unanimity, so a
    coordinated pair cannot outnumber the truth.
    """
    lie = base64.b64encode(bytes(range(64, 128))).decode()
    honest = fake_algod()
    liar_a = fake_algod(voters=lie)
    liar_b = fake_algod(voters=lie)

    result = corroborate_round(
        66647808,
        operators=[("honest", honest), ("liar-a", liar_a), ("liar-b", liar_b)])

    assert result.agreed is False, "a coordinated majority carried a fiction"
    assert "disagree on voters_commitment" in (result.failure or "")


def test_a_liar_alone_against_one_honest_operator_fails(fake_algod):
    honest = fake_algod()
    liar = fake_algod(voters=base64.b64encode(b"\xff" * 64).decode())
    result = corroborate_round(66647808, operators=[("honest", honest), ("liar", liar)])
    assert result.agreed is False
    assert "voters_commitment" in (result.failure or "")


def test_disagreement_on_proven_weight_fails(fake_algod):
    a = fake_algod()
    b = fake_algod(ln=2230418)
    result = corroborate_round(66647808, operators=[("a", a), ("b", b)])
    assert result.agreed is False
    assert "ln_proven_weight" in (result.failure or "")


def test_disagreement_on_block_headers_fails(fake_algod):
    a = fake_algod()
    b = fake_algod(headers_commitment=base64.b64encode(b"\x01" * 32).decode())
    result = corroborate_round(66647808, operators=[("a", a), ("b", b)])
    assert result.agreed is False
    assert "block_headers_commitment" in (result.failure or "")


def test_two_different_state_proofs_for_one_interval_fail(fake_algod):
    """No consensus rule allows two proofs of the same interval; treat it as refusal."""
    a = fake_algod(proof="AAAA")
    b = fake_algod(proof="BBBB")
    result = corroborate_round(66647808, operators=[("a", a), ("b", b)])
    assert result.agreed is False
    assert "different state proofs" in (result.failure or "")


def test_one_operator_down_is_not_agreement(fake_algod):
    """The failure mode that would make the mechanism theatre."""
    a = fake_algod()
    result = corroborate_round(66647808, operators=[("a", a), ("down", "http://127.0.0.1:1")])
    assert result.agreed is False
    assert "only 1 of 2" in (result.failure or "")
    assert "one operator agreeing with itself" in (result.failure or "")


def test_an_operator_answering_for_the_wrong_round_is_refused(fake_algod):
    class Wrong(_Handler):
        def do_GET(self):  # noqa: N802
            body = _payload(last=66648064)   # not the round asked for
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Wrong)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    wrong = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        honest = fake_algod()
        result = corroborate_round(66647808, operators=[("honest", honest), ("wrong", wrong)])
        assert result.agreed is False
        assert "answered for round" in (result.failure or "")
    finally:
        server.shutdown()
        server.server_close()


def test_an_error_response_is_an_unanswered_operator(fake_algod):
    a = fake_algod()
    b = fake_algod(status=500)
    result = corroborate_round(66647808, operators=[("a", a), ("b", b)])
    assert result.agreed is False
    assert "only 1 of 2" in (result.failure or "")


def test_the_report_states_what_independence_does_not_mean(fake_algod):
    """A reader must not take 'agreed' as 'these are separate companies'."""
    a = fake_algod()
    b = fake_algod()
    result = corroborate_round(66647808, operators=[("a", a), ("b", b)])
    report = result.to_dict()
    assert report["agreed"] is True
    assert "not proof of independent ownership" in report["independence"]
    assert "a mismatch is a refusal, not a vote" in report["trust_basis"]


# ----------------------------------------------------------------- guard rails


def test_a_round_that_is_not_an_interval_boundary_is_refused():
    with pytest.raises(CorroborationError, match="not an interval boundary"):
        corroborate_round(66647809)


def test_min_operators_below_two_is_refused():
    with pytest.raises(CorroborationError, match="at least 2"):
        corroborate_round(66647808, min_operators=1)


def test_fewer_configured_operators_than_required_is_refused():
    with pytest.raises(CorroborationError, match="configured but 2 required"):
        corroborate_round(66647808, operators=[("only", "http://127.0.0.1:1")])


def test_a_non_integer_round_is_refused():
    with pytest.raises(CorroborationError, match="positive integer"):
        corroborate_round("66647808")

def test_a_pruned_interval_is_named_as_pruned_not_as_a_failure(fake_algod):
    """The fact and the remedy differ, so the message must differ.

    Measured against the live network: public Algorand endpoints retain only three to four
    state-proof intervals. An old capture therefore cannot be corroborated after the fact
    by anyone, no matter how many operators you ask, and a message that says "only 0 of 2
    answered" invites exactly the retry that cannot work.
    """
    class Pruned(_Handler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({
                "message": "ledger does not have entry 66606848 (latest 66648454, "
                           "committed 66648454)"
            }).encode()
            self.send_response(500)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    servers = []
    for _ in range(2):
        server = HTTPServer(("127.0.0.1", 0), Pruned)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    try:
        ops = [(f"op{i}", f"http://127.0.0.1:{s.server_address[1]}")
               for i, s in enumerate(servers)]
        result = corroborate_round(66606848, operators=ops)
        assert result.agreed is False
        assert "every operator has pruned round 66606848" in (result.failure or "")
        assert "capture is made rather than afterwards" in (result.failure or "")
        assert all(r.error.startswith("pruned") for r in result.responders)
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()

def test_an_operator_that_answers_without_a_proof_does_not_agree(fake_algod):
    """The reviewer's finding, reproduced before it was fixed.

    The agreement set was built with `if r.state_proof_sha256`, which dropped the absent
    case, so {digest, None} reduced to one value and counted as agreement. An operator
    returning a message and no proof was therefore corroborating. That is precisely the
    "answered without answering" case this module exists to refuse.
    """
    with_proof = fake_algod()

    class NoProof(_Handler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({
                "Message": {
                    "BlockHeadersCommitment": REAL_HEADERS,
                    "FirstAttestedRound": 66647553,
                    "LastAttestedRound": 66647808,
                    "LnProvenWeight": 2230417,
                    "VotersCommitment": REAL_VOTERS,
                }
                # no StateProof key at all
            }).encode()
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), NoProof)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        no_proof = f"http://127.0.0.1:{server.server_address[1]}"
        result = corroborate_round(66647808,
                                   operators=[("with", with_proof), ("without", no_proof)])
        assert result.agreed is False, "an operator with no proof was counted as agreeing"
        assert "without a state proof" in (result.failure or "")
        assert result.agreement["state_proof_sha256"]["agreed"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_a_non_ascii_state_proof_is_refused_rather_than_mangled(fake_algod):
    """`encode("ascii", "replace")` silently substituted the offending bytes.

    A proof must be base64, so a non-ASCII body is malformed. Mangling it produced a
    digest of something that was never served, which would then "agree" with nothing.
    """
    good = fake_algod()
    bad = fake_algod(proof="\u00ff not base64")
    result = corroborate_round(66647808, operators=[("good", good), ("bad", bad)])
    assert result.agreed is False
    responses = {r.name: r for r in result.responders}
    assert responses["bad"].ok is False
    assert "ASCII base64" in (responses["bad"].error or "")
    assert "only 1 of 2" in (result.failure or "")
