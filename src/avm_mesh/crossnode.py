"""Independent corroboration of an anchor: agreement across unrelated node operators.

The problem this solves. `anchor.walk` verifies every interval between a pinned
checkpoint and a target, but every capture can come from one endpoint. A single operator
serving a consistent fiction produces a walk that verifies perfectly. Until now the
project said so in a caveat and had no way to answer it.

This module answers it the only way it can be answered: fetch the same attested interval
from several operators that do not share an infrastructure provider, and require their
independent responses to agree on the fields the state proof is verified against — the
voters commitment, the proven weight, and the block headers commitment. Disagreement is a
refusal, not a vote: two nodes outvoting one honest node is not evidence, so any mismatch
fails the whole check.

What agreement proves: the interval's provenance is not one operator's private view, and
a single node cannot substitute a different signing set without being caught by the
others.

What it does not prove: that the operators are genuinely independent (a shared upstream,
a shared hosting provider, or an operator running two domains defeats it), or that a
majority of them are honest. `independence` in the report is a claim about *domains
contacted*, not about ownership, and the module says so rather than implying more.

Stdlib only, no third-party dependency, matching the rest of the core.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterable

from .receipt import MeshError

#: Fields the state proof is verified against. If these agree, the operators agree about
#: what the chain's signing set was at that round. `state_proof_bytes` is compared too
#: where present, because two nodes serving different proofs of the same interval is a
#: contradiction no consensus rule allows.
AGREEMENT_FIELDS = ("voters_commitment", "ln_proven_weight", "block_headers_commitment")

#: Operators believed to be organisationally distinct. Advertised list, not a guarantee:
#: see `independence` in the report.
DEFAULT_OPERATORS = (
    ("algonode", "https://mainnet-api.algonode.cloud"),
    ("nodely", "https://mainnet-api.4160.nodely.dev"),
)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_S = 25.0


class CorroborationError(MeshError):
    """The interval could not be corroborated. A subclass of MeshError on purpose: a
    caller that already handles verification refusal should not need a second except."""


@dataclass
class OperatorResponse:
    """One operator's answer for one interval."""

    name: str
    endpoint: str
    ok: bool
    last_attested_round: int | None = None
    voters_commitment: str | None = None
    ln_proven_weight: int | None = None
    block_headers_commitment: str | None = None
    state_proof_sha256: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "endpoint": self.endpoint,
            "ok": self.ok,
            "last_attested_round": self.last_attested_round,
            "voters_commitment": self.voters_commitment,
            "ln_proven_weight": self.ln_proven_weight,
            "block_headers_commitment": self.block_headers_commitment,
            "state_proof_sha256": self.state_proof_sha256,
            "error": self.error,
        }


@dataclass
class Corroboration:
    """The outcome of asking several operators about one interval."""

    round: int
    agreed: bool
    responders: list[OperatorResponse] = field(default_factory=list)
    agreement: dict[str, Any] = field(default_factory=dict)
    failure: str | None = None
    independence: str = (
        "agreement across distinct endpoints, not proof of independent ownership; "
        "a shared upstream or hosting provider defeats this"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "agreed": self.agreed,
            "operators_contacted": len(self.responders),
            "operators_answered": sum(1 for r in self.responders if r.ok),
            "agreement": self.agreement,
            "failure": self.failure,
            "independence": self.independence,
            "trust_basis": (
                "fields compared across endpoints; a mismatch is a refusal, not a vote"
            ),
            "responses": [r.to_dict() for r in self.responders],
        }


def _fetch_stateproof(endpoint: str, round_number: int, *,
                      timeout: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    url = f"{endpoint.rstrip('/')}/v2/stateproofs/{round_number}"
    request = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CorroborationError(f"{url} returned more than {MAX_RESPONSE_BYTES} bytes")
    return json.loads(raw)


def _response(name: str, endpoint: str, round_number: int, *,
              timeout: float = DEFAULT_TIMEOUT_S) -> OperatorResponse:
    try:
        body = _fetch_stateproof(endpoint, round_number, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # A pruned interval is a different fact from a broken operator, and the remedy
        # differs: nothing will make an old interval available on a node that has
        # discarded it, so say so instead of reporting a generic failure that invites a
        # pointless retry. Public Algorand endpoints keep only the last few intervals --
        # measured at three to four -- which means corroboration has to happen when a
        # capture is taken, not afterwards.
        try:
            detail = exc.read(512).decode("utf-8", "replace")
        except Exception:
            detail = ""
        if "does not have entry" in detail or "not found" in detail.lower():
            return OperatorResponse(
                name=name, endpoint=endpoint, ok=False,
                error=("pruned: this node no longer retains the state proof for that "
                       "interval, so it cannot corroborate it after the fact; "
                       "corroborate at capture time"))
        return OperatorResponse(name=name, endpoint=endpoint, ok=False,
                                error=f"HTTP {exc.code}")
    except urllib.error.URLError as exc:
        return OperatorResponse(name=name, endpoint=endpoint, ok=False,
                                error=f"unreachable: {exc.reason}")
    except (OSError, ValueError, CorroborationError) as exc:
        return OperatorResponse(name=name, endpoint=endpoint, ok=False,
                                error=f"{type(exc).__name__}: {exc}")

    message = body.get("Message")
    if not isinstance(message, dict):
        return OperatorResponse(name=name, endpoint=endpoint, ok=False,
                                error="response has no Message object")
    try:
        last = int(message["LastAttestedRound"])
        voters = message["VotersCommitment"]
        ln = int(message["LnProvenWeight"])
        headers = message["BlockHeadersCommitment"]
    except (KeyError, TypeError, ValueError) as exc:
        return OperatorResponse(name=name, endpoint=endpoint, ok=False,
                                error=f"malformed Message: {exc}")

    if last != round_number:
        return OperatorResponse(name=name, endpoint=endpoint, ok=False,
                                last_attested_round=last,
                                error=f"answered for round {last}, asked for {round_number}")

    import hashlib
    proof = body.get("StateProof")
    digest = None
    if isinstance(proof, str) and proof:
        digest = hashlib.sha256(proof.encode("ascii", "replace")).hexdigest()

    return OperatorResponse(
        name=name, endpoint=endpoint, ok=True, last_attested_round=last,
        voters_commitment=voters, ln_proven_weight=ln,
        block_headers_commitment=headers, state_proof_sha256=digest,
    )


def corroborate_round(round_number: int, *,
                      operators: Iterable[tuple[str, str]] | None = None,
                      min_operators: int = 2,
                      timeout: float = DEFAULT_TIMEOUT_S) -> Corroboration:
    """Ask several operators about one attested interval and require agreement.

    ``min_operators`` is the number that must ANSWER, not the number configured. Two
    operators configured and one down is not corroboration, so this refuses rather than
    reporting agreement with itself — the failure mode that would make the whole
    mechanism theatre.
    """
    if type(round_number) is not int or round_number <= 0:
        raise CorroborationError("round must be a positive integer")
    if round_number % 256:
        raise CorroborationError(
            f"round {round_number} is not an interval boundary; state proofs cover "
            "intervals of 256 rounds")
    if type(min_operators) is not int or min_operators < 2:
        raise CorroborationError(
            "min_operators must be at least 2: one operator agreeing with itself is not "
            "corroboration")

    chosen = list(operators if operators is not None else DEFAULT_OPERATORS)
    if len(chosen) < min_operators:
        raise CorroborationError(
            f"{len(chosen)} operator(s) configured but {min_operators} required")

    responses = [_response(name, url, round_number, timeout=timeout)
                 for name, url in chosen]
    answered = [r for r in responses if r.ok]

    result = Corroboration(round=round_number, agreed=False, responders=responses)

    if len(answered) < min_operators:
        pruned = [r for r in responses if r.error and r.error.startswith("pruned")]
        if pruned and len(pruned) == len(responses):
            result.failure = (
                f"every operator has pruned round {round_number}: public endpoints retain "
                "only the most recent intervals, so corroboration must be taken when the "
                "capture is made rather than afterwards")
            return result
        result.failure = (
            f"only {len(answered)} of {len(chosen)} operators answered for round "
            f"{round_number}; {min_operators} required, and one operator agreeing with "
            "itself is not corroboration")
        return result

    # Any disagreement fails the whole check. A majority vote is the wrong shape here:
    # two nodes agreeing on a fiction and one telling the truth would carry a vote.
    for field_name in AGREEMENT_FIELDS:
        values = {getattr(r, field_name) for r in answered}
        result.agreement[field_name] = {
            "agreed": len(values) == 1,
            "values": {r.name: getattr(r, field_name) for r in answered},
        }
        if len(values) != 1:
            result.failure = (
                f"operators disagree on {field_name}: "
                + ", ".join(f"{r.name}={getattr(r, field_name)!r}" for r in answered))
            return result

    # The state proof itself, where every operator served one.
    proofs = {r.state_proof_sha256 for r in answered if r.state_proof_sha256}
    result.agreement["state_proof_sha256"] = {
        "agreed": len(proofs) <= 1,
        "values": {r.name: r.state_proof_sha256 for r in answered},
    }
    if len(proofs) > 1:
        result.failure = "operators served different state proofs for the same interval"
        return result

    result.agreed = True
    return result


def corroborate_captures(capture_dir, *, operators=None, min_operators: int = 2,
                         timeout: float = DEFAULT_TIMEOUT_S) -> list[Corroboration]:
    """Corroborate every interval present in a capture directory.

    Reads the round from each filename, which the walk already requires to be the round
    the proof attests, so a directory that walks is a directory that can be corroborated.
    """
    import pathlib

    root = pathlib.Path(capture_dir)
    if not root.exists():
        raise CorroborationError(f"capture directory does not exist: {root}")

    rounds: list[int] = []
    for path in sorted(root.iterdir()):
        name = path.name
        stem = name[:-8] if name.endswith(".json.gz") else path.stem
        if stem.isascii() and stem.isdigit():
            rounds.append(int(stem))
    if not rounds:
        raise CorroborationError(f"no round-named captures in {root}")

    return [corroborate_round(r, operators=operators, min_operators=min_operators,
                              timeout=timeout) for r in rounds]
