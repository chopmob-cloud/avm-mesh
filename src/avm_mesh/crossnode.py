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
#:
#: EMPTY ON PURPOSE. The previous default was
#: ``(("algonode", "https://mainnet-api.algonode.cloud"),
#:    ("nodely", "https://mainnet-api.4160.nodely.dev"))``
#: and those are one operator. Nodely's own documentation states that the old
#: ``algonode.cloud`` hosts are "same rules, same infra as nodely.dev"; measured, both
#: return byte-identical state proofs and the same ``x-and-nl`` datacentre header. A
#: default that presents one provider twice as corroboration is worse than no default,
#: because a reader takes "2 operators agree" at face value. Callers now have to name
#: the operators they trust, and the check refuses two endpoints that behave alike.
DEFAULT_OPERATORS: tuple[tuple[str, str], ...] = ()

#: Headers that identify a provider rather than a server. Deliberately NARROW: only
#: stable, operator-specific values belong here. ``server`` and ``via`` are excluded
#: because two genuinely independent operators running nginx would otherwise be reported
#: as one business, and ``x-request-id``/``cf-ray`` are unique per request so they can
#: never match.
#:
#: ``x-and-dl`` is EXCLUDED, and that was a defect corrected here. It reads ``0.05`` on
#: every response from both Nodely hostnames, which looks like a provider stamp and is
#: not: it is a rate value, the same on two genuinely independent operators that happen to
#: share a rate. Testing the false-positive path — two different datacentres, both sending
#: it — refused them as one business. A check that fires on unrelated operators is worse
#: than one that misses a related pair, because it makes real corroboration impossible.
#:
#: Only ``x-and-nl`` remains, and only its datacentre half is compared; see
#: ``_operator_identity``.
FINGERPRINT_HEADERS = ("x-and-nl",)

#: The part of a header value that identifies the OPERATOR, as opposed to the machine
#: that answered this particular request.
#:
#: ``x-and-nl`` is ``<node>@<datacentre>``, and the node label is load-balanced: repeated
#: requests to one endpoint return ``de1@de_central`` and ``de2@de_central`` in a 5:7
#: ratio, measured over twelve requests to each of two endpoints. Comparing the raw value
#: therefore compares two coin flips. Two requests to ONE provider disagree about a third
#: of the time, and the pair is then accepted as independent — the precise failure this
#: check exists to prevent.
#:
#: The datacentre is the stable part and the operator is what owns it, so that is what is
#: compared. A value with no ``@`` is used whole, which keeps any other provider's format
#: working without this module having to know about it.
def _endpoint_identity(endpoint: str) -> str:
    """Reduce an endpoint URL to the server it names, for duplicate detection.

    Comparing raw strings misses ``host`` vs ``host:443``, ``http`` vs ``https`` and
    ``localhost`` vs ``127.0.0.1`` — each of which is one server named twice. Scheme and
    the default port are therefore dropped, a trailing slash and case are ignored, and the
    two loopback spellings are unified. A non-default port is kept, because two services
    on one host really are separable.
    """
    raw = endpoint.strip().lower()
    if "//" in raw:
        raw = raw.split("//", 1)[1]
    raw = raw.split("/", 1)[0]
    host, _, port = raw.partition(":")
    if port in ("", "443", "80"):
        port = ""
    if host in ("localhost", "127.0.0.1", "[::1]"):
        host = "loopback"
    return f"{host}:{port}" if port else host


def _operator_identity(header: str, value: str) -> str:
    """Reduce a fingerprint header to the part that names the operator."""
    if header == "x-and-nl" and "@" in value:
        return value.rsplit("@", 1)[1]
    return value


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
    #: Infrastructure fingerprint read from the response headers, used to detect one
    #: provider answering under two hostnames. Not a security value: it is evidence for
    #: the independence check, not something an attacker is prevented from spoofing.
    fingerprint: dict[str, str] = field(default_factory=dict)

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
            "fingerprint": dict(self.fingerprint),
        }


#: How the claim that two answers are independent is supported. This is the field a
#: reader should make their decision on, because "agreed" only says the fields matched.
#:
#: The distinction exists because of a defect: absence of a fingerprint header used to be
#: treated as evidence of independence. It is not evidence of anything. Two hostnames of
#: one provider that send no headers were reported ``corroborated: true``, and that is the
#: exact class of false claim this module exists to prevent — the check was only catching
#: the operators careless enough to identify themselves.
INDEPENDENCE_EVIDENCED = "evidenced"   # every answer stamped, no two stamps collide
INDEPENDENCE_ASSERTED = "asserted"     # caller named the node(s) they run themselves
INDEPENDENCE_UNKNOWN = "unknown"       # nothing to go on: agreed, but unverified
INDEPENDENCE_SAME = "same_operator"    # positive evidence of one provider
INDEPENDENCE_WAIVED = "waived"         # witness check deliberately skipped


@dataclass
class Corroboration:
    """The outcome of asking several operators about one interval."""

    round: int
    agreed: bool
    responders: list[OperatorResponse] = field(default_factory=list)
    agreement: dict[str, Any] = field(default_factory=dict)
    failure: str | None = None
    #: True only on POSITIVE evidence that these are one provider under several hostnames:
    #: a shared fingerprint header, or the same endpoint named twice. Deliberately NOT set
    #: by byte-identical state proofs — those are deterministic in the signing set, so
    #: honest independent nodes are expected to return identical bytes.
    same_operator: bool = False
    #: One of the INDEPENDENCE_* constants. ``agreed`` and this together are what a caller
    #: needs; neither alone answers "may I trust that two parties checked this?".
    independence_state: str = INDEPENDENCE_UNKNOWN
    independence: str = (
        "agreement across distinct endpoints, not proof of independent ownership; "
        "a shared upstream or hosting provider defeats this"
    )

    @property
    def corroborated(self) -> bool:
        """Agreement PLUS support for the independence claim. Never inferred from silence."""
        return bool(
            self.agreed
            and self.independence_state in (INDEPENDENCE_EVIDENCED, INDEPENDENCE_ASSERTED)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "agreed": self.agreed,
            "corroborated": self.corroborated,
            "same_operator_suspected": self.same_operator,
            "independence_state": self.independence_state,
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
                      timeout: float = DEFAULT_TIMEOUT_S) -> tuple[dict[str, Any], dict[str, str]]:
    url = f"{endpoint.rstrip('/')}/v2/stateproofs/{round_number}"
    request = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        headers = {h.lower(): response.headers.get(h, "")
                   for h in FINGERPRINT_HEADERS}
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CorroborationError(f"{url} returned more than {MAX_RESPONSE_BYTES} bytes")
    return json.loads(raw), {k: v for k, v in headers.items() if v}


def _response(name: str, endpoint: str, round_number: int, *,
              timeout: float = DEFAULT_TIMEOUT_S) -> OperatorResponse:
    fingerprint: dict[str, str] = {}
    try:
        body, fingerprint = _fetch_stateproof(endpoint, round_number, timeout=timeout)
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
        try:
            digest = hashlib.sha256(proof.encode("ascii")).hexdigest()
        except UnicodeEncodeError:
            return OperatorResponse(name=name, endpoint=endpoint, ok=False,
                                    error="StateProof is not ASCII base64 as the spec requires")

    return OperatorResponse(
        name=name, endpoint=endpoint, ok=True, last_attested_round=last,
        voters_commitment=voters, ln_proven_weight=ln,
        block_headers_commitment=headers, state_proof_sha256=digest,
        fingerprint=dict(fingerprint),
    )


def _independence_state(answered: list[OperatorResponse]) -> tuple[str, str | None]:
    """How well these answers support the claim that they come from separate operators.

    Returns ``(state, reason)`` where state is one of the INDEPENDENCE_* constants.

    Only two things are actual evidence, and one is the opposite:

    * **A shared provider header.** ``x-and-nl`` is Nodely's stamp, and its legacy
      ``algonode.cloud`` hosts carry the same datacentre as ``nodely.dev``. Two endpoints
      sharing it are one provider however the hostnames differ. This is positive evidence
      of sameness and it is decided here.
    * **The same endpoint named twice.** One operator under two labels.
    * **Identical state proofs are NOT evidence either way.** A state proof is a
      deterministic function of the interval's signing set, so two honest, fully
      independent nodes are *expected* to return the same bytes — that agreement is the
      evidence, not a contradiction. Treating identical proofs as collusion would invert
      the mechanism and fail every correct answer.

    The correction that matters: **silence is not evidence of independence.** An earlier
    version returned "independent" whenever no headers collided, which is true for two
    Nodely hostnames only if you never look up whether they are the same business. Voi's
    two public hosts send no fingerprint at all, so that version reported corroboration
    for a pair its own documentation calls one operator. A missing header is a missing
    measurement, so it now reports ``unknown`` and ``corroborated`` stays False.

    ``evidenced`` therefore requires that EVERY answering operator stamped itself and no
    two stamps collided. Anything less is ``unknown``: the caller may still trust it, but
    on their own knowledge rather than on this check's output. A caller who knows they run
    one of the nodes can say so with ``declared_independent``, which yields ``asserted``
    and is recorded as exactly that.
    """
    endpoints = [_endpoint_identity(r.endpoint) for r in answered]
    if len(set(endpoints)) != len(endpoints):
        return (INDEPENDENCE_SAME,
                "the same endpoint was named more than once, which is not two operators")

    seen: dict[str, str] = {}
    stamped = 0
    for r in answered:
        found = False
        for header, value in r.fingerprint.items():
            if header not in FINGERPRINT_HEADERS or not value:
                continue
            found = True
            key = f"{header}={_operator_identity(header, value)}"
            if key in seen:
                return (INDEPENDENCE_SAME,
                        f"operators {seen[key]!r} and {r.name!r} returned the same "
                        f"provider header ({key}), so they are one provider answering "
                        "under two names")
            seen[key] = r.name
        stamped += 1 if found else 0

    if stamped == len(answered):
        return (INDEPENDENCE_EVIDENCED, None)
    missing = [r.name for r in answered if not r.fingerprint]
    return (INDEPENDENCE_UNKNOWN,
            "no evidence either way: operator(s) " + ", ".join(missing)
            + " sent no fingerprint header, so this check cannot tell whether they are "
            "separate businesses. Agreement is real; independence is unverified. Run one "
            "of the endpoints yourself and declare it, or use operators that identify "
            "their infrastructure.")


def corroborate_round(round_number: int, *,
                      operators: Iterable[tuple[str, str]] | None = None,
                      min_operators: int = 2,
                      timeout: float = DEFAULT_TIMEOUT_S,
                      require_witness: bool = True,
                      declared_independent: bool = False) -> Corroboration:
    """Ask several operators about one attested interval and require agreement.

    ``min_operators`` is the number that must ANSWER, not the number configured. Two
    operators configured and one down is not corroboration, so this refuses rather than
    reporting agreement with itself — the failure mode that would make the whole
    mechanism theatre.

    ``require_witness`` (default) also requires that the answers come from more than one
    provider. Agreement between two hostnames owned by the same business is not
    corroboration, and reporting it as such was this module's own defect: the shipped
    default paired Nodely's current and legacy domains and called them two operators.
    Set it False only when you want the agreement comparison alone, for example when
    re-analysing captures someone else made.
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
    if not chosen:
        raise CorroborationError(
            "no operators given. There is no safe default: the only two public Algorand "
            "endpoints that serve state proofs are Nodely's current and legacy hostnames, "
            "which are one provider. Name the operators you trust with --operator "
            "NAME=URL, ideally one you run yourself."
        )
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

    # The state proof itself. Every answering operator must have served one: filtering out
    # the absent cases made {digest, None} look like agreement, so an operator replying
    # with a message and no proof was silently counted as corroborating. That is the
    # failure mode this whole module exists to prevent, so it is an explicit refusal here
    # rather than a filtered set.
    missing_proof = [r.name for r in answered if not r.state_proof_sha256]
    proofs = {r.state_proof_sha256 for r in answered if r.state_proof_sha256}
    result.agreement["state_proof_sha256"] = {
        "agreed": not missing_proof and len(proofs) == 1,
        "values": {r.name: r.state_proof_sha256 for r in answered},
    }
    if missing_proof:
        result.failure = (
            f"operator(s) {', '.join(missing_proof)} answered without a state proof, so "
            "they cannot be said to agree about one")
        return result
    if len(proofs) > 1:
        result.failure = "operators served different state proofs for the same interval"
        return result

    # Agreement is necessary but not sufficient: the support for "these are separate
    # operators" decides whether anything has been corroborated. Checking this AFTER the
    # field comparison keeps the refusals distinct — "they disagree" is a contradiction to
    # investigate, "they agree because they are the same operator" is a claim that was
    # never corroborated, and "nobody identified themselves" is a measurement that was
    # never taken.
    if require_witness:
        state, reason = _independence_state(answered)
        result.independence_state = state
        if state == INDEPENDENCE_SAME:
            result.same_operator = True
            result.failure = f"not corroborated: {reason}"
            return result
        if state == INDEPENDENCE_UNKNOWN and not declared_independent:
            # Agreement stands; the independence claim does not. This is still a refusal
            # for the purpose of the word "corroborated", because reporting it as one is
            # precisely the false claim 0.13.4 made about two Nodely hostnames.
            result.independence_state = INDEPENDENCE_UNKNOWN
            result.failure = f"not corroborated: {reason}"
            result.agreed = True
            return result
        if state == INDEPENDENCE_UNKNOWN and declared_independent:
            # The caller states they run one of these nodes. That is knowledge this check
            # cannot obtain, so it is recorded as the caller's assertion, not as evidence.
            result.independence_state = INDEPENDENCE_ASSERTED
            result.independence = (
                "caller declared one endpoint self-run; independence rests on that "
                "assertion, not on a measurement"
            )
    else:
        # The witness check was deliberately skipped. Agreement may be reported, but the
        # word "corroborated" must not appear: the flag exists to re-analyse someone
        # else's captures, and a machine consumer reading `corroborated: true` would be
        # told one provider under two names had been corroborated.
        result.independence_state = INDEPENDENCE_WAIVED
        result.independence = (
            "same-operator check waived by the caller; agreement only, not corroboration"
        )

    result.agreed = True
    return result


def corroborate_captures(capture_dir, *, operators=None, min_operators: int = 2,
                         timeout: float = DEFAULT_TIMEOUT_S,
                         require_witness: bool = True,
                         declared_independent: bool = False) -> list[Corroboration]:
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
                              timeout=timeout, require_witness=require_witness,
                              declared_independent=declared_independent)
            for r in rounds]
