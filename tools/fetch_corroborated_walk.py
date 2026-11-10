#!/usr/bin/env python
"""Fetch a walk and corroborate each interval across independent operators as it is taken.

This is the tool that makes the independence claim real rather than aspirational. It does
the two things that must happen together:

1. capture each interval's state proof, so the walk has bytes to verify later;
2. ask several distinct operators for the same interval at the same moment, and record
   whether they agree about the fields the proof is verified against.

The ordering matters and is the reason this exists as one tool. Public endpoints retain
only the most recent state-proof intervals -- measured at three to four on Algorand
mainnet -- so corroboration is possible only during capture. Done afterwards it is
impossible, and a reader cannot tell an uncorroborated capture from a corroborated one
unless the capture records which it is. So every capture carries its own corroboration
result, signed off with the operators that answered and the fields they agreed on.

A capture set that fails corroboration is still written, because a partial record is
better than none, but its provenance says so and `--require-agreement` (on by default)
makes the exit code non-zero.

Usage:

    python tools/fetch_corroborated_walk.py --hops 3 --out examples/walk-mainnet-X

Reads nothing from the local repo, writes one bundle per interval plus `provenance.json`.
Stdlib only.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

INTERVAL = 256

#: Operators believed to be organisationally distinct. Declared, not proven -- the report
#: says so, and a reader who knows better can pass --operator to correct it.
OPERATORS = (
    ("algonode", "https://mainnet-api.algonode.cloud"),
    ("nodely", "https://mainnet-api.4160.nodely.dev"),
)

#: The path a state proof is fetched on, and the shape of the response.
FIELDS = ("VotersCommitment", "LnProvenWeight", "BlockHeadersCommitment")

#: Algorand mainnet genesis hash, base64. Pinned, not fetched: a genesis read from the
#: endpoint under test would let that endpoint declare which chain it is answering for.
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="


#: Same ceiling as `avm_mesh.crossnode.MAX_RESPONSE_BYTES`. Two tools reading the same
#: endpoint with different limits is how one of them ends up being the soft target.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _get(endpoint: str, path: str, *, timeout: float = 25.0) -> dict:
    request = urllib.request.Request(endpoint.rstrip("/") + path,
                                     headers={"accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f"{path} returned more than {MAX_RESPONSE_BYTES} bytes")
    return json.loads(raw)


def _message(algod_message: dict) -> dict:
    """algod's PascalCase StateProofMessage to the bundle's snake_case form.

    Deliberately identical to `tools/fetch_walk_captures.py`: two tools that build bundles
    differently is two formats, and the walk only reads one.
    """
    missing = [k for k in ("BlockHeadersCommitment", "FirstAttestedRound",
                           "LastAttestedRound", "LnProvenWeight", "VotersCommitment")
               if k not in algod_message]
    if missing:
        raise SystemExit(f"algod message is missing {', '.join(missing)}")
    return {
        "block_headers_commitment_b64": algod_message["BlockHeadersCommitment"],
        "first_attested_round": algod_message["FirstAttestedRound"],
        "last_attested_round": algod_message["LastAttestedRound"],
        "ln_proven_weight": algod_message["LnProvenWeight"],
        "voters_commitment_b64": algod_message["VotersCommitment"],
    }


def _status(endpoint: str) -> dict:
    return _get(endpoint, "/v2/status")


def _stateproof(endpoint: str, round_number: int) -> dict:
    return _get(endpoint, f"/v2/stateproofs/{round_number}")


def _probe(endpoint: str, round_number: int, timeout: float) -> bool:
    """Whether this operator still retains that interval's state proof.

    Catches the three ways an interval can be *absent* -- an HTTP error, an unreachable
    host, a body that is not JSON -- and nothing else. A bare `except Exception` here
    would report a bug in this tool as "the operator has pruned that interval", which is a
    wrong diagnosis rather than a missing one, and it was the last broad catch left after
    the same pattern was removed from `crossnode`.
    """
    try:
        body = _get(endpoint, f"/v2/stateproofs/{round_number}", timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, OSError):
        return False
    return isinstance(body, dict) and "StateProof" in body and "Message" in body


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=" ".join(__doc__.strip().splitlines()[0:1]) or None)
    parser.add_argument("--hops", type=int, default=3,
                        help="number of intervals to capture, ending at the newest (default 3)")
    parser.add_argument("--out", required=True, help="directory to write captures into")
    parser.add_argument("--operator", action="append", metavar="NAME=URL",
                        help="operator to ask; repeat for each. Defaults to two publicly "
                             "distinct Algorand endpoints")
    parser.add_argument("--allow-disagreement", action="store_true",
                        help="write captures even when operators disagree, with the "
                             "disagreement recorded (default: refuse and exit non-zero)")
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args(argv)

    operators = []
    for spec in (args.operator or []):
        if "=" not in spec:
            print(f"--operator wants NAME=URL, got {spec!r}", file=sys.stderr)
            return 2
        name, url = spec.split("=", 1)
        name, url = name.strip(), url.strip()
        # These URLs go straight into urlopen. Without a scheme check a file:// URL is a
        # local-file read, and nothing about "ask an operator" requires anything but HTTP.
        if not url.startswith(("http://", "https://")):
            print(f"refusing: --operator {name!r} is {url!r}; an operator endpoint must be "
                  "http:// or https://", file=sys.stderr)
            return 2
        operators.append((name, url))
    if args.hops < 1:
        # A walk needs at least one interval to capture; `requested[0]` below assumes a
        # non-empty list, and an IndexError is not how a usage error should present.
        print(f"refusing: --hops must be at least 1, got {args.hops}", file=sys.stderr)
        return 2
    if not operators:
        operators = list(OPERATORS)
    if len(operators) < 2:
        print("refusing: corroboration needs at least two operators; one agreeing with "
              "itself is not corroboration", file=sys.stderr)
        return 2

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        heads = {name: int(_status(url)["last-round"]) for name, url in operators}
    except Exception as exc:
        print(f"could not read node status: {exc}", file=sys.stderr)
        return 1
    # The newest interval every operator is certain to have finished. One interval back
    # from the newest available boundary, so the proof is complete rather than in flight.
    head = min(heads.values())
    newest = (head // INTERVAL) * INTERVAL - INTERVAL
    if newest < 0:
        print(f"refusing: head {head} is below one state-proof interval ({INTERVAL}); "
              "there is no completed interval to capture", file=sys.stderr)
        return 2
    requested = [newest - INTERVAL * i for i in range(args.hops)][::-1]
    if requested and requested[0] < 0:
        # Clamp rather than refuse: asking for more hops than the chain has history for
        # should capture what exists. Rounds below zero are dropped here; rounds the
        # operators no longer retain are then dropped by the retention probe further down,
        # which records them in `beyond_retention` rather than silently ignoring them.
        requested = [r for r in requested if r >= 0]

    print(f"head (min across operators): {head}")

    # Probe availability before committing to a set. Retention is short and it is shorter
    # than any fixed guess: asking for four intervals when the endpoint keeps three used
    # to look like a disagreement rather than a retention boundary. Probing turns that
    # into a recorded fact about which rounds exist, so `hops` is a request rather than a
    # promise and the provenance says what was actually captured.
    available = []
    for round_number in requested:
        if all(_probe(url, round_number, args.timeout) for _, url in operators):
            available.append(round_number)
    missing = [r for r in requested if r not in available]
    if missing:
        print(f"beyond retention on at least one operator: "
              f"{', '.join(str(r) for r in missing)}")
    # Keep the newest contiguous run: the walk chains, so a gap in the middle is useless.
    rounds = []
    for round_number in reversed(available):
        if not rounds or rounds[0] - round_number == INTERVAL:
            rounds.insert(0, round_number)
    if len(rounds) < 2:
        print(f"refusing: only {len(rounds)} interval(s) available; a walk needs at least "
              "two to show chaining", file=sys.stderr)
        return 2

    print(f"rounds to capture: {', '.join(str(r) for r in rounds)}")

    captures, corroborations = [], []
    fetched: dict[int, dict] = {}
    all_agreed = True

    for round_number in rounds:
        responses, agreed_fields, ok = {}, {}, True
        bodies: dict[str, dict] = {}
        for name, url in operators:
            try:
                body = _stateproof(url, round_number)
                bodies[name] = body
            except Exception as exc:
                responses[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                ok = False
                continue
            message = body.get("Message") or {}
            proof = body.get("StateProof") or ""
            responses[name] = {
                "ok": True,
                "last_attested_round": message.get("LastAttestedRound"),
                "fields": {f: message.get(f) for f in FIELDS},
                "state_proof_sha256": hashlib.sha256(proof.encode()).hexdigest() if proof else None,
            }

        answering = [n for n, r in responses.items() if r["ok"]]
        if len(answering) < 2:
            ok = False
        else:
            for field_name in FIELDS:
                values = {responses[n]["fields"][field_name] for n in answering}
                agreed_fields[field_name] = {
                    "agreed": len(values) == 1,
                    "values": {n: responses[n]["fields"][field_name] for n in answering},
                }
                if len(values) != 1:
                    ok = False
            # Same rule as `crossnode`: every answering operator must have served a proof,
            # and they must be the same proof. Including None in the value set happened to
            # fail here and pass there, which is not a difference of strictness but two
            # implementations of one rule.
            proofs = {responses[n]["state_proof_sha256"] for n in answering}
            any_missing = any(not responses[n]["state_proof_sha256"] for n in answering)
            agreed_fields["state_proof_sha256"] = {
                "agreed": not any_missing and len(proofs) == 1,
                "values": {n: responses[n]["state_proof_sha256"] for n in answering},
            }
            if any_missing or len(proofs) != 1:
                ok = False

        all_agreed = all_agreed and ok

        # The capture itself comes from the first operator that answered, and is checked
        # against every other operator's fingerprint of the same proof.
        if not answering:
            # Nobody answered: attempting a capture from a default endpoint would fail
            # noisily and record a misleading "source" the operators never agreed on.
            print(f"  {round_number}: no operator answered; nothing captured", file=sys.stderr)
            all_agreed = False
            corroborations.append({
                "round": round_number, "corroborated": False,
                "operators_answering": [], "agreement": agreed_fields,
                "responses": responses,
            })
            continue
        source = answering[0]
        source_url = dict(operators)[source]
        try:
            # Reuse the response already fetched above rather than asking a second time.
            # The second request cost a full state proof in bandwidth and, worse, could
            # return a different body than the one that was just corroborated -- so the
            # capture would carry bytes that no operator had agreed about.
            body = bodies.get(source)
            if body is None:
                body = _stateproof(source_url, round_number)
            if "StateProof" not in body or "Message" not in body:
                raise SystemExit(f"round {round_number}: no StateProof/Message")
            message = _message(body["Message"])
            if int(message["last_attested_round"]) != round_number:
                raise SystemExit(
                    f"round {round_number}: message attests "
                    f"{message['last_attested_round']}")
            # The bundle, in the same shape `anchor.walk` consumes. The previous
            # interval's message is included when it is in this set, because the walk
            # verifies each proof against the preceding interval's signing set.
            bundle = {
                "format": "avm-proofpack-bundle",
                "version": 1,
                "chain": "algorand-mainnet",
                "genesis_hash_b64": GENESIS,
                "state_proof_msgpack_b64": body["StateProof"],
                "state_proof_message": message,
                "provenance": {"endpoint": source, "round": round_number,
                               "corroborated_by": answering},
            }
            previous_round = round_number - INTERVAL
            if previous_round in fetched:
                bundle["previous_state_proof_message"] = _message(
                    fetched[previous_round]["Message"])
            fetched[round_number] = body

            raw = json.dumps(bundle, sort_keys=True).encode()
            packed = gzip.compress(raw, 9, mtime=0)
            name = f"{round_number}.json.gz"
            (out / name).write_bytes(packed)
            captures.append({
                "round": round_number,
                "file": name,
                "sha256_gz": _sha256_bytes(packed),
                "sha256_raw": _sha256_bytes(raw),
                "state_proof_bytes": len(base64.b64decode(body["StateProof"])),
                "ln_proven_weight": int(message["ln_proven_weight"]),
                "source": source,
                "corroborated_by": answering,
                "last_attested_round": message["last_attested_round"],
            })
            print(f"  {round_number}: captured {len(packed):,} bytes from {source}")
        except Exception as exc:
            print(f"  {round_number}: capture FAILED ({exc})", file=sys.stderr)
            ok = False

        corroborations.append({
            "round": round_number,
            "corroborated": ok,
            "operators_answering": answering,
            "agreement": agreed_fields,
            "responses": responses,
        })
        print(f"  {round_number}: {'corroborated' if ok else 'NOT corroborated'}")

    provenance = {
        "tool": "tools/fetch_corroborated_walk.py",
        "chain": "algorand-mainnet",
        "interval": INTERVAL,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "node_heads": heads,
        "operators": [{"name": n, "endpoint": u} for n, u in operators],
        "requested_rounds": requested,
        "captured_rounds": rounds,
        "beyond_retention": missing,
        "captures": captures,
        "corroboration": corroborations,
        "cross_operator_agreement": all_agreed,
        "independence": (
            "agreement across distinct endpoints, not proof of independent ownership; "
            "a shared upstream, hosting provider or operator running two domains defeats "
            "this, and a reader who knows the operators should say so"
        ),
        "retention_note": (
            "corroboration is only possible during capture: public endpoints retain three "
            "to four state-proof intervals, so an interval cannot be cross-checked after "
            "the fact by anyone"
        ),
        "regenerate": (
            f"python tools/fetch_corroborated_walk.py --hops {args.hops} "
            f"--out {args.out}"
        ),
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n",
                                         encoding="utf-8")

    print(f"\ncross-operator agreement: {'YES' if all_agreed else 'NO'}")
    print(f"provenance: {out / 'provenance.json'}")
    if not all_agreed and not args.allow_disagreement:
        print("\nrefusing to present this as a corroborated walk; pass "
              "--allow-disagreement to write it anyway with the disagreement recorded",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
