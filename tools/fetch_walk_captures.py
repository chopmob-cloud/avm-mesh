#!/usr/bin/env python3
"""Fetch consecutive state proofs from a public algod and write walk captures.

The anchor walk has been proven on one interval for a long time, because proving two
needed a second capture and nobody had one. This tool makes the second capture
obtainable by anyone: point it at an algod endpoint and a target round, and it writes
one bundle per interval, each carrying its own state proof, its message, and the
previous interval's message.

    python tools/fetch_walk_captures.py --round 66606848 --hops 2 \
        --out examples/walk-mainnet-66606848

What the resulting captures let you do is prove that chaining works: each interval is
verified against voters derived from the previous interval's authenticated message,
which is the whole point of the module and something a single capture cannot show.

What they do NOT prove: that the endpoint is independent or honest. Every capture here
comes from one HTTP response, so the walk proves the mechanism, not the source. Say so
whenever these are cited.

stdlib only. The encoding is the chain's own: `StateProof` is already msgpack base64,
so it is passed through untouched rather than re-encoded here.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request

DEFAULT_INTERVAL = 256
DEFAULT_ENDPOINT = "https://mainnet-api.algonode.cloud"


def _get(url: str, timeout: int = 60) -> dict:
    request = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _message(algod_message: dict) -> dict:
    """algod's PascalCase StateProofMessage to the bundle's snake_case form."""
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch consecutive state proofs from a public algod and write walk captures.")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--round", type=int, required=True,
                        help="the interval's last attested round (a multiple of 256)")
    parser.add_argument("--hops", type=int, default=2,
                        help="how many intervals to fetch, oldest first, including the target")
    parser.add_argument("--genesis", default="wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
                        help="genesis hash of the chain being captured")
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)

    if args.round % DEFAULT_INTERVAL:
        raise SystemExit(f"--round must be a multiple of {DEFAULT_INTERVAL}")
    if args.hops < 2:
        raise SystemExit("--hops must be at least 2: one capture cannot show chaining")

    rounds = [args.round - i * DEFAULT_INTERVAL for i in range(args.hops)][::-1]
    args.out.mkdir(parents=True, exist_ok=True)

    fetched: dict[int, dict] = {}
    manifest: list[dict] = []
    for round_number in rounds:
        url = f"{args.endpoint.rstrip('/')}/v2/stateproofs/{round_number}"
        try:
            body = _get(url)
        except urllib.error.HTTPError as exc:
            print(f"FAIL  {round_number}: HTTP {exc.code} from {url}", file=sys.stderr)
            return 1
        except urllib.error.URLError as exc:
            print(f"FAIL  {round_number}: {exc.reason}", file=sys.stderr)
            return 1
        if "StateProof" not in body or "Message" not in body:
            print(f"FAIL  {round_number}: response has no StateProof/Message", file=sys.stderr)
            return 1
        fetched[round_number] = body

    for round_number in rounds:
        body = fetched[round_number]
        message = _message(body["Message"])
        if int(message["last_attested_round"]) != round_number:
            print(f"FAIL  {round_number}: message attests "
                  f"{message['last_attested_round']}", file=sys.stderr)
            return 1

        bundle = {
            "format": "avm-proofpack-bundle",
            "version": 1,
            "chain": "algorand-mainnet",
            "genesis_hash_b64": args.genesis,
            "state_proof_msgpack_b64": body["StateProof"],
            "state_proof_message": message,
            "provenance": {"endpoint": args.endpoint, "round": round_number},
        }
        previous = fetched.get(round_number - DEFAULT_INTERVAL)
        if previous is not None:
            bundle["previous_state_proof_message"] = _message(previous["Message"])

        path = args.out / f"{round_number}.json.gz"
        raw = json.dumps(bundle, sort_keys=True).encode()
        path.write_bytes(gzip.compress(raw, 9))
        manifest.append({
            "round": round_number,
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "state_proof_bytes": len(base64.b64decode(body["StateProof"])),
            "ln_proven_weight": int(message["ln_proven_weight"]),
        })
        print(f"wrote {path} ({path.stat().st_size // 1024} KB)")

    record = {
        "chain": "algorand-mainnet",
        "genesis_hash_b64": args.genesis,
        "endpoint": args.endpoint,
        "interval": DEFAULT_INTERVAL,
        "target_round": rounds[-1],
        "hops": rounds,
        "fetched_at_utc": datetime.datetime.now(datetime.timezone.utc)
                          .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "independence": "all captures came from one endpoint; this proves chaining, not source independence",
        "files": manifest,
    }
    (args.out / "provenance.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out / 'provenance.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
