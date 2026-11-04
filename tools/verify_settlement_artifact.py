#!/usr/bin/env python3
"""Standalone verifier for the AlgoVoi settlement-evidence A2A artefact.

Imports nothing from AlgoVoi. Stock library only. This exists so a counterparty
can check what we handed them without installing our package, and without having
to trust the verifier we shipped: the file is short enough to read in one sitting.

What it checks
  LEVEL 0  envelope   the artefact is an object, `parts` is a list, and exactly
                      one part carries this extension's payload
  LEVEL 1  integrity  sha256(canonical_bytes) == content_hash

What it deliberately does NOT check, and says so in its output
  LEVEL 2  operator signature   needs Falcon-1024 verification; use the package
  LEVEL 3  consensus attestation needs state-proof verification; use the package

A standalone verifier that quietly reported LEVEL 2 as passed would be worse than
no verifier, so the levels it cannot establish are named in the report.

    python verify_settlement_artifact.py artefact.json
    python verify_settlement_artifact.py artefact.json --json

Exit codes: 0 verified (envelope + integrity), 1 refused, 2 usage.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sys

EXTENSION_URI = "https://algovoi.co.uk/a2a/extensions/settlement-evidence/v1"

#: A sealed receipt is a digest and a pointer; anything approaching megabytes is
#: not one. Bounded before decoding rather than after, so a hostile peer cannot
#: make this process allocate first and refuse later.
MAX_CANONICAL_B64_CHARS = 2 * 1024 * 1024


class Refused(Exception):
    """The artefact does not carry verifiable settlement evidence."""


def _find_payload(artifact: object) -> dict:
    if not isinstance(artifact, dict):
        raise Refused("artefact is not an object")
    parts = artifact.get("parts")
    if not isinstance(parts, list):
        raise Refused("artefact has no parts list")

    payload = None
    seen_extension_part = False
    for part in parts:
        if not isinstance(part, dict):
            continue
        # A2A v1.0 identifies a DataPart by the presence of `data`; the inline
        # `kind` discriminator was removed. v0.3 peers still send it, so accept
        # `kind: "data"` and refuse a part whose tag contradicts its payload.
        if "data" not in part:
            continue
        if "kind" in part and part.get("kind") != "data":
            continue
        data = part.get("data")
        if isinstance(data, dict) and data.get("extension") == EXTENSION_URI:
            # Counted by part, not by payload value: a part carrying a null
            # receipt must not allow a second part to pass unnoticed.
            if seen_extension_part:
                raise Refused("artefact carries more than one settlement-evidence payload")
            seen_extension_part = True
            payload = data.get("avm_mesh_receipt")

    if payload is None:
        raise Refused("artefact carries no settlement-evidence payload")
    if not isinstance(payload, dict):
        raise Refused("settlement-evidence payload is not an object")
    return payload


def verify(artifact: object) -> dict:
    """Return a report dict; raise Refused on any failure."""
    payload = _find_payload(artifact)

    encoded = payload.get("canonical_bytes_b64")
    declared = payload.get("content_hash")
    if not isinstance(encoded, str):
        raise Refused("sealed receipt has no canonical_bytes_b64 string")
    if not isinstance(declared, str):
        raise Refused("sealed receipt has no content_hash string")
    if len(encoded) > MAX_CANONICAL_B64_CHARS:
        raise Refused(f"canonical_bytes_b64 is {len(encoded)} chars, over the limit")

    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refused("canonical_bytes_b64 is not valid base64") from exc

    computed = hashlib.sha256(raw).hexdigest()
    if computed != declared:
        raise Refused(f"content hash mismatch: declared {declared[:16]}..., computed {computed[:16]}...")

    try:
        content = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise Refused("canonical bytes are not valid JSON") from exc
    if not isinstance(content, dict):
        raise Refused("canonical bytes are not an object")

    settlement = content.get("settlement")
    return {
        "extension": EXTENSION_URI,
        "levels": {
            "envelope": "pass",
            "integrity": "pass",
            "signature": "not checked (needs Falcon-1024 verification)",
            "consensus": (
                "present, not checked (needs state-proof verification)"
                if content.get("consensus_attestation") is not None
                else "absent"
            ),
        },
        "content_hash": computed,
        "tx_id": settlement.get("tx_id") if isinstance(settlement, dict) else None,
        "note": (
            "envelope and integrity only; a signature or attestation present in this "
            "artefact has NOT been verified by this tool"
        ),
    }


def main(argv: list[str]) -> int:
    # Only these two spellings mean "help": `--helpful` or a filename containing "-h"
    # must not be swallowed, so the flag list is compared exactly, not by substring.
    for flag in argv:
        if flag in ("-h", "--help"):
            print("usage: python verify_settlement_artifact.py <artefact.json> [--json]")
            print()
            print("Standalone verifier for the settlement-evidence A2A artefact.")
            print("Checks the envelope and LEVEL 1 integrity; reports LEVEL 2 (signature) and")
            print("LEVEL 3 (consensus) as 'not checked' rather than omitting them.")
            print()
            print("  --json   emit the report as JSON")
            print()
            print("Exit codes: 0 verified, 1 refused, 2 usage.")
            return 0
    args = [a for a in argv if not a.startswith("-")]
    if not args:
        print("usage: python verify_settlement_artifact.py <artefact.json> [--json]", file=sys.stderr)
        return 2

    try:
        with open(args[0], encoding="utf-8") as handle:
            artifact = json.load(handle)
    except OSError as exc:
        print(f"cannot read {args[0]}: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"{args[0]} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    try:
        report = verify(artifact)
    except Refused as exc:
        if "--json" in argv:
            print(json.dumps({"verified": False, "reason": str(exc)}, indent=2))
        else:
            print(f"REFUSED: {exc}")
        return 1

    if "--json" in argv:
        print(json.dumps({"verified": True, **report}, indent=2))
    else:
        print(f"extension:  {report['extension']}")
        for level, verdict in report["levels"].items():
            print(f"{level:11}{verdict}")
        print(f"tx_id:      {report['tx_id']}")
        print(f"note:       {report['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
