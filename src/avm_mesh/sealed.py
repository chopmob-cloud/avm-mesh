"""Sealed receipts: the wire format the rails already speak, plus LEVEL 3.

Shape, matching the shipped rails receipt so a customer's existing verifier
still works unchanged:

    {
      "canonical_bytes_b64": "...",   the EXACT bytes that were hashed
      "content_hash":        "sha256...",
      "signature":           {...},   optional LEVEL 2, operator Falcon-1024
      "consensus_attestation": {...}  LEVEL 3, inside the canonical bytes
    }

Carrying the canonical bytes means no JSON canonicaliser is needed -- you
SHA-256 the bytes. That property was worth preserving: it is what keeps the
standalone verifier's trust base small.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable

from .attestation import ConsensusAttestation, attest, verify_attestation
from .receipt import MeshError

SEALED_VERSION = 1


def canonical_bytes(content: dict) -> bytes:
    if not isinstance(content, dict):
        raise MeshError("sealed content must be an object")
    return json.dumps(content, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def seal(content: dict, bundle: dict, evidence_uri: str, *,
         trusted_voters: Any, sign: Callable[[bytes], dict] | None = None) -> dict:
    """Bind a settlement description to consensus evidence and seal it.

    The attestation is inserted INTO `content` before hashing, so it is
    covered by LEVEL 1. `sign` is optional: without it the seal carries
    integration + consensus but no operator signature, which is a weaker but
    honest artefact -- and useful precisely because LEVEL 3 does not need the
    operator to cooperate.
    """
    if not isinstance(content, dict):
        raise MeshError("content must be an object")
    if "consensus_attestation" in content:
        raise MeshError("content already carries a consensus_attestation")

    att = attest(bundle, evidence_uri, trusted_voters=trusted_voters)
    sealed_content = {**content, "consensus_attestation": att.to_dict()}
    cb = canonical_bytes(sealed_content)
    digest = hashlib.sha256(cb).hexdigest()

    out = {
        "version": SEALED_VERSION,
        "canonical_bytes_b64": base64.b64encode(cb).decode("ascii"),
        "content_hash": digest,
    }
    if sign is not None:
        sig = sign(bytes.fromhex(digest))
        if not isinstance(sig, dict):
            raise MeshError("signer must return a signature object")
        out["signature"] = sig
    return out


def verify_sealed(sealed: dict, resolve: Callable[[str], dict],
                  *, trusted_voters: Any = None,
                  expected_genesis_hash_b64: str | None = None,
                  verify_signature: Callable[[bytes, dict], bool] | None = None) -> dict:
    """Verify a sealed receipt. Raises MeshError on any failure.

    Returns a summary naming exactly which levels passed, so a caller can
    report the trust actually established rather than a single boolean.
    """
    if not isinstance(sealed, dict):
        raise MeshError("sealed receipt must be an object")
    try:
        cb = base64.b64decode(sealed["canonical_bytes_b64"], validate=True)
        declared = sealed["content_hash"]
    except KeyError as exc:
        raise MeshError(f"sealed receipt missing field {exc}") from exc
    except Exception as exc:
        raise MeshError("canonical_bytes_b64 is not valid base64") from exc

    # LEVEL 1 -- integrity
    computed = hashlib.sha256(cb).hexdigest()
    if computed != declared:
        raise MeshError(
            f"content hash mismatch: declared {declared[:16]}..., computed {computed[:16]}..."
        )

    try:
        content = json.loads(cb.decode("utf-8"))
    except Exception as exc:
        raise MeshError("canonical bytes are not valid JSON") from exc
    if not isinstance(content, dict):
        raise MeshError("canonical bytes are not an object")

    levels = {"integrity": True, "signature": None, "consensus": None}

    if "signature" in sealed:
        if verify_signature is None:
            levels["signature"] = "present-unverified"
        else:
            ok = bool(verify_signature(cb, sealed["signature"]))
            if not ok:
                raise MeshError("operator signature does not verify")
            levels["signature"] = True

    att_dict = content.get("consensus_attestation")
    if att_dict is None:
        levels["consensus"] = "absent"
        report = None
    else:
        report = verify_attestation(
            ConsensusAttestation.from_dict(att_dict),
            resolve,
            trusted_voters=trusted_voters,
            expected_genesis_hash_b64=expected_genesis_hash_b64,
        )
        levels["consensus"] = "stake_attested"

    return {
        "levels": levels,
        "trust_root": "stake_attested" if levels["consensus"] == "stake_attested" else "structural",
        "attested_txid": None if report is None else report.txid,
        "attested_round": None if report is None else report.round,
        "content": content,
    }
