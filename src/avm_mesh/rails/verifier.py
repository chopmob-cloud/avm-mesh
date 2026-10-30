"""Verify a rails-shaped settlement receipt, with LEVEL 3.

Wire format (unchanged from the shipped rails verifier)::

    {
      "canonical_bytes_b64": "...",      the EXACT bytes that were hashed
      "content_hash":        "sha256...",
      "signature":           {...},      optional LEVEL 2, operator Falcon-1024
    }

with the consensus attestation living INSIDE the canonical bytes under
``consensus_attestation`` -- so it is covered by LEVEL 1 and cannot be swapped or
stripped without breaking the content hash.

Trust levels are reported separately, never collapsed into one boolean: a caller
must be able to see whether it is trusting the operator, the chain, or neither.
"""
from __future__ import annotations

from typing import Any, Callable

from ..receipt import MeshError
from ..sealed import verify_sealed

#: Level 3 is defined relative to an anchor the caller supplies. Without one the
#: verdict is structural, and this module says so rather than quietly downgrading.
REQUIRED_FOR_LEVEL3 = "trusted_voters"


def verify_rails_receipt(receipt: dict,
                         resolve: Callable[[str], dict],
                         *,
                         operator_pubkey_b64: str | None = None,
                         trusted_voters: Any = None,
                         expected_genesis_hash_b64: str | None = None) -> dict:
    """Verify a rails receipt and report each level separately.

    Parameters
    ----------
    receipt
        The JSON object as the rails emit it.
    resolve
        Maps the attestation's ``evidence_uri`` to a proofpack. Supplied by the
        caller so storage stays agnostic (file, HTTP, chain).
    operator_pubkey_b64
        The operator's Falcon-1024 public key. Without it a present signature is
        reported as ``"present-unverified"`` rather than being called valid.
    trusted_voters
        The caller's ``avm_proofpack.verify.TrustedVoters`` anchor. Required for
        LEVEL 3; it is what makes the consensus claim mean anything.
    expected_genesis_hash_b64
        Pinned genesis hash. Strongly recommended: without it the attestation's
        own anchor is checked against itself.

    Returns a dict with ``levels`` (integrity / signature / consensus),
    ``trust_root`` (``stake_attested`` only when LEVEL 3 passed, else
    ``structural``), and the decoded ``content``.
    """
    if not isinstance(receipt, dict):
        raise MeshError("rails receipt must be an object")

    if "canonical_bytes_b64" not in receipt or "content_hash" not in receipt:
        raise MeshError("rails receipt must carry canonical_bytes_b64 and content_hash")

    embedded_key = receipt.get("public_key_b64")
    signature_state = None
    verify_signature = None

    if "signature" in receipt:
        pinned = operator_pubkey_b64
        if pinned is not None and embedded_key is not None and pinned != embedded_key:
            # A receipt may not name a key that differs from the one you pinned.
            raise MeshError(
                "operator key mismatch: the receipt carries a different public key "
                "than the one pinned by the caller"
            )
        # With no pinned key, the embedded one can still check the signature, but
        # it is SELF-ASSERTED: whoever wrote the receipt chose the key, so this
        # proves internal consistency, not the operator's identity.
        key = pinned or embedded_key
        signature_state = "valid" if pinned else "self-asserted"
        verify_signature = _operator_verifier(key) if key else None

    result = verify_sealed(
        receipt,
        resolve,
        trusted_voters=trusted_voters,
        expected_genesis_hash_b64=expected_genesis_hash_b64,
        verify_signature=verify_signature,
    )

    levels = result["levels"]
    if "signature" in receipt:
        # verify_sealed reports a bare True; the rails distinction between a
        # pinned key and a self-asserted one is information the caller needs.
        levels["signature"] = signature_state if levels["signature"] is True else levels["signature"]

    return {
        "levels": levels,
        "trust_root": result["trust_root"],
        "content": result["content"],
        "attested_txid": result["attested_txid"],
        "attested_round": result["attested_round"],
    }


def _operator_verifier(pubkey_b64: str):
    """Falcon-1024 verification over sha256(canonical bytes).

    Uses avm_proofpack's stdlib-only verifier, not `pqcrypto`: 1.0.0 removed
    Falcon entirely when PQClean was archived. See docs/PQC-FALCON.md.

    ``falcon1024_verify`` RETURNS a bool and does not raise on a bad signature,
    so the return value is checked -- an unchecked call reads as success for any
    signature.
    """
    import base64
    import hashlib

    from avm_proofpack.consensus.falcon import falcon1024_verify

    try:
        pubkey = base64.b64decode(pubkey_b64, validate=True)
    except Exception as exc:
        raise MeshError("operator public key is not valid base64") from exc

    def verify(content_bytes: bytes, signature: dict) -> bool:
        if not isinstance(signature, dict) or "sig_b64" not in signature:
            raise MeshError("signature object has no sig_b64")
        try:
            sig = base64.b64decode(signature["sig_b64"], validate=True)
        except Exception as exc:
            raise MeshError("signature is not valid base64") from exc
        # The rails sign the HEX STRING of the digest, encoded UTF-8 -- not the
        # raw 32 bytes. Verified against their shipped verifier:
        #     falcon_verify(pk, computed.encode("utf-8"), sig)
        # where computed = sha256(cb).hexdigest(). Signing the raw digest instead
        # would produce a verifier that rejects every genuine rails receipt.
        payload = hashlib.sha256(content_bytes).hexdigest().encode("utf-8")
        return bool(falcon1024_verify(pubkey, payload, sig))

    return verify
