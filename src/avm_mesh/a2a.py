"""A2A settlement-evidence extension.

A2A is the transport agents already use to talk to each other. This
extension lets one agent hand another a settlement receipt as evidence, and
lets the receiver check it against chain consensus instead of taking the
sender's word.

Design follows the A2A extension mechanism rather than inventing a parallel
one: the extension is declared on the agent card, negotiated per request, and
the evidence travels as an ordinary Artifact with a `data` part. Nothing in
the protocol changes; a peer that does not implement the extension simply
ignores it and falls back to whatever it trusted before.

The extension URI is the versioning boundary. Never change the semantics
behind a published URI -- publish a v2.
"""
from __future__ import annotations

from typing import Any, Callable

from .receipt import MeshError
from .sealed import verify_sealed

EXTENSION_URI = "https://algovoi.co.uk/a2a/extensions/settlement-evidence/v1"
ARTIFACT_NAME = "settlement-receipt"


def extension_descriptor() -> dict:
    """The object to place in an agent card's capabilities.extensions."""
    return {
        "uri": EXTENSION_URI,
        "description": (
            "Carries a sealed settlement receipt whose settlement is attested by "
            "Algorand or Voi consensus state proofs (Falcon-1024). Receivers verify "
            "offline against a pinned genesis hash; no operator key is required in "
            "the trust base."
        ),
        "required": False,
        "params": {
            "tiers": ["stake_attested", "structural"],
            "chains": ["mainnet-v1.0", "voimain-v1.0"],
            "proofpack_delivery": "by-reference",
        },
    }


def advertise(card: dict) -> dict:
    """Return the card with this extension declared. Does not mutate the input."""
    if not isinstance(card, dict):
        raise MeshError("agent card must be an object")
    out = dict(card)
    caps = dict(out.get("capabilities") or {})
    existing = list(caps.get("extensions") or ())
    if not any(e.get("uri") == EXTENSION_URI for e in existing if isinstance(e, dict)):
        existing.append(extension_descriptor())
    caps["extensions"] = existing
    out["capabilities"] = caps
    return out


def wants_extension(message_or_params: Any) -> bool:
    """True if a peer asked for this extension in a request.

    A2A puts requested extensions on the message params as `extensions`, and
    older peers omit it entirely, so absence means "not requested" rather
    than "refused".
    """
    if not isinstance(message_or_params, dict):
        return False
    for container in (message_or_params, message_or_params.get("params") or {}):
        if isinstance(container, dict):
            exts = container.get("extensions")
            if isinstance(exts, (list, tuple)) and EXTENSION_URI in exts:
                return True
    return False


def as_artifact(sealed: dict, *, artifact_id: str = "settlement-receipt") -> dict:
    """Wrap a sealed receipt as an A2A Artifact.

    Returns the receipt itself in a ``data`` part rather than as text, so a
    receiver never has to parse prose or trust a base64 blob's framing.

    EMITS THE v1.0 FORM. A2A v1.0 removed the inline ``kind`` discriminator as a
    breaking change (spec appendix A.2.1): a DataPart is now identified by the
    presence of the ``data`` member, not by a tag. The legacy v0.3.x form was
    ``{"kind": "data", "data": {...}}``; emitting it against a v1.0 peer makes the
    part unparseable, because there is no ``kind`` field to read and the extra
    member is unexpected.
    """
    if not isinstance(sealed, dict):
        raise MeshError("sealed receipt must be an object")
    for key in ("canonical_bytes_b64", "content_hash"):
        if key not in sealed:
            raise MeshError(f"sealed receipt missing {key}")
    return {
        "artifact_id": artifact_id,
        "name": ARTIFACT_NAME,
        "parts": [{
            "data": {"avm_mesh_receipt": sealed, "extension": EXTENSION_URI},
            "mediaType": "application/json",
        }],
    }


def verify_artifact(artifact: dict, resolve: Callable[[str], dict],
                    *, trusted_voters: Any = None,
                    expected_genesis_hash_b64: str | None = None,
                    verify_signature: Callable[[bytes, dict], bool] | None = None) -> dict:
    """Verify settlement evidence received from a peer.

    Fail-closed: an artifact that does not carry this extension's data is an
    error, not an empty success. Returning "no evidence" as success is how
    receivers end up accepting nothing and thinking they verified something.
    """
    if not isinstance(artifact, dict):
        raise MeshError("artifact must be an object")
    parts = artifact.get("parts")
    if not isinstance(parts, list):
        raise MeshError("artifact has no parts")

    payload = None
    for part in parts:
        if not isinstance(part, dict):
            continue
        # v1.0: the presence of "data" identifies a DataPart; the inline `kind`
        # discriminator was removed (spec appendix A.2.1). v0.3.x peers still send
        # it, so accept both -- the spec tells implementors to dual-handle during
        # the overlap period.
        if "data" not in part:
            continue
        if "kind" in part and part.get("kind") != "data":
            continue
        data = part.get("data")
        if isinstance(data, dict) and data.get("extension") == EXTENSION_URI:
            payload = data.get("avm_mesh_receipt")
            break

    if payload is None:
        raise MeshError("artifact carries no settlement-evidence payload")
    if not isinstance(payload, dict):
        raise MeshError("settlement-evidence payload is not an object")

    return verify_sealed(
        payload,
        resolve,
        trusted_voters=trusted_voters,
        expected_genesis_hash_b64=expected_genesis_hash_b64,
        verify_signature=verify_signature,
    )
