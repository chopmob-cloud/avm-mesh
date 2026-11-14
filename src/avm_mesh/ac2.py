"""AC2 consent, bound to a settlement and to the key that paid for it.

What this module is for
=======================
`avm-mesh` proves *what settled*. AC2 (Algorand Foundation, Draft) is a consent
and signing-delegation channel: it lets an agent obtain a signature from a user's
wallet without ever holding the user's key. Neither answers the other's question,
and this module is the seam between them -- deliberately narrow.

The gap it closes
-----------------
A sealed receipt already carries a free-form ``content`` dict, and the shipped
examples already publish an ``issuer_did``. Nothing verifies either. So an
operator can publish a receipt beside a consent claim that nobody checks, and a
reader sees "human approved" next to ``stake_attested`` and reasonably -- and
wrongly -- reads the approval as proven too. That is the same defect class the
amount binding closed: a figure the producer chose sitting next to a tier that
was earned.

What is actually provable, and what is not
------------------------------------------
AC2's ``ac2/SigningResponse`` body is::

    { "signature": ..., "public_key": ..., "address"?: ..., "key_type"?: ... }

There is **no WebAuthn material** in it -- no ``authenticatorData``, no
``clientDataJSON``, no ``credentialId``, no attestation object. The Draft spec's
Pattern 2 diagram says a delegated signature comes "with constraints: expiry,
scope", but no normative field carries either, and the SDK's
``SigningResponseBody`` declares neither.

The consequence is stated here because getting it wrong inflates every claim
above it: **a third party holding only an AC2 response cannot tell a hardware
passkey from a software key.** So this module never says "hardware-bound" and
never says "a human approved". It proves exactly what the bytes prove:

``consent_present``
    The signature verifies, over *this* settlement's canonical payload, against
    the public key it names. Proves: the holder of that key signed this
    settlement description. Proves nothing about who or what that holder was.

``sender_bound``
    Additionally that public key IS the authenticated ``sender`` of the on-chain
    transaction, read out of the ``SignedTxnInBlock`` whose hash was proven into
    the block's transaction commitment. This is the property worth having: the
    approval and the payment come from one key, so they cannot be swapped for
    each other, and the payer cannot be misrepresented.

``consensus_bound``
    Additionally the settlement reached ``stake_attested``.

Why the payer is the signer, and not the agent
----------------------------------------------
AC2's whole design is that the agent cannot sign. So in the x402 flow the agent
holds a *delegated* signature and submits; the account that funds the transaction
is the controller's. That makes AC2's ``address`` field -- the Algorand account
bound to the passkey by the Liquid Extension -- the natural payer, and
``address == sender`` the binding to check. A wallet that signs from a different
account than it advertised will fail this check, which is the intended outcome:
the alternative is trusting the agent's word about who paid whom.

Storage
-------
The block lives inside the sealed ``content``, which is hashed *before* the
consensus attestation is inserted (see ``sealed.seal``), so the whole block is
covered by ``content_hash``. A receipt therefore cannot have its consent edited,
swapped or stripped without breaking LEVEL 1. That is what makes checking it
worth anything.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass

from .receipt import MeshError

#: Where the consent block sits inside sealed ``content``.
AC2_CONSENT_KEY = "ac2_consent"

#: Wire version of the block. The semantics behind this number must never
#: change: a reader either understands it or refuses it by name.
AC2_CONSENT_VERSION = 1

#: The canonical payload type the human is asked to approve.
CONSENT_PAYLOAD_TYPE = "algovoi/settlement-consent/v1"

#: Reached levels, weakest first.
LEVEL_NONE = "none"
LEVEL_CONSENT = "consent_present"
LEVEL_SENDER = "sender_bound"
LEVEL_CONSENSUS = "consensus_bound"
LEVELS = (LEVEL_NONE, LEVEL_CONSENT, LEVEL_SENDER, LEVEL_CONSENSUS)


def canonical_bytes(content: dict) -> bytes:
    """Canonical JSON identical to :func:`avm_mesh.sealed.canonical_bytes`.

    Re-declared rather than imported so this module states its own preimage, and
    pinned by a test that the two agree. Two "canonical" encoders drifting apart
    is the classic way a signature check starts passing over bytes nobody signed.
    """
    if not isinstance(content, dict):
        raise MeshError("content must be an object")
    return json.dumps(content, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _b64d(value: object, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise MeshError(f"ac2_consent.{field} must be a non-empty base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MeshError(f"ac2_consent.{field} is not valid base64") from exc


def consent_payload(settlement: dict) -> bytes:
    """The exact bytes an AC2 controller is asked to sign.

    One function so the agent's request and every verifier's check cannot drift
    apart. It covers the settlement in full -- chain, txid, round, amount, asset
    -- so a consent obtained for one payment cannot be re-presented for another.
    """
    if not isinstance(settlement, dict):
        raise MeshError("settlement must be an object")
    return canonical_bytes({"type": CONSENT_PAYLOAD_TYPE, "settlement": settlement})


def consent_digest(settlement: dict) -> str:
    """SHA-256 over :func:`consent_payload`, the value recorded in the block."""
    return hashlib.sha256(consent_payload(settlement)).hexdigest()


@dataclass(frozen=True)
class ConsentAttestation:
    """The AC2 half of a settlement, as stored inside a sealed receipt.

    ``signed_payload_sha256`` is the load-bearing field. Without it a signature
    would be checked against whatever bytes the verifier happened to assemble,
    and a consent obtained for one payment would verify against another. With it,
    the block states which payload it covers and the verifier recomputes.
    """

    version: int
    did: str
    sig_hint: str
    public_key_b64: str
    signature_b64: str
    signed_payload_sha256: str
    #: AC2 message ids, recorded for audit. Never trusted for anything.
    request_id: str | None = None
    response_id: str | None = None

    def __post_init__(self) -> None:
        d = self.signed_payload_sha256
        if not isinstance(d, str) or len(d) != 64:
            raise MeshError("ac2_consent.signed_payload_sha256 must be a 64-char sha256 hex")
        try:
            int(d, 16)
        except ValueError as exc:
            raise MeshError("ac2_consent.signed_payload_sha256 is not hexadecimal") from exc
        if not isinstance(self.did, str) or not self.did:
            raise MeshError("ac2_consent.did must be a non-empty string")

    def to_dict(self) -> dict:
        out: dict = {
            "version": self.version,
            "did": self.did,
            "sig_hint": self.sig_hint,
            "public_key": self.public_key_b64,
            "signature": self.signature_b64,
            "signed_payload_sha256": self.signed_payload_sha256,
        }
        if self.request_id:
            out["request_id"] = self.request_id
        if self.response_id:
            out["response_id"] = self.response_id
        return out

    @classmethod
    def from_dict(cls, data: object) -> "ConsentAttestation":
        if not isinstance(data, dict):
            raise MeshError("ac2_consent must be an object")
        try:
            version = int(data["version"])
        except KeyError as exc:
            raise MeshError("ac2_consent missing field 'version'") from exc
        except (TypeError, ValueError) as exc:
            raise MeshError("ac2_consent.version is not an integer") from exc
        if version != AC2_CONSENT_VERSION:
            # Refuse by name. Reinterpreting an older artefact under new
            # semantics reopens the hole a version bump exists to close.
            raise MeshError(
                f"unsupported ac2_consent version {version}: this verifier "
                f"implements version {AC2_CONSENT_VERSION} only"
            )
        fields = ("did", "sig_hint", "public_key", "signature", "signed_payload_sha256")
        missing = [f for f in fields if f not in data]
        if missing:
            raise MeshError(f"ac2_consent missing field(s) {', '.join(missing)}")
        return cls(
            version=version,
            did=str(data["did"]),
            sig_hint=str(data["sig_hint"]),
            public_key_b64=str(data["public_key"]),
            signature_b64=str(data["signature"]),
            signed_payload_sha256=str(data["signed_payload_sha256"]),
            request_id=data.get("request_id"),
            response_id=data.get("response_id"),
        )


def build_consent(*, did: str, sig_hint: str, public_key_b64: str,
                  signature_b64: str, settlement: dict,
                  request_id: str | None = None,
                  response_id: str | None = None) -> dict:
    """Assemble the ``ac2_consent`` block for sealed ``content``.

    Called on the **agent** side, after ``Ac2Client.requestSignature`` returns an
    approval. This does not sign, and must not: the agent never holds the key.
    The caller is responsible for having asked the controller to sign exactly
    :func:`consent_payload` of this settlement.
    """
    return ConsentAttestation(
        version=AC2_CONSENT_VERSION,
        did=did,
        sig_hint=sig_hint,
        public_key_b64=public_key_b64,
        signature_b64=signature_b64,
        signed_payload_sha256=consent_digest(settlement),
        request_id=request_id,
        response_id=response_id,
    ).to_dict()


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a detached Ed25519 signature.

    ``cryptography`` is the only dependency added for this feature. It is
    imported here rather than at module scope so that importing ``avm_mesh``
    stays cheap and the rest of the library keeps working without it; a caller
    that never checks a consent never needs it.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise MeshError(
            "verifying an AC2 consent needs the 'cryptography' package "
            "(pip install 'avm-mesh[ac2]'); refusing to report a check it "
            "could not perform"
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        # A well-formed signature that does not verify: the ordinary "wrong
        # signer" case.
        return False
    except ValueError as exc:
        # Reachable only if a caller passes a key or signature of the wrong
        # length without going through verify_consent (which checks both first).
        # Answering False is right -- it is not a valid approval -- but raising
        # would be wrong here, because this function's contract is a boolean and
        # the length refusal belongs to the caller that owns the message.
        return False


def _open_sealed(sealed: object) -> dict:
    """Return the verified ``content`` of a sealed receipt.

    Re-verifies LEVEL 1 here rather than trusting the caller to have done it: this
    function's whole job is to read claims out of authenticated bytes, so reading
    them out of unauthenticated ones would defeat it.
    """
    if not isinstance(sealed, dict):
        raise MeshError("sealed receipt must be an object")
    try:
        cb = base64.b64decode(sealed["canonical_bytes_b64"], validate=True)
    except KeyError as exc:
        raise MeshError("sealed receipt missing field 'canonical_bytes_b64'") from exc
    except (binascii.Error, ValueError) as exc:
        raise MeshError("canonical_bytes_b64 is not valid base64") from exc

    declared = sealed.get("content_hash")
    computed = hashlib.sha256(cb).hexdigest()
    if declared != computed:
        raise MeshError(
            f"content hash mismatch: declared {str(declared)[:16]}..., "
            f"computed {computed[:16]}...; refusing to read consent from it"
        )
    try:
        content = json.loads(cb.decode("utf-8"))
    except Exception as exc:
        raise MeshError("canonical bytes are not valid JSON") from exc
    if not isinstance(content, dict):
        raise MeshError("canonical bytes are not an object")
    return content


def verify_consent(sealed: dict, *, expected_sender: bytes | None = None,
                   require: bool = False) -> dict:
    """Verify the AC2 consent block inside a sealed receipt.

    Returns a dict with ``level``, ``reason`` and the consent identity. Fails
    closed: a present-but-invalid block always raises, and an absent block raises
    too unless the caller passes ``require=False``.

    ``expected_sender`` is the 32-byte sender read from the **authenticated**
    ``SignedTxnInBlock`` (``avm_effectproof`` exposes it as ``Effects.sender``).
    Supplying it is what promotes the result to ``sender_bound``; omitting it is
    honest but weaker, and the returned ``reason`` says which you got.
    """
    content = _open_sealed(sealed)
    block = content.get(AC2_CONSENT_KEY)

    if block is None:
        if require:
            raise MeshError("sealed receipt carries no ac2_consent block")
        return {
            "level": LEVEL_NONE,
            "reason": "no ac2_consent block in the sealed content",
            "did": None,
            "sig_hint": None,
            "public_key_b64": None,
        }

    consent = ConsentAttestation.from_dict(block)
    settlement = content.get("settlement")
    if not isinstance(settlement, dict):
        raise MeshError(
            "sealed content carries an ac2_consent but no settlement to bind it to"
        )

    actual = consent_digest(settlement)
    if actual != consent.signed_payload_sha256:
        raise MeshError(
            "the consent was signed over a different settlement payload: consent "
            f"commits to {consent.signed_payload_sha256[:16]}..., this settlement "
            f"hashes to {actual[:16]}..."
        )

    public_key = _b64d(consent.public_key_b64, "public_key")
    signature = _b64d(consent.signature_b64, "signature")
    if len(public_key) != 32:
        raise MeshError(
            f"ac2_consent.public_key is {len(public_key)} bytes, not a 32-byte Ed25519 key"
        )
    if len(signature) != 64:
        raise MeshError(
            f"ac2_consent.signature is {len(signature)} bytes, not a 64-byte Ed25519 signature"
        )

    if not _ed25519_verify(public_key, consent_payload(settlement), signature):
        raise MeshError(
            "ac2 consent signature does not verify over this settlement's "
            "canonical payload"
        )

    level = LEVEL_CONSENT
    reason = (
        "the consent signature verifies over this settlement's canonical payload. "
        "It does NOT establish that a human approved, nor that a hardware passkey "
        "was used: an AC2 SigningResponse carries no WebAuthn authenticator data, "
        "clientDataJSON or credential id, so a verifier cannot distinguish a "
        "passkey from a software key."
    )

    if expected_sender is not None:
        if not isinstance(expected_sender, (bytes, bytearray)) or len(expected_sender) != 32:
            raise MeshError(
                "expected_sender must be the 32-byte sender read from the STIB"
            )
        if bytes(expected_sender) != public_key:
            # A 32-byte AVM address is EITHER an Ed25519 public key (a single-signature
            # account) OR a hash of a program (a logic signature) or of a multisig
            # preimage. Length cannot tell them apart, so a mismatch here has two
            # very different meanings and the message must not conflate them.
            raise MeshError(
                "the consent key is not the key that authorised this transaction: "
                f"consent signed with {base64.b64encode(public_key).decode()}, "
                f"transaction sender is {base64.b64encode(bytes(expected_sender)).decode()}. "
                "NOTE: sender binding is only meaningful when the payer is a "
                "single-signature account whose address IS its Ed25519 public key. "
                "If the payer is a multisig or a logic-sig account, its address is a "
                "hash and can never equal an Ed25519 key: such a payment cannot be "
                "sender-bound by this check and must not be presented as if it were."
            )
        level = LEVEL_SENDER
        reason = (
            "the consent key IS the authenticated transaction sender, so the approval "
            "and the payment come from one key and cannot be swapped. This still does "
            "not prove a hardware passkey was used (see consent_present), only that "
            "the payer signed this settlement."
        )

    return {
        "level": level,
        "reason": reason,
        "did": consent.did,
        "sig_hint": consent.sig_hint,
        "public_key_b64": consent.public_key_b64,
    }


def sender_from_bundle(bundle: dict, genesis_id: str) -> bytes:
    """The authenticated sender of the bundle's transaction.

    Only meaningful for a bundle that has already passed verification; the
    caller must not call this on unverified bytes and treat the result as fact.
    It is read from the same ``stib_bytes`` the receipt's attestation covers, so
    once verification has passed this is a fact about the chain, not a claim.
    """
    from .effects import _effects  # local import: avoids a cycle at import time

    try:
        return bytes(_effects(bundle, genesis_id).sender)
    except MeshError:
        raise
    except Exception as exc:
        raise MeshError(f"cannot read the settled transaction's sender: {exc}") from exc


def consent_level(sealed: dict, report: object = None, *,
                  bundle: dict | None = None,
                  expected_sender: bytes | None = None,
                  require: bool = False) -> dict:
    """Final level, combining the consent with the proofpack tier.

    ``report`` is a proofpack verification report. When its ``trust_root`` is
    ``stake_attested`` and the consent reached ``sender_bound``, the answer is
    ``consensus_bound``: the strongest claim this seam can support.

    When the settlement is attested but the consent is *not* sender-bound, the
    reason is extended to say so explicitly. Without that sentence a reader sees
    ``consensus_bound``-grade evidence beside a consent block and assumes the two
    were tied together when they were verified independently.

    CONTRACT, deliberately strict: passing ``bundle`` means "derive the sender
    from the authenticated transaction and bind to it". If the report cannot
    supply a ``genesis_id`` the sender is unknown, and this raises rather than
    returning the weaker ``consent_present``. A silent downgrade would answer a
    question the caller did not ask, and report it at a level that reads as if the
    binding had been attempted. Pass ``expected_sender`` explicitly if you have the
    sender from another source, or omit ``bundle`` to ask for consent-only.
    """
    if expected_sender is None and bundle is not None:
        genesis = getattr(report, "genesis_id", None)
        if not genesis:
            # Silently continuing here would report a weaker level without saying
            # why: the caller asked for sender binding implicitly by passing a
            # bundle, and got consent-only. Refuse instead, so the degradation is
            # never mistaken for the strong path.
            raise MeshError(
                "consent_level was given a bundle to derive the sender from, but the "
                "verification report carries no genesis_id, so the sender is unknown. "
                "Pass expected_sender explicitly or supply a report from "
                "avm_proofpack.verify."
            )
        expected_sender = sender_from_bundle(bundle, genesis)

    out = verify_consent(sealed, expected_sender=expected_sender, require=require)
    trust_root = getattr(report, "trust_root", None)
    if trust_root == "stake_attested":
        if out["level"] == LEVEL_SENDER:
            out["level"] = LEVEL_CONSENSUS
            out["reason"] += (
                "; and the settlement itself reached stake_attested against a "
                "pinned state-proof anchor"
            )
        elif out["level"] == LEVEL_CONSENT:
            out["reason"] += (
                "; the settlement is stake_attested but the consent is NOT bound "
                "to the sender, so the approval could be for a different payer"
            )
    return out
