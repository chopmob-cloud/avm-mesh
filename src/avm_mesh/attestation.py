"""LEVEL 3: consensus attestation for a settlement receipt.

The rails receipt has two levels:

    LEVEL 1  integrity     sha256(canonical_bytes) == content_hash
    LEVEL 2  authenticity  the OPERATOR's Falcon-1024 signature over that hash

LEVEL 2 is signed by AlgoVoi, so it proves "the operator issued this receipt".
It cannot prove the settlement happened as described, because the operator
could sign anything. LEVEL 3 closes that: evidence that the transaction was
final, authenticated against the chain's own consensus -- and against a
*trusted voters anchor the verifier supplies*, never one the bundle asserts.

WHY THE ANCHOR IS MANDATORY (scheme v2). An earlier version of this module
derived the signing set from the bundle's own `previous_state_proof_message`.
That was forgeable: a bundle author chooses that field, so they could name
themselves as the only signer and mint a valid-looking stake_attested tier.
avm-proofpack 0.4.1 fixed this by requiring a caller-supplied
`TrustedVoters` anchor; v2 here follows. The scheme string is bumped because
v1 attestations must not be accepted as if they meant the same thing.

Obtain the anchor independently: walk the chain of state proofs from a pinned
genesis bootstrap (avm_proofpack.consensus.chain), or take it from a node you
already trust at a known round. Never read it out of the bundle you are
verifying.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Callable

from .receipt import MeshError, bundle_digest

SCHEME = "avm-stateproof-falcon1024-v2"
# Chains that carry Falcon-1024 state-proof consensus, so a receipt for them can
# reach stake_attested. testnet-v1.0 is Algorand testnet, which genuinely emits
# state proofs (confirmed against a live testnet node); it is admitted so the
# proof-of-concept can run on real testnet evidence. Admitting it does NOT let a
# testnet attestation pass where mainnet is expected: verify_attestation binds the
# genesis hash to the authenticated header, so a verifier that pins the mainnet
# genesis rejects a testnet proof. Testnet consensus is testnet-grade security, not
# mainnet-grade, and a caller must still pin the genesis it actually trusts.
SUPPORTED_CHAINS = ("mainnet-v1.0", "voimain-v1.0", "testnet-v1.0")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


@dataclass(frozen=True)
class ConsensusAttestation:
    """Evidence that a settlement was final, anchored in chain consensus.

    `anchor_voters_commitment_b64` and `anchor_ln_proven_weight` name the
    anchor the attestation was built against. The verifier must supply the
    same anchor independently and it must match; carrying it here makes the
    claim auditable, not self-certifying.
    """
    scheme: str
    chain: str
    genesis_hash_b64: str
    txid: str
    round: int
    trust_root: str
    evidence_uri: str
    evidence_digest: str
    first_attested_round: int
    last_attested_round: int
    anchor_voters_commitment_b64: str
    anchor_ln_proven_weight: int

    def __post_init__(self) -> None:
        if self.scheme != SCHEME:
            raise MeshError(
                f"unsupported attestation scheme {self.scheme!r}; "
                f"v1 attestations were forgeable and are refused"
            )
        if self.chain not in SUPPORTED_CHAINS:
            raise MeshError(
                f"chain {self.chain!r} has no state-proof consensus; "
                f"supported: {', '.join(SUPPORTED_CHAINS)}"
            )
        if self.trust_root != "stake_attested":
            raise MeshError(
                f"a consensus attestation must be stake_attested; got {self.trust_root!r}"
            )
        try:
            gh = _unb64(self.genesis_hash_b64)
            vc = _unb64(self.anchor_voters_commitment_b64)
        except Exception as exc:
            raise MeshError("genesis hash or voters commitment is not valid base64") from exc
        if len(gh) != 32:
            raise MeshError("genesis hash must be 32 bytes")
        if len(vc) != 64:
            raise MeshError("voters commitment must be 64 bytes")
        if self.anchor_ln_proven_weight < 0:
            raise MeshError("anchor proven weight cannot be negative")

    def to_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "chain": self.chain,
            "genesis_hash_b64": self.genesis_hash_b64,
            "txid": self.txid,
            "round": self.round,
            "trust_root": self.trust_root,
            "evidence_uri": self.evidence_uri,
            "evidence_digest": self.evidence_digest,
            "first_attested_round": self.first_attested_round,
            "last_attested_round": self.last_attested_round,
            "anchor_voters_commitment_b64": self.anchor_voters_commitment_b64,
            "anchor_ln_proven_weight": self.anchor_ln_proven_weight,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "ConsensusAttestation":
        if not isinstance(data, dict):
            raise MeshError("consensus_attestation must be an object")
        try:
            return cls(
                scheme=data["scheme"],
                chain=data["chain"],
                genesis_hash_b64=data["genesis_hash_b64"],
                txid=data["txid"],
                round=int(data["round"]),
                trust_root=data["trust_root"],
                evidence_uri=data["evidence_uri"],
                evidence_digest=data["evidence_digest"],
                first_attested_round=int(data["first_attested_round"]),
                last_attested_round=int(data["last_attested_round"]),
                anchor_voters_commitment_b64=data["anchor_voters_commitment_b64"],
                anchor_ln_proven_weight=int(data["anchor_ln_proven_weight"]),
            )
        except KeyError as exc:
            raise MeshError(f"attestation missing field {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise MeshError(f"attestation has an unusable field: {exc}") from exc


def attest(bundle: dict, uri: str, *, trusted_voters: Any) -> ConsensusAttestation:
    """Build a LEVEL 3 block from a proofpack, or refuse.

    `trusted_voters` is the caller's anchor (avm_proofpack.TrustedVoters).
    It is required: without it the evidence cannot reach stake_attested, and
    emitting a weaker block would let a receipt *look* consensus-backed while
    carrying an operator's word.
    """
    from avm_proofpack.bundle import Bundle
    from avm_proofpack.verify import verify_bundle

    if trusted_voters is None:
        raise MeshError(
            "a trusted voters anchor is required for LEVEL 3; derive one from a "
            "pinned genesis bootstrap or a chain walk, never from this bundle"
        )
    if not isinstance(bundle, dict):
        raise MeshError("bundle must be an object")

    try:
        report = verify_bundle(Bundle.from_dict(bundle), trusted_voters=trusted_voters)
    except Exception as exc:
        raise MeshError(f"evidence failed verification: {exc}") from exc
    if report.trust_root != "stake_attested":
        raise MeshError(
            f"evidence earns {report.trust_root!r}, not stake_attested"
        )
    return ConsensusAttestation(
        scheme=SCHEME,
        chain=report.genesis_id,
        genesis_hash_b64=report.genesis_hash_b64,
        txid=report.txid,
        round=report.round,
        trust_root=report.trust_root,
        evidence_uri=uri,
        evidence_digest=bundle_digest(bundle),
        first_attested_round=report.first_attested_round,
        last_attested_round=report.last_attested_round,
        anchor_voters_commitment_b64=_b64(bytes(trusted_voters.voters_commitment)),
        anchor_ln_proven_weight=int(trusted_voters.ln_proven_weight),
    )


def verify_attestation(attestation: ConsensusAttestation | dict,
                       resolve: Callable[[str], dict],
                       *, trusted_voters: Any,
                       expected_genesis_hash_b64: str | None = None) -> Any:
    """Check LEVEL 3 against a caller-supplied anchor. Returns the report.

    The anchor is required and must match the one recorded in the
    attestation. Passing the attestation's own anchor back to it would verify
    nothing: the claim would certify itself.
    """
    if isinstance(attestation, dict):
        attestation = ConsensusAttestation.from_dict(attestation)
    if not isinstance(attestation, ConsensusAttestation):
        raise MeshError("attestation must be a ConsensusAttestation")
    if trusted_voters is None:
        raise MeshError("a trusted voters anchor is required to check LEVEL 3")

    recorded_vc = _b64(bytes(trusted_voters.voters_commitment))
    if recorded_vc != attestation.anchor_voters_commitment_b64:
        raise MeshError(
            "anchor mismatch: the attestation was built against a different "
            "voters commitment than the one you trust"
        )
    if int(trusted_voters.ln_proven_weight) != attestation.anchor_ln_proven_weight:
        raise MeshError("anchor mismatch: proven weight differs from the attestation")

    expected_gh_bytes: bytes | None = None
    if expected_genesis_hash_b64 is not None:
        if attestation.genesis_hash_b64 != expected_genesis_hash_b64:
            raise MeshError(
                "genesis hash mismatch: attestation is anchored to a different chain"
            )
        try:
            expected_gh_bytes = _unb64(expected_genesis_hash_b64)
        except Exception as exc:
            raise MeshError("expected genesis hash is not valid base64") from exc

    # evidence_uri is a LOCATOR, not a security binding: it only tells the
    # caller's resolver where to look. It is deliberately not checked against
    # any verified value -- there is none to check it against -- because the
    # integrity binding is the digest below. Whatever the URI points at, only a
    # bundle hashing to evidence_digest passes, so the URI cannot substitute
    # evidence. URI policy (which schemes/hosts are acceptable) belongs to the
    # resolver the caller supplies.
    try:
        bundle = resolve(attestation.evidence_uri)
    except MeshError:
        raise
    except Exception as exc:
        raise MeshError(f"could not resolve evidence {attestation.evidence_uri!r}: {exc}") from exc
    if not isinstance(bundle, dict):
        raise MeshError("resolver returned something that is not a proofpack")

    actual = bundle_digest(bundle)
    if actual != attestation.evidence_digest:
        raise MeshError(
            f"evidence digest mismatch: attestation commits to "
            f"{attestation.evidence_digest[:16]}..., evidence hashes to {actual[:16]}..."
        )

    from avm_proofpack.bundle import Bundle
    from avm_proofpack.verify import verify_bundle

    # Pass the pin down so avm-proofpack enforces it against the *authenticated*
    # block header ('gh' is inside the signed header), not against a field the
    # evidence author chose. Without this the pin would only ever be compared to
    # the attestation's own self-asserted genesis_hash_b64 above.
    try:
        report = verify_bundle(
            Bundle.from_dict(bundle),
            trusted_voters=trusted_voters,
            expected_genesis_hash=expected_gh_bytes,
        )
    except Exception as exc:
        raise MeshError(f"evidence failed verification: {exc}") from exc

    if report.trust_root != "stake_attested":
        raise MeshError(f"evidence earns {report.trust_root!r}, not stake_attested")
    if report.txid != attestation.txid or report.round != attestation.round:
        raise MeshError("evidence attests a different settlement")
    if report.genesis_id != attestation.chain:
        raise MeshError("evidence is for a different chain")
    # Bind the recorded genesis hash to the one the evidence actually
    # authenticates to. This ties the attestation's genesis_hash_b64 field (and
    # therefore any pin checked against it) to verified data rather than to
    # metadata the bundle author supplied.
    if report.genesis_hash_b64 != attestation.genesis_hash_b64:
        raise MeshError(
            "genesis hash mismatch: attestation records a genesis hash the "
            "evidence does not authenticate to"
        )
    # Bind the claimed attested interval to the one the evidence actually
    # attests. LEVEL 3 exists precisely so the operator who sealed this is NOT
    # trusted; without this check that operator could advertise an interval the
    # evidence does not cover and still verify -- the same gap verify_receipt
    # already closes on its pointer interval.
    if (report.first_attested_round, report.last_attested_round) != (
            attestation.first_attested_round, attestation.last_attested_round):
        raise MeshError(
            f"attested interval mismatch: attestation says "
            f"[{attestation.first_attested_round}, {attestation.last_attested_round}], "
            f"evidence attests [{report.first_attested_round}, {report.last_attested_round}]"
        )
    return report
