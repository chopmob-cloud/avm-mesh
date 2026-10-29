"""Settlement receipts: digest + pointer, never an inlined bundle.

Three properties matter, and each is enforced rather than documented:

1. SUBSTITUTION. The receipt commits to the bundle by SHA-256 over canonical
   JSON. Swapping the bundle behind a pointer changes the digest.
2. UPGRADE. The receipt carries the trust tier the bundle EARNED. A verifier
   re-derives the tier and refuses a mismatch in either direction, so a
   structural bundle cannot be advertised as stake_attested.
3. IDENTITY. The receipt's chain/txid/round must match the bundle's. A valid
   bundle for a different transaction is not evidence for this one.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

RECEIPT_VERSION = 1
VALID_TIERS = ("stake_attested", "corroborated", "structural", "unattested")


class MeshError(Exception):
    """Raised on any malformed or dishonest receipt. Never returns a pass."""


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def bundle_digest(bundle: dict) -> str:
    """SHA-256 over the canonical form of the bundle."""
    if not isinstance(bundle, dict):
        raise MeshError("bundle must be an object")
    return hashlib.sha256(_canonical(bundle)).hexdigest()


@dataclass(frozen=True)
class ProofpackPointer:
    """Where the bundle lives, and which bundle it is."""
    uri: str
    digest: str
    first_attested_round: int
    last_attested_round: int

    def __post_init__(self) -> None:
        if not isinstance(self.uri, str) or not self.uri:
            raise MeshError("pointer uri must be a non-empty string")
        if not isinstance(self.digest, str) or len(self.digest) != 64:
            raise MeshError("pointer digest must be a 64-char sha256 hex digest")
        try:
            int(self.digest, 16)
        except ValueError as exc:
            raise MeshError("pointer digest is not hexadecimal") from exc
        if self.first_attested_round > self.last_attested_round:
            raise MeshError("pointer interval is inverted")

    def to_dict(self) -> dict:
        return {
            "uri": self.uri,
            "digest": self.digest,
            "first_attested_round": self.first_attested_round,
            "last_attested_round": self.last_attested_round,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "ProofpackPointer":
        if not isinstance(data, dict):
            raise MeshError("pointer must be an object")
        try:
            return cls(
                uri=data["uri"],
                digest=data["digest"],
                first_attested_round=int(data["first_attested_round"]),
                last_attested_round=int(data["last_attested_round"]),
            )
        except KeyError as exc:
            raise MeshError(f"pointer missing field {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise MeshError(f"pointer has an unusable field: {exc}") from exc


@dataclass(frozen=True)
class SettlementReceipt:
    version: int
    chain: str
    txid: str
    round: int
    trust_root: str
    pointer: ProofpackPointer
    #: Who observed this settlement. A CAPTURE-TIME property: it cannot be
    #: established later, and it must never be read as quorum unless the
    #: witnesses are independent operators.
    corroboration: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.version != RECEIPT_VERSION:
            raise MeshError(f"unsupported receipt version {self.version}")
        if self.trust_root not in VALID_TIERS:
            raise MeshError(f"unknown trust tier {self.trust_root!r}")
        if not isinstance(self.txid, str) or not self.txid:
            raise MeshError("txid must be a non-empty string")
        if not isinstance(self.chain, str) or not self.chain:
            raise MeshError("chain must be a non-empty string")

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "chain": self.chain,
            "txid": self.txid,
            "round": self.round,
            "trust_root": self.trust_root,
            "pointer": self.pointer.to_dict(),
            "corroboration": list(self.corroboration),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "SettlementReceipt":
        if not isinstance(data, dict):
            raise MeshError("receipt must be an object")
        try:
            return cls(
                version=int(data["version"]),
                chain=data["chain"],
                txid=data["txid"],
                round=int(data["round"]),
                trust_root=data["trust_root"],
                pointer=ProofpackPointer.from_dict(data["pointer"]),
                corroboration=tuple(data.get("corroboration") or ()),
            )
        except KeyError as exc:
            raise MeshError(f"receipt missing field {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise MeshError(f"receipt has an unusable field: {exc}") from exc


def _verify_bundle_dict(bundle: dict, trusted_voters=None):
    from avm_proofpack.bundle import Bundle
    from avm_proofpack.verify import verify_bundle

    return verify_bundle(Bundle.from_dict(bundle), trusted_voters=trusted_voters)


def create_receipt(bundle: dict, uri: str, corroboration: tuple[str, ...] = (), *,
                   trusted_voters: Any = None) -> SettlementReceipt:
    """Build a receipt from a bundle, recording the tier the bundle EARNS.

    The tier, chain, txid and round all come from verification rather than from
    the caller or from trusting the bundle's own claims, so a receipt cannot
    assert a strength or an identity its bundle does not support.
    """
    report = _verify_bundle_dict(bundle, trusted_voters)
    return SettlementReceipt(
        version=RECEIPT_VERSION,
        chain=report.genesis_id,
        txid=report.txid,
        round=report.round,
        trust_root=report.trust_root,
        pointer=ProofpackPointer(
            uri=uri,
            digest=bundle_digest(bundle),
            first_attested_round=report.first_attested_round,
            last_attested_round=report.last_attested_round,
        ),
        corroboration=tuple(corroboration),
    )


def verify_receipt(receipt: SettlementReceipt | dict,
                   resolve: Callable[[str], dict],
                   *, expected_chain: str | None = None,
                   witness_set: Any = None,
                   corroboration_threshold: int = 0,
                   trusted_voters: Any = None) -> Any:
    """Resolve the pointer, prove the bundle is the one committed to, verify it.

    Returns the proofpack verification report. Raises MeshError on any mismatch.
    `resolve` is supplied by the caller so this stays storage-agnostic: a file,
    an HTTP endpoint or a chain all work.

    Pass `witness_set` (and a `corroboration_threshold`) to make the receipt's
    corroboration claim checkable. Without it the claim is recorded evidence, not
    established evidence, and the caller should say so.
    """
    if isinstance(receipt, dict):
        receipt = SettlementReceipt.from_dict(receipt)
    if not isinstance(receipt, SettlementReceipt):
        raise MeshError("receipt must be a SettlementReceipt")

    if expected_chain is not None and receipt.chain != expected_chain:
        raise MeshError(
            f"receipt is for chain {receipt.chain!r}, verifier expected {expected_chain!r}"
        )

    try:
        bundle = resolve(receipt.pointer.uri)
    except MeshError:
        raise
    except Exception as exc:
        raise MeshError(f"could not resolve {receipt.pointer.uri!r}: {exc}") from exc

    if not isinstance(bundle, dict):
        raise MeshError("resolver returned something that is not a bundle")

    actual = bundle_digest(bundle)
    if actual != receipt.pointer.digest:
        raise MeshError(
            f"bundle digest mismatch: receipt commits to {receipt.pointer.digest[:16]}..., "
            f"resolved bundle hashes to {actual[:16]}..."
        )

    try:
        report = _verify_bundle_dict(bundle, trusted_voters)
    except Exception as exc:
        raise MeshError(f"bundle failed verification: {exc}") from exc

    if report.txid != receipt.txid or report.round != receipt.round:
        raise MeshError("resolved bundle is evidence for a different settlement")
    if report.genesis_id != receipt.chain:
        raise MeshError(
            f"resolved bundle is for chain {report.genesis_id!r}, receipt says {receipt.chain!r}"
        )

    if witness_set is not None or corroboration_threshold > 0:
        from .bond import BondError, validate_corroboration

        if witness_set is None:
            raise MeshError(
                "a corroboration threshold was set but no witness_set was supplied"
            )
        try:
            validate_corroboration(
                receipt.corroboration, witness_set,
                receipt.chain,
                max(1, corroboration_threshold),
            )
        except BondError as exc:
            raise MeshError(f"corroboration not established: {exc}") from exc

    if report.trust_root != receipt.trust_root:
        raise MeshError(
            f"trust tier mismatch: receipt claims {receipt.trust_root!r}, "
            f"bundle earns {report.trust_root!r}"
        )
    return report
