"""Trust policy: the file a deployment owns, instead of scattered arguments.

Everything a verifier must pin is one document: which chain, which genesis hash,
which voters anchor, which witnesses have bonds, and how many independent ones
are needed. Shipping that as data rather than as code means an operator can
audit and diff it, and means a verifier cannot quietly relax one pin because it
was passed as a default somewhere else.

The policy is deliberately NOT self-verifying. It is the root of the deployment's
trust, so it arrives by whatever means the operator trusts -- a container image,
a config-management system, a signed release. What matters is that every pin it
states is enforced, not that it is signed by us.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

from .bond import Witness, WitnessSet, witnesses
from .receipt import MeshError, verify_receipt


@dataclass(frozen=True)
class TrustPolicy:
    chain: str
    genesis_hash_b64: str
    anchor_voters_commitment_b64: str
    anchor_ln_proven_weight: int
    witnesses: WitnessSet
    corroboration_threshold: int = 0

    def __post_init__(self) -> None:
        if not self.chain:
            raise MeshError("policy chain is required")
        try:
            gh = base64.b64decode(self.genesis_hash_b64.encode("ascii"), validate=True)
            vc = base64.b64decode(self.anchor_voters_commitment_b64.encode("ascii"),
                                  validate=True)
        except Exception as exc:
            raise MeshError("policy genesis hash or voters commitment is not base64") from exc
        if len(gh) != 32:
            raise MeshError("policy genesis hash must be 32 bytes")
        if len(vc) != 64:
            raise MeshError("policy voters commitment must be 64 bytes")
        if self.anchor_ln_proven_weight < 0:
            raise MeshError("policy proven weight cannot be negative")
        if self.corroboration_threshold < 0:
            raise MeshError("policy threshold cannot be negative")

    # -- serialisation ---------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "chain": self.chain,
            "genesis_hash_b64": self.genesis_hash_b64,
            "anchor_voters_commitment_b64": self.anchor_voters_commitment_b64,
            "anchor_ln_proven_weight": self.anchor_ln_proven_weight,
            "corroboration_threshold": self.corroboration_threshold,
            "witnesses": [
                {
                    "witness_id": w.witness_id,
                    "operator_id": w.operator_id,
                    "chain": w.chain,
                    "bond_microalgo": w.bond_microalgo,
                    "escrow_txid": w.escrow_txid,
                    "active": w.active,
                }
                for w in self.witnesses.witnesses
            ],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "TrustPolicy":
        if not isinstance(data, dict):
            raise MeshError("policy must be an object")
        try:
            raw = data.get("witnesses") or []
            if not isinstance(raw, list):
                raise MeshError("policy witnesses must be a list")
            return cls(
                chain=data["chain"],
                genesis_hash_b64=data["genesis_hash_b64"],
                anchor_voters_commitment_b64=data["anchor_voters_commitment_b64"],
                anchor_ln_proven_weight=int(data["anchor_ln_proven_weight"]),
                witnesses=witnesses(*raw),
                corroboration_threshold=int(data.get("corroboration_threshold") or 0),
            )
        except KeyError as exc:
            raise MeshError(f"policy missing field {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise MeshError(f"policy has an unusable field: {exc}") from exc

    # -- derived ---------------------------------------------------------
    def trusted_voters(self):
        """Build the avm-proofpack anchor this policy describes."""
        from avm_proofpack.verify import TrustedVoters

        return TrustedVoters(
            voters_commitment=base64.b64decode(self.anchor_voters_commitment_b64),
            ln_proven_weight=self.anchor_ln_proven_weight,
        )

    def require_witness_coverage(self) -> None:
        """Refuse a policy that asks for corroboration it cannot deliver.

        A threshold above the number of independent bonded witnesses would fail
        every verification at runtime, long after the deployment looked healthy.
        """
        if self.corroboration_threshold <= 0:
            return
        independent = self.witnesses.independent_corroborators(self.chain)
        if len(independent) < self.corroboration_threshold:
            raise MeshError(
                f"policy asks for {self.corroboration_threshold} independent witnesses "
                f"but only {len(independent)} are bonded on {self.chain}"
            )


#: A policy is a small document of pins: a chain, a genesis hash, an anchor and a witness
#: set. 256 KiB is far more than that shape needs and still bounds a file a stranger hands
#: you. The receipt and proofpack readers were bounded in earlier releases and this one was
#: missed -- the same defect shape each time: the guard was written for the path someone was
#: thinking about rather than for the category.
MAX_POLICY_BYTES = 256 * 1024


def load_policy(path: str) -> TrustPolicy:
    """Read a policy document, refusing one larger than MAX_POLICY_BYTES.

    Bounded before parse rather than after: the document is measured on the descriptor it
    will be read from, so a file over the cap is refused without ever being loaded. Note
    that "never build the string" is true of the *raw bytes* and not of the decoded text —
    decoding happens after the size check and does allocate, which is the point of checking
    first.

    One descriptor for both the measurement and the read. The earlier version called
    `stat()` on the path and then `read_bytes()` on the path again, which is two opens: a
    file swapped in between would be read without ever having been measured, and the
    post-read check only catches growth. `fstat` on the same handle closes that window, and
    the read is bounded by the descriptor's own size.

    Opened "rb" so a text-mode descriptor cannot stop at a 0x1A byte on Windows and hand
    back a truncated document that happens to parse.
    """
    target = pathlib.Path(path)
    # OSError is deliberately NOT wrapped. A missing or unreadable file is an I/O
    # condition, and `tests/test_fail_closed.py` pins that it surfaces as OSError so a
    # caller can tell "not there" from "malformed". The suite's contract is that
    # MALFORMED input raises MeshError -- not that every failure does. Wrapping this was
    # my change and it broke that pin, which the clean room caught on both interpreters.
    with open(target, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        if size > MAX_POLICY_BYTES:
            raise MeshError(
                f"policy {path} is {size} bytes, over the {MAX_POLICY_BYTES} byte cap")
        # Read one byte past the cap so a file that grew after fstat is still refused,
        # and so the read can never exceed the bound it was checked against.
        raw = handle.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        raise MeshError(
            f"policy {path} is larger than the {MAX_POLICY_BYTES} byte cap")
    try:
        return TrustPolicy.from_dict(json.loads(raw.decode("utf-8-sig")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MeshError(f"policy {path} is not valid UTF-8 JSON: {exc}") from exc


def verify_with_policy(receipt, resolve, policy: TrustPolicy):
    """Verify a receipt against every pin in the policy at once."""
    if not isinstance(policy, TrustPolicy):
        raise MeshError("verify_with_policy needs a TrustPolicy")
    if receipt.chain != policy.chain:
        raise MeshError(
            f"receipt is for chain {receipt.chain!r}, policy is for {policy.chain!r}"
        )
    return verify_receipt(
        receipt,
        resolve,
        trusted_voters=policy.trusted_voters(),
        expected_chain=policy.chain,
        expected_genesis_hash_b64=policy.genesis_hash_b64,
        witness_set=policy.witnesses if policy.corroboration_threshold else None,
        corroboration_threshold=policy.corroboration_threshold,
    )
