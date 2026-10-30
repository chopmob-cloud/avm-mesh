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


def load_policy(path: str) -> TrustPolicy:
    with open(path, "r", encoding="utf-8") as f:
        return TrustPolicy.from_dict(json.load(f))


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
