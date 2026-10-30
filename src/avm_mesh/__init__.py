"""avm-mesh -- settlement receipts.

A receipt is what moves between meshes. It is deliberately small: a digest,
a pointer to a proofpack, and the trust tier that proofpack actually earned.
The bundle itself is stored once per attested interval, never per transaction.
"""
from .attestation import ConsensusAttestation, attest, verify_attestation
from . import a2a, produce, service, trust
from .produce import produce as produce_receipt
from .service import Store, WitnessInfo
from .trust import TrustPolicy, load_policy, verify_with_policy
from .sealed import seal, verify_sealed
from .receipt import (
    MeshError,
    ProofpackPointer,
    SettlementReceipt,
    create_receipt,
    verify_receipt,
)

__all__ = [
    "produce",
    "service",
    "trust",
    "produce_receipt",
    "Store",
    "WitnessInfo",
    "TrustPolicy",
    "load_policy",
    "verify_with_policy",
    "a2a",
    "seal",
    "verify_sealed",
    "ConsensusAttestation",
    "attest",
    "verify_attestation",
    "MeshError",
    "ProofpackPointer",
    "SettlementReceipt",
    "create_receipt",
    "verify_receipt",
]
__version__ = "0.2.0"
