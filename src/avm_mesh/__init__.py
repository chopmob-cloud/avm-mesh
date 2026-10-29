"""avm-mesh -- settlement receipts.

A receipt is what moves between meshes. It is deliberately small: a digest,
a pointer to a proofpack, and the trust tier that proofpack actually earned.
The bundle itself is stored once per attested interval, never per transaction.
"""
from .attestation import ConsensusAttestation, attest, verify_attestation
from . import a2a
from .sealed import seal, verify_sealed
from .receipt import (
    MeshError,
    ProofpackPointer,
    SettlementReceipt,
    create_receipt,
    verify_receipt,
)

__all__ = [
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
__version__ = "0.1.1"
