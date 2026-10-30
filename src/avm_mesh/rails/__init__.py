"""Adoption kit for the AlgoVoi Payment Rails receipt format.

The rails ship a standalone verifier (`verify_settlement_receipt.py`) that checks
two levels: integrity over the exact canonical bytes, and the operator's
Falcon-1024 signature over the content hash. This package verifies the same wire
format and adds LEVEL 3 -- evidence authenticated against Algorand/Voi consensus.

It is an ADAPTER, not a second implementation. The rules live once, in
:mod:`avm_mesh.sealed` and :mod:`avm_mesh.attestation`; this module only maps the
rails naming onto them and enforces the rails-specific expectations. Two
implementations of the same verification rules is how the two drift apart and how
one of them ends up weaker.
"""
from .verifier import REQUIRED_FOR_LEVEL3, verify_rails_receipt

__all__ = ["REQUIRED_FOR_LEVEL3", "verify_rails_receipt"]
