# The Falcon-1024 dependency: why `pqcrypto` stopped working

A postmortem and a decision record, written because this broke a shipped verifier and will otherwise
break again.

## What happened

`pip install pqcrypto` used to provide `pqcrypto.sign.falcon_1024.verify`. On **pqcrypto 1.0.0** it does
not, and the import fails:

```
ModuleNotFoundError: No module named 'pqcrypto.sign.falcon_1024'
```

## Why — it is a rewrite, not a security removal

Upstream, in [backbone-hq/pqcrypto issue #21](https://github.com/backbone-hq/pqcrypto/issues/21):

> "Per issue #604 in the PQClean repo, PQClean will be deprecated and archived as read-only in July 2026,
> so no new algorithms will be added, nor will security vulnerabilities be addressed."

> "With the advent of pqcrypto 1.0.0, we've successfully migrated away from PQClean implementations to our
> own pqcrypto implementations; supporting both NIST-standardized and competing algorithms and their
> variants."

Versions 0.x wrapped PQClean's C through CFFI. Version 1.0.0 replaces that with a single Rust extension
built with PyO3. The shipped API on a current install is, verified locally by inspecting `dir(pqcrypto)`:

```
ml_kem_512/768/1024      ml_dsa_44/65/87        slh_dsa_sha2_*  slh_dsa_shake_*
mceliece_*               hqc_128/192/256        sntrup_*
```

No `falcon` of any kind. The new surface is the NIST-**finalised** schemes — ML-KEM (FIPS 203), ML-DSA
(FIPS 204), SLH-DSA (FIPS 205) — plus KEM candidates. Falcon's standardised form, **FN-DSA (FIPS 206)**,
is still a draft.

The maintainer's own caveat, quoted because it matters for anyone relying on 1.0.0:

> "here be dragons; none of these implementations have been audited by a third party."

## Why we cannot simply switch algorithms

The obvious response — "use ML-DSA instead" — is not available to us. **Algorand and Voi sign their
consensus state with Falcon-1024.** It is part of the protocol, not a design choice on our side. Switching
algorithm would mean being unable to verify a state proof at all, which is the entire product.

So the question is not *which algorithm*, but *which implementation*.

## Decision

**Verify Falcon-1024 with `avm_proofpack.consensus.falcon.falcon1024_verify`.**

```python
from avm_proofpack.consensus.falcon import falcon1024_verify
ok = falcon1024_verify(public_key, message, signature)   # returns bool, does not raise
```

Reasons:

- **stdlib-only** — no third-party package in the trust base at all, so this cannot break the same way.
- **Already exercised against real data**: it verified 71/71 live mainnet state-proof signatures, and
  rejects a changed message or a different key.
- **KAT-verified**: `tests/falcon_kat/falcon1024_det_kat.json` in `avm-proofpack` pins it to reference
  vectors.
- It implements the variant Algorand actually uses — deterministic, salted
  (`HEADER_DET_COMPRESSED`, `_det_salt`), not the randomised form.

## Rejected alternatives

| Option | Why not |
|---|---|
| `pqcrypto>=0.3,<1.0` | Works today, but its upstream (PQClean) is archived with **no security fixes**, and the pin rots silently. Acceptable only as a temporary stopgap. |
| `qcrypto` (liboqs bindings) | Exposes Falcon-512/1024, but as the randomised variant. Algorand's signatures are deterministic and salted, so a generic implementation is **likely** incompatible. Hypothesis, not tested here — if you want to use it, prove it against the KAT vectors first. |
| `pip install pqcrypto` unpinned | Broken at import today. This is the failure being documented. |

## Where this matters

1. **`avm-mesh`** — `cli._make_signature_verifier` uses the `avm_proofpack` verifier. No `pqcrypto`
   import anywhere; `tests/test_level2_real_falcon.py` asserts that, and exercises the primitive against
   genuine KAT vectors.
2. **The AlgoVoi Payment Rails bundle** — `live-install/verify_settlement_receipt.py` still imports
   `pqcrypto.sign.falcon_1024`. Any customer following its documented install instruction gets a verifier
   that fails on import. It needs the same change before the next cut.

## Residual risk, stated plainly

- The **signer** side of LEVEL 2 is unexercised here: no Falcon-1024 *signing* implementation is
  installable in this environment (`pqcrypto` 1.0.0 dropped it; there is no 0.9.x build on this platform).
  An operator signing a receipt with their own toolchain is the only way to close it, and that belongs in
  their acceptance test.
- `avm_proofpack.consensus.falcon` is our own code. It is tested against KAT vectors and live signatures,
  but it has not had an independent cryptographic audit. It is **unaudited** by a third party. That is a
  different assurance level from a well-reviewed library, and should be stated as such in customer
  material.
