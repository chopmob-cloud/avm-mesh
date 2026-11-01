# Adopting LEVEL 3 in the Payment Rails bundle

For whoever cuts the next rails build. Short version: delete one import, add this package, and change what
you tell customers.

## What the shipped verifier does today

`live-install/verify_settlement_receipt.py` checks two levels against the receipt's exact canonical bytes:

| Level | Check | Trust root |
|---|---|---|
| 1 | `sha256(canonical_bytes) == content_hash` | — |
| 2 | the **operator's** Falcon-1024 signature over that hash | AlgoVoi |

That is a sound design, and the decision to ship the canonical bytes so no JSON canonicaliser is needed was
right — it keeps the standalone verifier small.

Two problems with it, one of which is live **today**:

1. **It imports `pqcrypto`.** `pqcrypto` 1.0.0 removed Falcon entirely when PQClean was archived, so a
   customer following the documented `pip install pqcrypto` gets
   `ModuleNotFoundError: No module named 'pqcrypto.sign.falcon_1024'`. See `docs/PQC-FALCON.md`.
2. **LEVEL 2 proves who spoke, not what happened.** The operator signs the receipt, so the operator could
   sign anything. There is no evidence that the settlement occurred as described.

## What to change

### 1. Replace the Falcon import

```python
# remove
from pqcrypto.sign.falcon_1024 import verify as falcon_verify

# use instead -- stdlib-only, KAT-verified, 71/71 live mainnet signatures
from avm_proofpack.consensus.falcon import falcon1024_verify
```

`falcon1024_verify(public_key, message, signature)` **returns a bool**; it does not raise on a bad
signature. Check the return value, or every signature reads as valid.

### 2. Verify with the kit instead of the local implementation

```python
from avm_mesh.rails import verify_rails_receipt

result = verify_rails_receipt(
    receipt,
    resolve=my_storage.read,                       # maps evidence_uri -> proofpack
    operator_pubkey_b64=operator_pubkey_b64,       # LEVEL 2
    trusted_voters=anchor,                         # LEVEL 3, required for it
    expected_genesis_hash_b64=PINNED_GENESIS,      # strongly recommended
)

print(result["trust_root"])            # "stake_attested" | "structural"
print(result["levels"])                # integrity / signature / consensus, separately
```

The wire format is unchanged — same `canonical_bytes_b64`, same `content_hash`, same optional
`signature`. The consensus attestation lives **inside** the canonical bytes under `consensus_attestation`,
so it is covered by LEVEL 1 and cannot be swapped or stripped without breaking the hash.

Levels are reported separately and never collapsed: a caller must be able to see whether it is trusting the
operator, the chain, or neither. A signature present without a public key reports
`"present-unverified"` rather than being called valid.

### 3. Carry three wheels, not one

`avm-mesh`, `avm-proofpack` and `avm-effectproof` — all stdlib-only, all pure `py3-none-any`. Net effect:
`pqcrypto` (a compiled, now-broken dependency) is removed and replaced by auditable source. The
licence/extraction flow must include them.

## The customer-facing statement must change

Today:

> "no AlgoVoi software in your trust base"

After LEVEL 3:

> "you trust Algorand/Voi consensus, plus an auditable verifier you can read"

This is **stronger** — the operator can no longer forge the settlement — but it is **different**, and it is
not a changelog line. A customer who bought "no AlgoVoi software" is being asked to accept two AlgoVoi
packages in their trust base instead. That is defensible (they are readable source, not a service call),
but it must be stated plainly, and the unaudited status of our Falcon verifier should be disclosed
alongside it.

Alternative if that is unacceptable for a given customer: keep LEVEL 2 only, pin `pqcrypto<1.0`, and accept
that PQClean receives no further security fixes. That is a real option, not a rhetorical one.

## Exact compatibility notes (read these before swapping)

These came from reading the shipped `verify_settlement_receipt.py` line by line. Each one, got wrong,
produces a verifier that passes its own tests and rejects every genuine receipt.

**1. The signature payload is the hex digest, encoded UTF-8.**

```python
# what the rails actually do
falcon_verify(pk, hashlib.sha256(cb).hexdigest().encode("utf-8"), sig)   # 64 ASCII bytes
# NOT the raw digest
falcon_verify(pk, hashlib.sha256(cb).digest(), sig)                      # 32 bytes -- wrong
```

**2. The receipt embeds the operator's public key** in `public_key_b64`. That is useful for offline
verification and dangerous as a trust signal: whoever writes the receipt chooses the key, so verifying
against it proves internal consistency, not identity. This kit therefore reports three distinct states:

| Situation | `levels.signature` |
|---|---|
| a key you pinned, matching the embedded one | `"valid"` |
| only the embedded key | `"self-asserted"` |
| no key available at all | `"present-unverified"` |
| pinned key differs from the embedded one | refused — `MeshError` |

**3. Exit codes are 0 / 1 / 2, not 0 / 2 / 3.** The shared CLI uses 0 verified, 2 failed, 3 usage; the
rails tool uses 1 for a failed verification. `python -m avm_mesh.rails` translates them, so an operator's
existing scripts do not read a failed verification as a usage error.

**4. Field names differ from ours.** The rails carry `settlement.tx_id`, `settlement.chain`,
`settlement.asset_id`, `settlement.amount_microunits`, `issuer_did`, and `signature.kid` / `signature.alg`.
This kit verifies the envelope (`canonical_bytes_b64`, `content_hash`, `public_key_b64`, `signature`) and
returns `content` decoded, so settlement fields come from `result["content"]["settlement"]` — no renaming
is done for you.

## What is not proven, and must not be implied

- **This kit has not been round-tripped against a genuine rails receipt.** The format and the signing
  convention are now pinned by tests (including a test that captures the exact payload bytes the signature
  is checked over), but no receipt produced by the bundle has been verified here. The rails source tree is not
  available here, so adoption is tested against the format and against our own fixtures, not against bytes
  the bundle actually emits. Verify with a real receipt before release.
- **The signer side of LEVEL 2 needs an operator-side signer.** No signer is a runtime dependency and
  `pqcrypto` 0.1.0 has no prebuilt Linux wheel, so it is built from sdist for the acceptance run. With it
  installed, `tests/test_level2_real_signer.py` exercises an operator key signing and the verifier accepting,
  end to end; those tests are marked `signer` and deselected where the signer is absent.
- **Only Algorand and Voi can reach `stake_attested`.** Hedera, Stellar, Base, Solana and Tempo have no
  state proofs; their receipts stay honestly at LEVEL 2. Do not present seven chains as equal.
