# AC2 consent, bound to a settlement

`avm_mesh.ac2` connects two layers that answer different questions, and it is
careful to keep them apart.

| | **AC2** (Algorand Foundation, Draft) | **avm-mesh** |
|---|---|---|
| Answers | *Who approved this payload, and can an agent carry that approval without the key?* | *Did this transaction settle, and can a third party prove it offline?* |
| Trust root | the controller's key, delivered over Liquid Auth (FIDO2/WebAuthn + WebRTC) | Algorand/Voi consensus, via a Falcon-1024 state proof |
| Fails at | a compromised controller | a forged or whitelied proofpack |

Neither is evidence for the other. This module makes the *join* checkable.

## The gap it closes

A sealed receipt already carries a free-form `content` dict, and the shipped
examples already publish an `issuer_did`. Nothing verifies either. So an
operator can publish a receipt next to a consent claim that nobody checks, and a
reader sees "human approved" beside `stake_attested` and reasonably — and
wrongly — reads the approval as proven too.

That is the same defect class the amount binding closed: a figure the producer
chose sitting beside a tier the evidence earned.

## What AC2 actually proves — and what it does not

The `ac2/SigningResponse` body is:

```json
{ "signature": "...", "public_key": "...", "address": "...", "key_type": "account" }
```

There is **no WebAuthn material in it**: no `authenticatorData`, no
`clientDataJSON`, no `credentialId`, no attestation object. The Draft spec's
Pattern 2 diagram says a delegated signature arrives *"with constraints: expiry,
scope"*, but no normative field carries either, and the SDK's
`SigningResponseBody` declares neither.

**Therefore a third party holding only an AC2 response cannot tell a hardware
passkey from a software key.** The spec's design goal is that the *wallet*
requires user verification; that is a claim about the wallet's behaviour, and it
is not something the message lets a verifier re-check.

This module never says "hardware-bound" and never says "a human approved". It
proves exactly what the bytes prove:

| Level | What it establishes | What it does not |
|---|---|---|
| `none` | no consent block present | — |
| `consent_present` | the holder of `public_key` signed **this** settlement's canonical payload | that a human, or a passkey, was involved |
| `sender_bound` | that key **is** the authenticated transaction sender | still not a passkey — only that the payer signed |
| `consensus_bound` | additionally the settlement reached `stake_attested` | that goods shipped; that the witness set is independent |

`sender_bound` is the property worth having: it collapses "someone approved
this" and "this was paid" into one key, so the approval and the payment cannot be
substituted for each other, and the payer cannot be misrepresented.

## Why the payer is the signer, not the agent

AC2's whole design is that the agent cannot sign. In an x402 flow the agent
holds a *delegated* signature and submits it; the account that funds the
transaction is the controller's. AC2's `address` field — the Algorand account
bound to the passkey by the Liquid Extension — is therefore the natural payer,
and `address == sender` is the binding to check. A wallet that signs from a
different account than it advertised fails, which is the intended outcome: the
alternative is trusting the agent's word about who paid whom.

## Usage

The block must be placed into `content` **before** sealing, so it lands inside
the bytes `content_hash` covers. Placed afterwards it would be forgeable and the
tamper check below would rightly fail.

```python
import base64
from avm_mesh import ac2, sealed

settlement = {"chain": report.genesis_id, "txid": report.txid,
              "round": report.round, "amount": "0", "asset": 586896}

# 1. Agent asks the controller to sign ac2.consent_payload(settlement) over AC2,
#    and builds the block from the SigningResponse it gets back.
consent = ac2.build_consent(
    did="did:key:z6Mk...",                 # controller DID from the AC2 session
    sig_hint="raw-ed25519",
    public_key_b64=resp.body.public_key,
    signature_b64=resp.body.signature,
    settlement=settlement,
)

# 2. Seal it -- the consent lands inside the hashed bytes.
envelope = sealed.seal(
    {"version": 1, "settlement": settlement, "ac2_consent": consent},
    bundle, evidence_uri, trusted_voters=anchor,
)

# 3. Anyone verifies, reading the payer out of the authenticated STIB.
out = ac2.consent_level(envelope, report, bundle=bundle)
print(out["level"], out["reason"])
```

`ac2.sender_from_bundle(bundle, genesis_id)` reads the sender from the same
`stib_bytes` the receipt's attestation covers, so once verification has passed it
is a fact about the chain rather than a claim.

## Installing

Ed25519 verification is an optional extra so the rest of the library stays
dependency-light:

```bash
pip install "avm-mesh[ac2]"
```

Without it, `verify_consent` raises rather than reporting a check it could not
perform.

## Honest limits

- **The positive path is only demonstrated with a keypair the test owns.** The
  Algorand and Voi mainnet captures are real, and the sender is read from their
  authenticated bytes on both chains, but their private keys are not ours. A
  genuine "the payer approved" run needs a real AC2 wallet approving for an
  account it controls. `tests/test_ac2.py` says so where it matters.
- **One capture per chain, one endpoint.** Same limit as the rest of the estate:
  this proves the mechanism, not witness independence.
- **AC2 is a Draft.** The wire fields here are from `ac2-sdk` 1.0.0 and the
  `ac2.md` Draft read at publication. If the SDK starts carrying WebAuthn
  material, `consent_present` could honestly become a stronger claim — that would
  be a new consent version, not a reinterpretation of this one.
- **Consent is captured at seal time.** Like corroboration, it cannot be attached
  to a settlement after the fact without changing the content hash.
