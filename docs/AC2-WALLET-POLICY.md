# Wallet policy, read from source (not inferred)

Claim under test: *"whether the shipped mobile wallet approves a payload it does not
recognise as a transaction is a product decision no test here can settle."*

That was wrong to leave open. The wallet is public, so the policy is readable.

Repository: **perawallet/ac2-wallet**, `private: false`, `visibility: public`,
default branch `main`, last push 2026-08-19. Every quotation below is from that
branch and every file was fetched over the network, not remembered.

## 1. The wallet does not check `sig_hint` before signing

`hooks/useAc2Responders.ts`, `approveSigning`, lines 67-86:

```ts
const payload = new Uint8Array(Buffer.from(request.body.payload, 'base64'));
let signature: Uint8Array;
if (isGroupSigningSchema(request.body.schema)) {
  ...                                    // one approval covers an atomic group
} else {
  signature = await key.store.sign(matchedKey.id, payload);   // line 85, unconditional
}
```

The only branch is a *schema* special case for atomic groups. There is no
`sig_hint` comparison anywhere in this path: a `raw-ed25519` hint, an
`transaction-algorand` hint and an unset hint all reach the same
`key.store.sign(...)` call. **No payload-type policy exists to refuse.**

## 2. The user sees an explicit warning only for `transaction-algorand`

`lib/ac2/messageDisplay.ts`, lines 11-15:

```ts
export function isFundMovingRequest(envelope: Envelope): boolean {
  if (envelope.type !== 'ac2/SigningRequest') return false;
  const body = envelope.body as { sig_hint?: string; schema?: string } | undefined;
  return body?.sig_hint === 'transaction-algorand' || isGroupSigningSchema(body?.schema);
}
```

`Ac2MessageCard.tsx` gates three things on that single boolean:
the fund-moving icon (`account-balance-wallet` vs `verified-user`), the
legal-approved `TransactionWarning`, and the decoded `TransactionGroupOverview`
showing amount and recipient. When it is false the card renders the
agent-supplied `body.description` and a `RawContentViewer`, and still offers
**Decline / Approve**.

So a canonical-payload consent is *signable* but shows the user the agent's own
description, with no transaction summary and no warning. A transaction-bound
consent gets the warning and the decoded amount. That is a reason to prefer the
transaction-bound flavour on honesty grounds, independent of whether the wallet
would refuse anything.

## 3. The signing preimage is `"TX"` + canonical encoding, confirmed in code

`bytesForSigning.transaction` (algokit-utils `transact/signer.js`) is
`encodeTransaction(txn)`, and `encodeTransaction` is:

```js
function encodeTransaction(transaction) {
  const rawBytes = encodeTransactionRaw(transaction);
  return concatArrays(new TextEncoder().encode("TX"), rawBytes);
}
```

with `rawTxId() { return hash(encodeTransaction(this)); }`. This is exactly the
`b"TX" + encode_canonical(transaction_from_stib(...))` derivation that
`avm_ac2.txn_consent` reproduces, and that the tests check against each bundle's
own `transaction.txid`.

## 4. A `"TX"`-prefixed payload is also rendered correctly

`decodeTransaction` strips the prefix when present:

```js
const prefixBytes = new TextEncoder().encode("TX");
let hasPrefix = true; ... compare bytes ...
const decodedData = decodeMsgpack(hasPrefix ? encoded_transaction.slice(prefixBytes.length)
                                            : encoded_transaction);
```

So one payload satisfies both requirements: the wallet signs it (bytes are the
preimage) and the UI can summarise it as a transaction (prefix is stripped).
For the non-group path the wallet signs `payload` verbatim, so the payload we send
must BE the preimage, `"TX"` included. It is.

## 5. Version parity, since the wallet pins a canary

The wallet pins `@algorandfoundation/ac2-sdk` at `1.0.0-canary.1`; the code under
test was validated against `1.0.0`. Both were installed and their type surfaces
compared:

| | `1.0.0-canary.1` (wallet) | `1.0.0` (tested) |
|---|---|---|
| `SigningResponseBody` | `signature`, `public_key`, `address?`, `key_type?` | identical |
| `SigningHint` values | 9, incl. `transaction-algorand`, `raw-ed25519` | identical set |

`SigningResponseBody` is byte-identical between the two, so the verifier parses the
wallet's actual response shape. `transaction-voi` is absent from both, confirming
Voi must travel as `transaction-algorand`.

## 6. Encoding: the wallet emits standard base64

`lib/ac2/responders.ts` defines its own encoder:

```ts
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}
```

Standard base64, not base64url — and `utils/base64.ts` keeps url-safe conversion as
a separate explicit helper.

Both alphabets do occur in practice, but not in the same field, which is why the
verifier must accept both. Measured, not assumed, across the two implementations:

| producer | field | alphabet |
|---|---|---|
| this wallet (`responders.ts`) | `signature` | **standard** base64 |
| reference seam (`receipt.ts:38`) | signature over claims | **base64url** |
| reference seam (`x402-seam.ts:43`) | `payload` | standard base64 |

So the signature field is the one that varies between producers, and a strict
`b64decode(validate=True)` rejects the reference seam's own signature:
`-` and `_` are outside the standard alphabet. Accepting both is required, not
defensive.

## How these quotations were checked

Every quotation above was extracted from the fetched file at write time, not typed
from memory: eight positive assertions (the `sign(payload)` call, the
`isGroupSigningSchema` branch, the `isFundMovingRequest` return, the `"TX"` prefix in
`encodeTransaction`, `rawTxId` hashing the prefixed form, `decodeTransaction`
stripping the prefix, `bytesForSigning.transaction` delegating to
`encodeTransaction`, and `toString('base64')` in the responders) all matched
verbatim. The load-bearing *negative* claim — that no `sig_hint` check exists in the
approve path — was checked the only way a negative can be: `sig_hint` occurs **zero**
times in `hooks/useAc2Responders.ts`.

Re-run the check before trusting this document after the wallet moves:

```bash
curl -sSL https://raw.githubusercontent.com/perawallet/ac2-wallet/main/hooks/useAc2Responders.ts \
  | grep -c sig_hint     # must print 0 while this document is accurate
```

## What this does and does not settle

**Settled.** The wallet will sign a non-transaction payload; there is no policy
check in that code path. The transaction-bound flavour produces exactly the bytes
the wallet signs and reaches the richer, warned UI. Version and encoding
compatibility are confirmed by installing both and comparing, not by reading prose.

**Not settled — and not settleable from source.** That the running app on a device
signs and returns a response over a live DIDComm/WebRTC transport. Source-reading
proves the *policy*; it does not execute the app. No test here has ever seen a real
wallet's signature, and this document does not claim otherwise.

The design no longer depends on that gap: both flavours are accepted, and the one
that needs no new wallet behaviour is the one now shipped and tested.
