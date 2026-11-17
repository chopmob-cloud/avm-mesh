// Interop harness: emit a REAL AC2 consent using the actual AC2 SDK and Node's
// base64url encoder, exactly as the reference implementation (ac2-open-claw-reference
// src/receipt.ts) does. The Python verifier must then accept these bytes.
//
// This exists because a round-trip test in one language only proves my encoder
// agrees with my decoder. The defect it catches -- base64url vs base64 -- was
// invisible to every test in tests/test_consent.py, which encoded with Python's
// standard alphabet and decoded it with the same alphabet.
//
//   node interop_emit.mjs <out.json>
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const AGENT_DID = 'did:key:z6MkAgentInterop';
const CONTROLLER_DID = 'did:key:z6MkControllersInterop';

// The exact bytes the Python side puts in front of a controller. Declared here
// independently so a change on either side shows up as a mismatch rather than
// passing because both moved together.
const CONSENT_PAYLOAD_TYPE = 'algovoi/settlement-consent/v1';

// The settlement this consent covers. Field-for-field what avm-ac2 builds.
export const SETTLEMENT = {
  chain: 'voimain-v1.0',
  txid: '75LUFZZNQNOPS3SLQRHZZKZIECEEVGGP4N3ZZ2UU2UKFFJU5WG4A',
  round: 24213754,
  amount: '0',
  asset: 586896,
};

/** JCS-lite: RFC 8785 subset, identical to ac2-open-claw-reference/src/receipt.ts. */
function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    if (typeof value === 'number' && !Number.isInteger(value)) {
      throw new Error('jcs: non-integer numbers are not supported; pass amounts as strings');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new Error('jcs: unsupported type ' + typeof value);
}

const payload = Buffer.from(
  jcs({ type: CONSENT_PAYLOAD_TYPE, settlement: SETTLEMENT }),
  'utf8',
);

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const jwk = publicKey.export({ format: 'jwk' });

// Exactly what the real stack emits: Node's 'base64url', unpadded.
const signatureB64u = edSign(null, payload, privateKey).toString('base64url');
const publicKeyB64u = jwk.x; // already base64url per JWK

const consent = {
  version: 1,
  did: CONTROLLER_DID,
  sig_hint: 'raw-ed25519',
  public_key: publicKeyB64u,
  signature: signatureB64u,
  signed_payload_sha256: (await import('node:crypto'))
    .createHash('sha256')
    .update(payload)
    .digest('hex'),
  request_id: 'ac2-interop-request',
  response_id: 'ac2-interop-response',
};

const out = {
  emitted_by: 'node + @algorandfoundation/ac2-sdk conventions',
  agent_did: AGENT_DID,
  controller_did: CONTROLLER_DID,
  settlement: SETTLEMENT,
  consent,
  payload_utf8: payload.toString('utf8'),
  notes: [
    'signature and public_key are base64url, unpadded, as AC2 emits them',
    'signed_payload_sha256 is over the UTF-8 JCS bytes above',
  ],
};

const dest = process.argv[2] ?? 'ac2-interop.json';
writeFileSync(dest, JSON.stringify(out, null, 2));
console.log(`wrote ${dest}`);
console.log(`  signature (base64url): ${signatureB64u.slice(0, 32)}...`);
console.log(`  has url chars (- or _): ${/[-_]/.test(signatureB64u)}`);
console.log(`  public_key (base64url): ${publicKeyB64u.slice(0, 20)}...`);
