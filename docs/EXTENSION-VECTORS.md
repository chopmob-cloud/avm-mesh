# Settlement-evidence extension: conformance vectors

The A2A TCK has requirements for extensions as a mechanism (extended agent card, refusing an unsupported
required extension) but none for the payload a third-party extension carries. A green TCK run therefore
cannot say whether this extension's evidence is accepted when it should be, or refused when it should be.
This page and `tests/vectors/a2a/settlement-evidence-v1.json` are how that gap is closed from our side, and
they are offered openly so another implementer can check us against them.

## The two verifiers that must agree

| Verifier | Where | What it needs |
|---|---|---|
| Library | `avm_mesh.a2a.verify_artifact` | the package, plus a resolver for proofpacks |
| Standalone | `tools/verify_settlement_artifact.py` | the Python standard library, and nothing from AlgoVoi |

The standalone tool exists so a counterparty can check what we handed them without installing our package.
It is deliberately short enough to read before running, and a test asserts it imports nothing from either
`avm_mesh` or `avm_proofpack`.

Every case in the vector file is run through both, and the suite fails if they disagree. Agreement is the
property: a sender and a receiver reaching different verdicts about the same artefact is the failure mode
worth engineering against.

## What each verifier establishes

| Level | Library | Standalone |
|---|---|---|
| Envelope: one payload, right extension, parseable part | yes | yes |
| LEVEL 1 integrity: `sha256(canonical_bytes) == content_hash` | yes | yes |
| LEVEL 2 operator signature | yes, with a key | **no**, and it says so |
| LEVEL 3 consensus attestation | yes, with an anchor | **no**, and it says so |

The standalone tool reports the levels it cannot check as `not checked` rather than omitting them. A
convenience verifier that stayed quiet about the levels it skipped would be worse than no verifier.

## The cases

Fourteen cases, both verdicts represented:

| Case | Expected | Why it is in the set |
|---|---|---|
| `valid_structural` | pass | the envelope and LEVEL 1 both hold |
| `valid_legacy_kind_tag` | pass | v0.3.x peers still send `kind: "data"`; the spec asks for dual handling during overlap |
| `kind_contradicts_payload` | reject | a part tagged `text` is not an evidence payload, whatever it contains |
| `extension_uri_mismatch` | reject | another extension's payload is not ours, however well formed |
| `no_parts_member` | reject | an artefact with no parts is not evidence |
| `parts_not_a_list` | reject | type confusion must fail closed, not raise |
| `part_not_an_object` | reject | a non-object part is skipped, and with nothing else the artefact is refused |
| `payload_not_an_object` | reject | the receipt must be an object |
| `content_hash_mismatch` | reject | the digest is the integrity claim |
| `canonical_not_base64` | reject | malformed encoding is a refusal, not a crash |
| `canonical_is_not_json` | reject | a correct digest over bytes that are not JSON proves the bytes, not a receipt |
| `missing_content_hash` | reject | nothing to compare against |
| `two_payloads_ambiguous` | reject | two payloads is not a shape to resolve by taking the first |
| `null_payload_then_valid_payload` | reject | a first part carrying a null receipt must not let a second part pass unnoticed |

Plus one case that cannot live in a vector file because it is deliberately large:
`test_an_oversized_canonical_blob_is_refused_before_decoding` builds a blob just over the cap in memory and
requires the refusal to happen before base64 decoding, so a hostile peer cannot make the verifier allocate
first and refuse later.

## Proven by mutation, not by assertion

Each guard was removed and the corresponding case required to fail:

| Guard removed | Result |
|---|---|
| extension URI comparison | `extension_uri_mismatch` fails |
| content-hash comparison | `content_hash_mismatch` fails |
| size cap before decoding | the oversized case fails |
| `kind` contradiction check | `kind_contradicts_payload` fails |
| library duplicate-payload guard | `two_payloads_ambiguous` diverges between the verifiers |
| duplicate guard in either verifier, reverted to a value test | `null_payload_then_valid_payload` fails |
| duplicate guard in either verifier, removed | `two_payloads_ambiguous` fails |

All of them go red on removal or on weakening, and green on restore, so the suite is measuring the guards
rather than describing them.

## What these vectors do not prove

- **Not LEVEL 2 or LEVEL 3.** A signature or an attestation present in an artefact is reported, not verified,
  by the standalone tool. Use the package, with a key and an anchor you chose.
- **Not the semantics of the receipt inside the payload.** The vectors check the envelope and the integrity
  binding. What the receipt attests, and whether a chain's consensus backs it, is verified by
  `avm_mesh.verify_sealed` / `verify_attestation` and is out of scope here.
- **Not a substitute for the TCK.** The TCK proves protocol conformance for the transport we claim. These
  vectors prove the extension's own contract. Neither is the other.
- **Not normative for ambiguous input.** Both verifiers refuse the ambiguous case rather than resolving it.
  Where they might diverge is exactly where the input is ambiguous, which is why the ambiguous case is a
  refusal in both.
