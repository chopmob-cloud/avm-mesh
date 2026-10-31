# A2A conformance — what has actually been run

Two separate things, kept separate because conflating them is how "TCK-validated" becomes a false claim.

## 1. Our artifact, parsed by the reference implementation — PROVEN

The sharpest question for the extension is not "does the JSON look right" but "does the reference SDK
accept it". `a2a-sdk` **1.3.0**, `google.protobuf.json_format.Parse` into `lf.a2a.v1.Artifact`:

```
artifact_current   PARSED   parts=1 payload=['data']
artifact_legacy    REJECTED Failed to parse parts field: Message type "lf.a2a.v1.Part" has no field named "kind"
```

The second line is the defect fixed in 0.4.2: v1.0 removed the inline `kind` discriminator, so the form we
used to emit is **not merely legacy — it is unparseable**. This is a negative control on the reference
implementation, not on our own tests: the same code path accepts one form and refuses the other.

Reproduce:

```bash
python -m pip install "a2a-sdk[http-server,grpc,sqlite]"
python -c "
import json; from google.protobuf import json_format; import a2a.types.a2a_pb2 as pb
art = pb.Artifact(); json_format.Parse(open('artifact_current.json').read(), art); print(art)"
```

## 2. The TCK itself — harness runs, but NOT against our code

The TCK (`chopmob-cloud/a2a-tck`, spec v1.0) was staged into a `python:3.12-slim` container on VM2 and run
against the **reference SUT it generates itself** (`sut/a2a-python/sut_agent.py`):

```
python run_tck.py --sut-host http://localhost:9999 --level must
5 failed, 183 passed, 47 skipped, 30 deselected in 129.37s
```

**That result says nothing about `avm-mesh`.** It is a baseline proving the harness, the SDK install, the
three transports and the report generation all work end to end on this infrastructure.

The five failures are in the reference SUT, not ours:

| Test | Failure |
|---|---|
| `test_cancel_terminal_task_returns_error[http_json]` | cancelling a terminal task does not error |
| `test_subscribe_rejects_terminal_task[grpc]` | subscribing to a terminal task is accepted |
| `test_response_content_type` | REST response content type wrong |
| `test_push_not_supported_returns_unimplemented` | wrong gRPC status (FAILED_PRECONDITION, not UNIMPLEMENTED) |
| `test_version_not_supported_returns_unimplemented` | unsupported `A2A-Version` processed normally |

Worth stating plainly: **the stock reference SUT does not pass its own TCK at `must` level.**

## 3. The TCK with our extension served — A/B, identical outcomes

A SUT (`tools/sut/avm_sut.py`) was derived from the reference one with exactly two differences: the card
advertises our extension via `avm_mesh.extension_descriptor()`, and a `settlement-evidence-*` message id
returns a real receipt built by `avm_mesh.as_artifact()`, converted through the SDK's own
`json_format.Parse(..., Part())`.

| Run | Result |
|---|---|
| reference SUT (baseline) | **5 failed, 183 passed, 47 skipped, 30 deselected** |
| our SUT, extension advertised | **5 failed, 183 passed, 47 skipped, 30 deselected** |
| failures in both | the same five, all inherited from the reference SUT |

Identical outcomes, same five failures. Advertising our extension and returning our artifact **costs zero
protocol conformance**, and adds nothing to the baseline's failures.

### The extension path, exercised end to end

```
card: AlgoVoi settlement-evidence SUT
extension uri: https://algovoi.co.uk/a2a/extensions/settlement-evidence/v1

task state: TASK_STATE_COMPLETED
artifacts: 1
  part keys: ['data', 'mediaType'] | mediaType: application/json
  extension: https://algovoi.co.uk/a2a/extensions/settlement-evidence/v1
  LEVEL 1 recomputed == declared: True
  settlement payload: {'amount_microunits': '1000000', 'chain': 'voi',
                       'tx_id': 'TCK-settlement-evidence-probe-1'}
```

The receipt's bytes survive the round trip through a real SDK server and JSON-RPC, and recomputing
`sha256(canonical_bytes)` on the receiver side still equals the declared `content_hash`. The part carries
`data` + `mediaType` and no `kind` — the v1.0 form.

What this SUT does **not** do: anchor a tier. It seals LEVEL 1 integrity only, because a `stake_attested`
claim needs a trusted-voters anchor and a proofpack it can reach, and emitting one without those would be a
fabricated trust claim.

## 4. What is still not done

- **No extension *semantic* validation, and none is possible with this TCK.** The A/B above proves our
  presence breaks nothing; it cannot prove the extension's own rules, because the TCK does not test them.
- **The TCK has no extension-payload requirements.** Grepping `tests/compatibility` for `EXT-*` returns
  nothing; extensions appear only in `ExtensionSupportRequiredError` handling. A green TCK run therefore
  cannot validate extension *semantics* — at most it would show our presence does not break protocol
  conformance.
- Serving the extension needs an `a2a-sdk` agent plus a trusted-voters anchor, on a host that can reach the
  evidence. That is the next step, and it is a build rather than a check.

## 5. Update, 2026-11-01 — our SUT is now a required CI gate, and it found a real defect

The run above (`§2`, 5 failed) was all transports against the reference SUT. Running ours on `a2a-sdk`
1.3.0 at `--transport jsonrpc --level must`, and then wiring the same thing into CI, produced a different
and better outcome — and one defect:

| Run | Result |
|---|---|
| local, our SUT, jsonrpc/must, before fix | 79 passed, 0 failed* |
| CI, our SUT, jsonrpc/must, before fix | **1 failed**, 79 passed, 155 skipped |
| local, after the content-type fix | **80 passed, 0 failed** |
| CI (`9dab2cd`), after the fix | green — `a2a TCK (jsonrpc, must) => success` |

\* the local run and CI disagreed about one test (their skip counts differ by one). CI reproduced the
failure, so CI is where the fix is evidenced, not the local run.

The defect: **JSONRPC-SSE-002**. A request with `Content-Type: text/plain` reached the SDK's JSON parser
and returned `ParseError (-32700)` rather than `ContentTypeNotSupportedError (-32005)`. A wrong media type
is an HTTP-level condition, so `tools/sut/avm_sut.py` now answers `415` with the A2A JSON-RPC error body
before the parser sees the bytes. That was a defect in the *SUT*, not in the extension: the receipt path
was never involved.

**`a2a-conformance` is now a required CI job.** On `bf0af17` it passed with the gate on, and the run shows
`a2a TCK (jsonrpc, must) => success`. This is protocol conformance for the transports we claim, nothing
more: the TCK still tests no extension semantics (§4).
