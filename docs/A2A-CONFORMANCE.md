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

## 3. What is still not done

- **No TCK run with our extension advertised.** The extension is not served by any agent here, so no
  requirement has been exercised through our code.
- **The TCK has no extension-payload requirements.** Grepping `tests/compatibility` for `EXT-*` returns
  nothing; extensions appear only in `ExtensionSupportRequiredError` handling. A green TCK run therefore
  cannot validate extension *semantics* — at most it would show our presence does not break protocol
  conformance.
- Serving the extension needs an `a2a-sdk` agent plus a trusted-voters anchor, on a host that can reach the
  evidence. That is the next step, and it is a build rather than a check.
