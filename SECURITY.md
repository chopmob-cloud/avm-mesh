# Security policy

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability.

Email: security@algovoi.co.uk

Include: the version (e.g. `avm-mesh 0.7.0`), the command or API used, what you
observed, and a minimal reproduction if you have one. Proof-of-concept code is
welcome; if it includes keys or mnemonics, encrypt it first and say so in a
plain first message.

**Response targets** (best effort, not a contractual SLA): acknowledgement
within 3 working days, a triage decision within 10 working days.

## Scope

In scope for `avm-mesh`:

- the receipt/sealing and verification path (`receipt.py`, `sealed.py`,
  `attestation.py`), including any input that makes a false receipt verify;
- the witness service and its HTTP surface (`service.py`, `net.py`): path
  traversal, symlink escape, unbounded reads, SSRF, rate/connection limits;
- the rails adapter (`rails/`), where a malformed receipt is accepted or a
  non-verifying signature is reported as valid.

Explicitly **out of scope** here, and reviewed elsewhere:

- the Falcon-1024 implementation and state-proof arithmetic in the
  `avm-proofpack` dependency — that is the root of trust and its own review;
- economic/threat parameters for on-chain bonding — not implemented yet;
- denial of service by a client that already proved it can saturate the
  network path (the server sheds with 503 by design).

## What this package will not do

- It will not claim a verification level it did not perform. If a tier could
  not be checked, the output says so and the exit code reflects it.
- It will not fetch from a non-public address unless `--allow-private` is
  given explicitly.
