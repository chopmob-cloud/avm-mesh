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
- **Windows reparse points** (directory junctions/mount points) inside an evidence or store
  directory are not detected by Python's `Path.is_symlink()` without elevation, so a junction to an
  outside path could bypass the resolver's symlink refusal on Windows. This is a Windows-only gap; on
  POSIX `O_NOFOLLOW` refuses a junction-equivalent link atomically. The resolver's evidence directory
  is operator-owned; do not point `--evidence` at a directory writable by an untrusted user.
- denial of service by a client that already proved it can saturate the
  network path (the server sheds with 503 by design).

## What this package will not do

- It will not claim a verification level it did not perform. If a tier could
  not be checked, the output says so and the exit code reflects it.
- It will not fetch from a non-public address unless `--allow-private` is
  given explicitly.

- It will not detect **hard links** inside an evidence or store directory: a path that is a hard
  link to a file outside the allowed root shares an inode and reads the same bytes without being a
  symlink. The `--evidence` directory and the receipt store are therefore assumed to be owned by
  the operator; this is a filesystem limit shared by `Store._safe_name`, not a defect to be fixed
  in Python. Symlink hardening (POSIX atomically; Windows by an explicit pre-open check) does not
  cover this case, which is why it is written here rather than discovered by an operator.
