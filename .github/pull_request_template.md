# Issue and pull-request templates

Thank you for taking the time to report something. Two notes before you write.

**Security issues do not belong here.** See [`SECURITY.md`](../SECURITY.md) and email
security@algovoi.co.uk. Do not open a public issue for a suspected vulnerability, and do
not paste keys, mnemonics or private evidence into one.

**"It reports a trust level it did not earn" is the bug that matters most.** This project
exists to make evidence checkable, so a false verification is more serious than a crash.
If you have found one, say so plainly and include the input.

---

## Reporting a defect

```
### What you ran

The exact command or code, with the package version (`python -c "import avm_mesh; print(avm_mesh.__version__)"`).

### What you expected

### What happened

The output, and the exit code if this was the CLI (`echo $?`).

### Evidence

Attach the receipt or proofpack if you can. If it is a real mainnet capture, it is public
chain data and safe to share. If it contains anything you would not publish, say what the
shape is instead and we will construct a fixture.

### Environment

OS, Python version, and whether the package came from PyPI or a checkout.
```

## Proposing a change

Open a pull request from a branch, not from `main` — the repository enforces this with a
`pre-push` hook, and the reason is in [`CONTRIBUTING.md`](../CONTRIBUTING.md). A direct
commit to `main` looks the same as a reviewed one in the log, and CI is green either way,
which is how two releases slipped through before the hook existed.

The four checks that must pass are `tests (py3.10)`, `tests (py3.12)`,
`artefacts (licence + metadata)` and `a2a TCK (jsonrpc, must)`.

If your change adds a guard, add the test that fails without it. If you can, remove the
guard once and check the test goes red — `tools/mutation_check.py` exists because a test
that has never been observed failing is a hypothesis, not a check.
