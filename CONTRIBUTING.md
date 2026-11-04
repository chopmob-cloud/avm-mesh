# Contributing

## Branches and pull requests

**Every change lands through a branch and a pull request, including releases.** `main` is what PyPI is built
from, so a commit that arrives on `main` without review is indistinguishable in the log from one that arrived
through it: CI is green either way. Two releases (0.10.2 and 0.11.0) landed directly on `main` before this
rule existed, and neither was caught by anything except a later look at the PR list.

```sh
git switch -c feat/what-you-are-doing
# ...changes, commit...
git push -u origin feat/what-you-are-doing
gh pr create --base main --head feat/what-you-are-doing
```

Wait for all four CI jobs — `tests (py3.10)`, `tests (py3.12)`, `artefacts (licence + metadata)`, and
`a2a TCK (jsonrpc, must)` — then merge with `gh pr merge --merge`.

## The local guard

This repository activates a `pre-push` hook through `core.hooksPath`:

```sh
git config core.hooksPath tools/hooks      # already set in this clone
```

`tools/hooks/pre-push` refuses a push whose target is `refs/heads/main` and which would introduce commits,
and refuses deleting `main`. It allows a branch push, allows an up-to-date no-op push, and allows an
explicit override:

```sh
AVM_ALLOW_MAIN_PUSH=1 git push origin main
```

An override is for a genuine emergency and should be justified in the commit message, because the next
reader will find the commit on `main` with no review behind it.

### What the hook cannot do

- **It does not run on `gh pr merge`.** That merges server-side, which is the intended path, so the gap is
  the design rather than a hole.
- **It does not bind anyone else.** A hook set through `core.hooksPath` is per-clone configuration, so a
  fresh clone or a different machine has to run the `git config` line above. The `tools/hooks` directory is
  committed, which makes that one command rather than a manual reconstruction.
- **It is not a server-side control.** GitHub branch protection is unavailable here: this repository is
  private and the account is not on a paid plan, so the API answers
  `Upgrade to GitHub Pro or make this repository public to enable this feature`. Once the repository is
  public, enable protection on `main` (require a pull request, require the four checks) and this hook becomes
  the local convenience rather than the only guard.

## Before you open the pull request

The project's own gate, in the order that catches the most:

```sh
python -m pytest tests -q -m 'not signer'     # 440+ tests, no skips on Linux
python tools/audit_trust_boundary.py          # rule A must pass
python tools/red_team.py                      # every attack must be refused
python tools/check_artifacts.py dist/         # wheel + sdist licence and metadata
```

Then `/validate` in the Hermes desktop app, which runs an independent reviewer over the diff and is not the
author model. Test every finding before acting on it: a reviewer reading only a diff hunk will report guards
that sit just outside it as missing, and a finding that cannot be reproduced is a false positive.

## Reporting a security issue

Do not open an issue. See [`SECURITY.md`](../SECURITY.md).
