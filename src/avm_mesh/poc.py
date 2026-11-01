"""Testnet proof-of-concept: administrative enforcement of witness bonds.

HONESTY FIRST, because this module is the easiest place in the repository to
overclaim. It does NOT slash anything on chain. There is no escrow reader
(`docs/BONDING-DECISIONS.md`), so a "slash" here is ADMINISTRATIVE: a witness
whose served attestation does not verify against the trusted anchor is marked
inactive, and the decision is written to a hash-chained, append-only ledger. The
forfeit figure recorded alongside it is illustrative arithmetic over the
witness's DECLARED bond (`BondPolicy.slash_amount`), not an amount this code can
take, because there is nothing on chain to take it from.

Why it exists: so the whole flow -- declare a bond, attest, challenge, remove --
can be run and inspected on testnet before any real stake or on-chain slashing is
built. That is the point of the PoC, and its honest ceiling.

What it does NOT do: adjudicate intent. An attestation can fail to verify for
malice (the witness served evidence that contradicts consensus) or for an
operational reason (it could not serve the evidence at all). The PoC removes on a
failed verification and records the exact reason so the verdict is auditable and
disputable; it does not decide which kind of failure it was. Separating malice
from error, with a challenge deposit, a dispute window and an arbiter, is exactly
what `docs/BONDING-DECISIONS.md` sections 2 to 4 leave to the communities and what
the production escrow application would enforce. Do not read a removal here as a
finding of dishonesty.

THE LOG IS THE SOURCE OF TRUTH. A challenge appends a durable (fsync'd) line to
the ledger and only then moves in-memory state, so a crash can leave a recorded
decision but never a live removal with no record. A `<ledger>.head` sidecar
(itself fsync'd) records the latest sequence and hash so truncation is
detectable; it is a self-healing checkpoint, written after the line, so if it
lags by one entry the log still wins and the next open re-syncs it.

TAMPER-EVIDENCE, stated precisely. Editing a line in place breaks the hash chain
(self-evident). Dropping trailing lines is caught by the head sidecar. Deleting
the whole log while the head survives is refused on open. This is tamper-EVIDENT,
not tamper-PROOF, and two cases specifically need an externally retained hash
passed to `verify_ledger(expected_head_hash=...)`:

  - a writer able to rewrite BOTH the log and the head consistently; and
  - the UNCHECKPOINTED TAIL. The head is written just after the log line, so a
    crash or a failed head write can leave the single most recent entry
    uncheckpointed (the head still names the entry before it). Until the next
    successful append or a clean reopen re-checkpoints that entry, it can be
    rolled back or rewritten by editing ONLY the log, and the sidecar cannot tell.
    In normal operation (no crash, the head write succeeds inside the same locked
    critical section as the line) the head is always current and no such window
    exists; the window is strictly post-failure, and a retained post-removal hash
    closes it.

A single writer per ledger file is required: the append guard turns the usual
two-instance mistake into a loud refusal, but there is no OS lock, so genuinely
concurrent writers are out of scope.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .attestation import ConsensusAttestation, verify_attestation
from .bond import BondError, BondPolicy, DEFAULT_POLICY, Witness, WitnessSet
from .receipt import MeshError

#: A challenge was examined and the witness's attestation verified. No action.
UPHELD = "upheld"
#: The witness's attestation did not verify against the trusted anchor. The
#: witness is marked inactive and the reason is recorded. NOT a finding of intent.
REMOVED = "removed"

_GENESIS = "enforcement-ledger-genesis"  # prev_hash of the first entry


@dataclass(frozen=True)
class ChallengeResult:
    """The outcome of one challenge, as written to the ledger."""
    seq: int
    witness_id: str
    operator_id: str
    verdict: str          # UPHELD or REMOVED
    reason: str           # verbatim verifier message on REMOVED, else "attestation verified"
    declared_slash_microalgo: int
    ts: str
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(body: dict) -> str:
    return hashlib.sha256(_canonical(body)).hexdigest()


def _head_path(path: pathlib.Path) -> pathlib.Path:
    return path.with_suffix(path.suffix + ".head")


def _last_nonempty_line(path: pathlib.Path) -> str | None:
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            last = line
    return last


def _read_head(path: pathlib.Path) -> dict | None:
    hp = _head_path(path)
    if not hp.exists():
        return None
    return json.loads(hp.read_text(encoding="utf-8"))


def _write_head(path: pathlib.Path, seq: int, last_hash: str) -> None:
    """Write the checkpoint durably: fsync the temp file, then atomically replace."""
    hp = _head_path(path)
    tmp = hp.with_suffix(hp.suffix + ".tmp")
    data = json.dumps({"seq": seq, "last_hash": last_hash},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, hp)


def _walk_chain(path: pathlib.Path):
    """Yield (seq, verdict, witness_id, entry_hash) for a hash-valid ledger, or raise.

    Checks each line's prev_hash chains and its entry_hash matches its body, so an
    in-place edit fails here. It also derives the sequence from POSITION, not from
    the record: ``seq`` must be a real integer (not a bool or a coercible string)
    and must equal its 1-based position, strictly consecutive. Trusting the stored
    ``seq`` would let a rebuilt headless log end at sequence 0 and slip past the
    "entries exist -> need a head" check, or report a false entry count. Truncation
    across a valid chain is still the head sidecar's job, not this walk's.
    """
    prev = _GENESIS
    position = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        position += 1
        entry = json.loads(line)
        body = {k: entry[k] for k in entry if k != "entry_hash"}
        seq = entry.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise MeshError(f"ledger entry at position {position}: sequence is not an integer")
        if seq != position:
            raise MeshError(
                f"ledger entry at position {position}: sequence {seq} is not consecutive from 1"
            )
        if entry.get("prev_hash") != prev:
            raise MeshError(f"ledger broken at seq {position}: prev_hash does not chain")
        if _entry_hash(body) != entry.get("entry_hash"):
            raise MeshError(f"ledger broken at seq {position}: entry_hash does not match body")
        prev = entry["entry_hash"]
        yield seq, entry["verdict"], entry["witness_id"], entry["entry_hash"]


def _check_head(path: pathlib.Path, head: dict | None, seq: int, last: str,
                checkpoint_hash: str | None) -> None:
    """Reconcile a walked chain against the head sidecar.

    ``seq``/``last`` are the chain's length and tail; ``checkpoint_hash`` is the
    hash the chain carries AT the head's recorded sequence (None if the chain is
    shorter than that, or if there is no head).

    - no head, but entries exist: completeness cannot be confirmed -> raise.
    - log shorter than head: truncation -> raise.
    - the chain's entry at the head's sequence does not hash to the head's
      recorded hash: tampering or a forked rewrite -> raise. This is the check
      that matters when the log is LONGER than the head: a lagging head is only
      acceptable if the recorded checkpoint is still a genuine PREFIX of the
      current chain, otherwise "append one more line" would launder a rewrite.
    - otherwise the head is a valid prefix; any entries beyond it are a lagging
      tail from a crash between the line write and the head write. The log wins.
    """
    if head is None:
        if seq > 0:
            raise MeshError(
                f"ledger {path} has {seq} entries but no head sidecar; completeness "
                "cannot be confirmed (supply expected_head_hash if you retained it)"
            )
        return
    hseq = int(head["seq"])
    if seq < hseq:
        raise MeshError(
            f"ledger {path} is shorter than its head (have {seq}, head says {hseq}): "
            "truncation detected"
        )
    if checkpoint_hash != head["last_hash"]:
        raise MeshError(
            f"ledger {path} head does not match the chain at the checkpoint sequence "
            f"{hseq}: tampering or a forked rewrite"
        )


class EnforcementLedger:
    """Runs challenges against a witness set and records every verdict.

    The ledger is the state: which witnesses are still active is derived from the
    recorded removals, so the audit log and the live set can never silently
    disagree. A removal is committed to the durable log BEFORE in-memory state
    moves; the head checkpoint is written after and may lag by one entry without
    harm. See the module docstring for the full durability and tamper model.
    """

    def __init__(self, witness_set: WitnessSet, path: pathlib.Path | str,
                 policy: BondPolicy | None = None) -> None:
        if not isinstance(witness_set, WitnessSet):
            raise BondError("EnforcementLedger expects a WitnessSet")
        self.policy = policy or DEFAULT_POLICY
        self._by_id: dict[str, Witness] = {w.witness_id: w for w in witness_set.witnesses}
        #: witness_id -> inactive, set on REMOVED. Starts from the declared
        #: `active` flag so a witness that arrives inactive is not "removed" twice.
        self._removed: set[str] = {w.witness_id for w in witness_set.witnesses if not w.active}
        self.path = pathlib.Path(path)
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = _GENESIS
        self._reconcile_on_open()

    def _reconcile_on_open(self) -> None:
        head = _read_head(self.path)
        if not self.path.exists():
            # A surviving head with no log means the log was deleted or moved: refuse
            # rather than silently start fresh and resurrect removed witnesses.
            if head is not None and int(head.get("seq", 0)) > 0:
                raise MeshError(
                    f"ledger {self.path} is missing but its head sidecar survives "
                    f"(head seq {head.get('seq')}): the log was deleted or moved"
                )
            return
        seq = 0
        last = _GENESIS
        checkpoint_hash: str | None = None
        hseq = int(head["seq"]) if head is not None else None
        for s, verdict, wid, entry_hash in _walk_chain(self.path):
            seq, last = s, entry_hash
            if hseq is not None and s == hseq:
                checkpoint_hash = entry_hash
            if verdict == REMOVED:
                self._removed.add(wid)
        _check_head(self.path, head, seq, last, checkpoint_hash)
        self._seq = seq
        self._last_hash = last
        # Heal a lagging head: if a prior checkpoint write failed, the recovered
        # chain is longer than the head. Refresh it now (the prefix was just
        # validated), so a later truncation back to the stale checkpoint cannot
        # resurrect a witness this chain already removed.
        if head is not None and seq > int(head["seq"]):
            _write_head(self.path, seq, last)

    def _assert_chain_head(self) -> None:
        """Refuse to append if the file no longer ends where we last wrote."""
        if not self.path.exists():
            if self._last_hash != _GENESIS:
                raise MeshError("ledger file vanished underneath this writer; refusing to append")
            return
        last_line = _last_nonempty_line(self.path)
        if last_line is None:
            if self._last_hash != _GENESIS:
                raise MeshError("ledger emptied underneath this writer; refusing to append")
            return
        entry = json.loads(last_line)
        if entry.get("entry_hash") != self._last_hash:
            raise MeshError(
                "ledger changed underneath this writer (another writer or an edit); "
                "refusing to append and fork the chain"
            )

    def active_witnesses(self) -> WitnessSet:
        """The witness set as it stands now, removals reflected as `active=False`."""
        out = [dataclasses.replace(w, active=w.witness_id not in self._removed)
               for w in self._by_id.values()]
        return WitnessSet(tuple(out))

    def challenge(self, witness_id: str, attestation: ConsensusAttestation | dict,
                  resolve: Callable[[str], dict], *, trusted_voters: Any,
                  expected_genesis_hash_b64: str | None = None) -> ChallengeResult:
        """Examine a witness's attestation against an independently trusted anchor.

        `attestation` is what the witness served; `trusted_voters` and
        `expected_genesis_hash_b64` are the challenger's OWN anchor and pin, never
        taken from the witness. If the attestation verifies, the challenge is
        upheld and nothing changes. If it does not, the witness is marked inactive
        and the verifier's exact message is recorded -- but only AFTER the decision
        is durably on the log.
        """
        witness = self._by_id.get(witness_id)
        if witness is None:
            raise BondError(f"no witness record for {witness_id!r}; cannot challenge an unknown witness")

        verdict = UPHELD
        reason = "attestation verified"
        try:
            verify_attestation(attestation, resolve, trusted_voters=trusted_voters,
                               expected_genesis_hash_b64=expected_genesis_hash_b64)
        except MeshError as exc:
            verdict = REMOVED
            reason = str(exc)

        with self._lock:
            self._assert_chain_head()
            declared = self.policy.slash_amount(witness.bond_microalgo) if verdict == REMOVED else 0
            next_seq = self._seq + 1
            body = {
                "seq": next_seq,
                "witness_id": witness_id,
                "operator_id": witness.operator_id,
                "verdict": verdict,
                "reason": reason,
                "declared_slash_microalgo": declared,
                "ts": datetime.now(timezone.utc).isoformat(),
                "prev_hash": self._last_hash,
            }
            entry_hash = _entry_hash(body)
            record = {**body, "entry_hash": entry_hash}

            # 1. Durable log line. This is the source of truth.
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

            # 2. Commit in-memory the moment the record is durable, so the live
            #    set and the log cannot disagree even if the checkpoint below fails.
            self._seq = next_seq
            self._last_hash = entry_hash
            if verdict == REMOVED:
                self._removed.add(witness_id)

            # 3. Checkpoint. If this throws, the log and memory are already
            #    consistent; the head simply lags and re-syncs on the next open/write.
            _write_head(self.path, next_seq, entry_hash)

        return ChallengeResult(entry_hash=entry_hash, **body)


def verify_ledger(path: pathlib.Path | str, *, expected_head_hash: str | None = None) -> int:
    """Re-read a ledger and check it end to end. Returns the entry count.

    Catches two kinds of tampering and is honest about a third:
      - in-place edits: the hash chain breaks (raises).
      - truncation / a deleted log: the `<ledger>.head` sidecar records the true
        length and last hash; a ledger shorter than its head, or absent with a
        surviving head, raises. A ledger with entries but no head cannot be
        confirmed complete and raises, unless you pass `expected_head_hash`.
      - a writer that rewrites BOTH the log and the head consistently, OR a
        rollback/rewrite of the single uncheckpointed tail entry after a crash
        (see the module docstring), can still rewrite history; only an externally
        retained `expected_head_hash` closes those, so pass it for adversarial use.
    """
    path = pathlib.Path(path)
    head = _read_head(path)
    if not path.exists():
        if head is not None and int(head.get("seq", 0)) > 0:
            raise MeshError(f"ledger {path} is missing but its head sidecar survives: the log was deleted")
        raise MeshError(f"no ledger at {path}")
    count = 0
    last = _GENESIS
    checkpoint_hash: str | None = None
    hseq = int(head["seq"]) if head is not None else None
    for seq, _verdict, _wid, entry_hash in _walk_chain(path):
        count = seq
        last = entry_hash
        if hseq is not None and seq == hseq:
            checkpoint_hash = entry_hash
    if expected_head_hash is not None:
        if last != expected_head_hash:
            raise MeshError("ledger head does not match the externally retained hash: truncated or forked")
        return count
    _check_head(path, head, count, last, checkpoint_hash)
    return count
