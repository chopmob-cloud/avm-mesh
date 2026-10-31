"""Derive a trust anchor by walking state proofs forward from a pinned checkpoint.

The problem this solves. A verifier needs ``TrustedVoters`` — the signing set and
proven weight for the interval it is checking. Until now the only way to get them
was to be given them, or to take them from the bundle's own previous message, which
proves nothing: whoever assembled the bundle chose that message.

A walk replaces "trust this document" with "trust this checkpoint, then verify every
interval between it and the target". Each step is Falcon-verified against the
previous step's authenticated inputs, so a single pinned checkpoint carries the
whole distance. The checkpoint is still trust — that is unavoidable, and this module
does not pretend otherwise — but it is one clearly-labelled trust decision instead
of one per bundle.

What a walk does **not** establish: that the checkpoint was ever the chain's real
signing set. A wrong checkpoint produces a walk that fails immediately, rather than a
walk that silently succeeds against the wrong chain, because the first link's
signatures are checked against it.
"""
from __future__ import annotations

import base64
import gzip
import zlib
import json
import pathlib
from dataclasses import dataclass

from .receipt import MeshError

#: Algorand and Voi attest every 256 rounds.
DEFAULT_INTERVAL = 256

#: Largest capture this will read. Real proofpacks are ~0.5-0.9 MB; the cap exists so
#: a capture directory cannot be used as a memory-exhaustion primitive. It applies to
#: the DECOMPRESSED bytes: a gzip bomb is small on disk and enormous when read, which
#: is exactly why a stat() alone is not enough.
MAX_BUNDLE_BYTES = 8 * 1024 * 1024


@dataclass
class AnchorWalk:
    """The outcome of a checkpoint walk, with the anchor it derives."""

    ok: bool
    links_verified: int
    target_round: int
    voters_commitment_b64: str | None = None
    ln_proven_weight: int | None = None
    failure: str | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "links_verified": self.links_verified,
            "target_round": self.target_round,
            "voters_commitment_b64": self.voters_commitment_b64,
            "ln_proven_weight": self.ln_proven_weight,
            "failure": self.failure,
            # Stated in the output so a caller cannot mistake a walk for absolute trust.
            "trust_basis": "pinned checkpoint; every interval verified forward from it",
        }


def _b64(value: str, what: str, expect_len: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise MeshError(f"{what} must be a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise MeshError(f"{what} is not valid base64") from exc
    if expect_len is not None and len(raw) != expect_len:
        raise MeshError(f"{what} must decode to {expect_len} bytes, got {len(raw)}")
    return raw


def load_bundle(path: pathlib.Path) -> dict:
    """Read a captured proofpack, gzipped or plain, with a hard size cap.

    The cap is checked twice: on the file's own size before opening (cheap, catches a
    large plain file), and on the bytes actually read *after* decompression (catches a
    gzip bomb, whose compressed size says nothing about what it expands to).
    """
    try:
        on_disk = path.stat().st_size
    except OSError as exc:
        raise MeshError(f"cannot read {path}: {exc}") from exc
    if on_disk > MAX_BUNDLE_BYTES:
        raise MeshError(
            f"{path} is {on_disk} bytes on disk, over the {MAX_BUNDLE_BYTES} byte limit")

    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rb") as handle:
            raw = handle.read(MAX_BUNDLE_BYTES + 1)
    except MeshError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        # A truncated gzip stream raises EOFError, not OSError: `read()` on a stream
        # whose trailer is missing reports end-of-file. zlib.error covers a corrupt
        # deflate block. Both are the caller's input being wrong, so both are MeshError.
        raise MeshError(f"cannot read {path}: {exc}") from exc
    if len(raw) > MAX_BUNDLE_BYTES:
        raise MeshError(
            f"{path} expands past the {MAX_BUNDLE_BYTES} byte limit; refusing to parse it")

    try:
        bundle = json.loads(raw)
    except RecursionError as exc:
        raise MeshError(f"{path} is nested too deeply to parse") from exc
    except ValueError as exc:
        raise MeshError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(bundle, dict):
        raise MeshError(f"{path} must contain a JSON object")
    return bundle


def links_from_directory(directory: pathlib.Path | str, genesis_hash: bytes, *,
                         rounds: set[int] | None = None,
                         max_links: int = 4096) -> dict:
    """Build round-keyed chain links from ``<round>.json`` / ``<round>.json.gz`` files.

    The filename is not decoration: it must be the round the bundle's own state-proof
    message attests. A mislabelled capture would otherwise be walked as if it belonged
    somewhere it does not.

    ``rounds`` limits loading to the intervals a walk actually needs. Without it a
    directory is decoded in full, so per-file size caps bound each capture but not the
    total -- a directory of a thousand captures is loaded to walk one link.
    """
    if rounds is not None:
        if not isinstance(rounds, set):
            raise MeshError("rounds must be a set of integers")
        if len(rounds) > max_links:
            raise MeshError(f"walk would need {len(rounds)} links, over the {max_links} limit")
    from avm_proofpack import mpack
    from avm_proofpack.consensus import chain as chain_module

    root = pathlib.Path(directory)
    if not root.exists():
        raise MeshError(f"bundle directory does not exist: {root}")
    if not root.is_dir():
        raise MeshError(f"bundle directory is not a directory: {root}")

    links: dict[int, object] = {}
    for path in sorted(root.iterdir()):
        if not path.is_file():
            continue
        # ".json.gz" is eight characters; ".json" four. Stripping the wrong count
        # leaves a digit behind and every bundle then looks mislabelled.
        stem = path.name[:-8] if path.name.endswith(".json.gz") else path.stem
        # isdigit() is true for characters like "²" that int() then rejects, so the
        # grammar is ASCII decimal digits, checked before conversion.
        if not (stem.isascii() and stem.isdigit()):
            # A file outside the round grammar is only a problem if the walk needed it;
            # stray files in a capture directory are common and harmless.
            if rounds is None:
                raise MeshError(f"{path.name}: filename must be the attested round "
                                "(ASCII decimal digits)")
            continue
        declared_round = int(stem)
        if rounds is not None and declared_round not in rounds:
            continue

        bundle = load_bundle(path)
        for key in ("state_proof_msgpack_b64", "state_proof_message"):
            if key not in bundle:
                raise MeshError(f"{path.name}: missing {key}")

        try:
            state_proof = mpack.decode(base64.b64decode(bundle["state_proof_msgpack_b64"]))
            message = bundle["state_proof_message"]
            attested = chain_module.message_round(message)
        except Exception as exc:
            raise MeshError(f"{path.name}: cannot decode the state proof: {exc}") from exc

        if attested != declared_round:
            raise MeshError(
                f"{path.name}: file is named round {declared_round} but its message "
                f"attests round {attested}")
        if declared_round in links:
            raise MeshError(f"two bundles claim round {declared_round}")
        links[declared_round] = chain_module.ChainLink(
            state_proof=state_proof, message=message, genesis_hash=genesis_hash)
    if not links:
        if rounds is not None:
            wanted = ", ".join(str(r) for r in sorted(rounds)[:3])
            raise MeshError(f"no captures for the rounds this walk needs ({wanted}...) in {root}")
        raise MeshError(f"no bundles found in {root}")
    return links


def walk(*, genesis_hash_b64: str, anchor_round: int, voters_commitment_b64: str,
         ln_proven_weight: int, target_round: int, bundles: pathlib.Path | str,
         interval: int = DEFAULT_INTERVAL) -> AnchorWalk:
    """Verify every interval from the checkpoint to ``target_round`` and derive its anchor."""
    from avm_proofpack.consensus import chain as chain_module

    genesis_hash = _b64(genesis_hash_b64, "genesis hash", expect_len=32)
    voters_commitment = _b64(voters_commitment_b64, "voters commitment", expect_len=64)

    if type(anchor_round) is not int or anchor_round < 0:
        raise MeshError("anchor round must be a non-negative integer")
    if type(ln_proven_weight) is not int or ln_proven_weight < 0:
        raise MeshError("anchor ln proven weight must be a non-negative integer")
    if type(target_round) is not int:
        raise MeshError("target round must be an integer")
    if type(interval) is not int or interval <= 0:
        raise MeshError("interval must be a positive integer")
    if target_round <= anchor_round:
        raise MeshError("target round must be beyond the anchor round")
    # authenticate_chain refuses an off-grid target too, so this is not the only
    # guard -- but it fails before the capture directory is read, which is the
    # difference between a quick refusal and loading gigabytes to learn the same.
    if (target_round - anchor_round) % interval:
        raise MeshError("target round is not on the anchor's interval grid")

    anchor = chain_module.ChainAnchor(
        round=anchor_round, voters_commitment=voters_commitment,
        ln_proven_weight=ln_proven_weight, genesis_hash=genesis_hash)

    needed = set(range(anchor_round + interval, target_round + 1, interval))
    links = links_from_directory(bundles, genesis_hash, rounds=needed)
    try:
        result = chain_module.authenticate_chain(
            anchor, links, target_round=target_round, interval=interval)
    except MeshError:
        raise
    except Exception as exc:                     # ChainError and anything malformed
        raise MeshError(f"cannot walk the chain: {exc}") from exc

    if not result.ok or result.target_inputs is None:
        return AnchorWalk(ok=False, links_verified=getattr(result, "links_verified", 0),
                          target_round=target_round,
                          failure=getattr(result, "failure", None) or "chain not authenticated")

    commitment, proven_weight = result.target_inputs
    return AnchorWalk(
        ok=True, links_verified=result.links_verified, target_round=target_round,
        voters_commitment_b64=base64.b64encode(commitment).decode(),
        ln_proven_weight=int(proven_weight))
