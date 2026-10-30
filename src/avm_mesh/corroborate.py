"""Collect a settlement receipt from several witnesses and check they agree.

A single witness is a single operator's word. The mesh only becomes interesting
when independent operators return the *same* receipt, and "independent" is a claim
about operators, not endpoints: two URLs belonging to one operator are one voice
(and are the cheapest way to fake agreement).

What this module refuses to do:

- count a witness with no published card toward independence. An endpoint that
  will not say who operates it cannot corroborate anybody; it is collected and
  reported, never counted.
- treat identical content hashes as agreement when the pointers differ. Two
  receipts can agree that a transaction happened and disagree about which
  proofpack evidences it, which is exactly the substitution the receipt design
  exists to prevent.
- call partial agreement success. Agreement is all-or-nothing across the
  witnesses that were collected and verified.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .receipt import MeshError, SettlementReceipt, bundle_digest


@dataclass
class WitnessView:
    """What one witness said, and whether it can count."""

    url: str
    witness_id: str | None = None
    operator_id: str | None = None
    chain: str | None = None
    round: int | None = None
    trust_root: str | None = None
    pointer_digest: str | None = None
    #: The witness served a proofpack whose bytes hash to the digest it points at.
    pointer_verified: bool = False
    problem: str | None = None

    @property
    def counts(self) -> bool:
        """Count only a witness that answered, proved its pointer, and named its operator."""
        return (self.problem is None and self.pointer_verified
                and self.operator_id is not None)


@dataclass
class Corroboration:
    txid: str
    views: list[WitnessView] = field(default_factory=list)
    min_operators: int = 2
    problems: list[str] = field(default_factory=list)

    @property
    def operators(self) -> tuple[str, ...]:
        return tuple(sorted({v.operator_id for v in self.views if v.counts}))

    @property
    def agreed_digest(self) -> str | None:
        """The proofpack digest all counting witnesses agree on."""
        digests = {v.pointer_digest for v in self.views if v.counts}
        return digests.pop() if len(digests) == 1 else None

    @property
    def agreed(self) -> bool:
        if self.problems:
            return False
        if len(self.operators) < self.min_operators:
            return False
        return self.agreed_digest is not None

    def to_dict(self) -> dict:
        return {
            "txid": self.txid,
            "agreed": self.agreed,
            "agreed_digest": self.agreed_digest,
            "operators": list(self.operators),
            "min_operators": self.min_operators,
            "problems": list(self.problems),
            "witnesses": [
                {
                    "url": v.url,
                    "witness_id": v.witness_id,
                    "operator_id": v.operator_id,
                    "chain": v.chain,
                    "round": v.round,
                    "trust_root": v.trust_root,
                    "pointer_digest": v.pointer_digest,
                    "pointer_verified": v.pointer_verified,
                    "counts": v.counts,
                    "problem": v.problem,
                }
                for v in self.views
            ],
        }


def _get(url: str, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError) as exc:
        raise MeshError(f"cannot reach {url}: {exc}") from exc


def _card(base: str, timeout: float) -> dict:
    status, body = _get(base.rstrip("/") + "/witness", timeout)
    if status != 200:
        return {}
    try:
        card = json.loads(body)
    except ValueError:
        return {}
    return card if isinstance(card, dict) else {}


def collect(txid: str, witness_urls: list[str], *, min_operators: int = 2,
            timeout: float = 5.0) -> Corroboration:
    """Ask each witness for the same receipt and decide whether they agree."""
    if not isinstance(txid, str) or not txid:
        raise MeshError("txid must be a non-empty string")
    if not witness_urls:
        raise MeshError("at least one witness is required")
    if min_operators < 1:
        raise MeshError("min_operators must be at least 1")

    result = Corroboration(txid=txid, min_operators=min_operators)

    for url in witness_urls:
        view = WitnessView(url=url)
        try:
            card = _card(url, timeout)
            view.witness_id = card.get("witness_id")
            view.operator_id = card.get("operator_id")

            status, body = _get(f"{url.rstrip('/')}/receipts/{txid}", timeout)
            if status != 200:
                view.problem = f"receipt not served (HTTP {status})"
            else:
                receipt = SettlementReceipt.from_dict(json.loads(body))
                if receipt.txid != txid:
                    raise MeshError(f"witness returned a receipt for {receipt.txid}")
                view.chain, view.round = receipt.chain, receipt.round
                view.trust_root = receipt.trust_root
                view.pointer_digest = receipt.pointer.digest

                # The pointer is a claim. Fetch the proofpack and hash it: a
                # witness that points at good evidence while serving something
                # else is the substitution this design exists to catch.
                status, body = _get(
                    f"{url.rstrip('/')}/proofpacks/{receipt.pointer.digest}", timeout)
                if status != 200:
                    view.problem = f"proofpack not served (HTTP {status})"
                else:
                    served = json.loads(body)
                    if bundle_digest(served) != receipt.pointer.digest:
                        view.problem = "proofpack bytes do not match the pointer digest"
                    else:
                        view.pointer_verified = True
        except MeshError as exc:
            view.problem = str(exc)
        except (ValueError, KeyError, TypeError) as exc:
            view.problem = f"malformed response: {exc}"
        result.views.append(view)

    counting = [v for v in result.views if v.counts]
    if not counting:
        result.problems.append("no witness published an operator identity that verified")

    digests = {v.pointer_digest for v in counting}
    if len(digests) > 1:
        result.problems.append(
            "witnesses disagree about which proofpack evidences this settlement")
    rounds = {v.round for v in counting}
    if len(rounds) > 1:
        result.problems.append("witnesses report different rounds for the same txid")
    tiers = {v.trust_root for v in counting}
    if len(tiers) > 1:
        result.problems.append("witnesses disagree about the trust tier")
    if len(result.operators) < min_operators:
        result.problems.append(
            f"only {len(result.operators)} independent operator(s); {min_operators} required "
            "(endpoints of one operator are one voice)")
    return result
