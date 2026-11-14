"""End-to-end AC2 consent binding, on real Algorand AND Voi mainnet captures.

Run it:

    python examples/ac2_consent_demo.py

What it does, per chain:
  1. Loads the checked-in mainnet capture and verifies it against a pinned
     genesis hash and an anchor, reaching ``stake_attested``.
  2. Reads the payer out of the AUTHENTICATED SignedTxnInBlock.
  3. Builds a sealed receipt carrying an AC2 consent block, signed by a key
     the demo generates.
  4. Verifies the consent and prints the level reached.
  5. Shows the refusals: a consent from the wrong key, a consent replayed onto a
     different settlement, and a consent edited after sealing.

READ THIS BEFORE QUOTING THE OUTPUT
-----------------------------------
The demo generates the consent keypair, because the mainnet accounts' private
keys are not ours. So step 4 proves the *machinery* on real chain evidence, while
the final "payer approved" step is shown with a key the demo holds. That is
stated in the output, not glossed over. A genuine end-to-end run needs a real AC2
wallet approving for an account it controls.
"""
from __future__ import annotations

import base64
import gzip
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Prefer an INSTALLED avm_mesh over the source tree beside this file, so running
# the demo in a clean room exercises the wheel rather than the checkout. The
# source tree is only a convenience for a developer who has not installed it.
try:
    import avm_mesh  # noqa: F401
except ImportError:  # pragma: no cover - developer convenience
    sys.path.insert(0, str(ROOT / "src"))

from avm_mesh import MeshError, ac2, sealed  # noqa: E402
from avm_mesh.receipt import _verify_bundle_dict  # noqa: E402
from avm_proofpack.verify import TrustedVoters  # noqa: E402

CHAINS = [
    ("Algorand mainnet", ROOT / "examples" / "proofpack-66457600.json",
     "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="),
    ("Voi mainnet", ROOT / "examples" / "voi-proofpack-24213754.json.gz",
     "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="),
]


def load(path: pathlib.Path) -> dict:
    raw = path.read_bytes()
    text = gzip.decompress(raw).decode() if path.suffix == ".gz" else raw.decode()
    return json.loads(text)


def anchor_for(bundle: dict) -> TrustedVoters:
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(prev["voters_commitment_b64"]),
                         int(prev["ln_proven_weight"]))


def sealed_with_consent(settlement, bundle, keypair):
    sk, pk = keypair
    consent = ac2.build_consent(
        did="did:key:z6MkDemoController",
        sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(ac2.consent_payload(settlement))).decode(),
        settlement=settlement,
    )
    return sealed.seal(
        {"version": 1, "settlement": settlement, "ac2_consent": consent},
        bundle, "mem://demo", trusted_voters=anchor_for(bundle),
    ), consent


def run_chain(label: str, path: pathlib.Path, genesis_b64: str) -> bool:
    print(f"\n{'=' * 72}\n{label}\n{'=' * 72}")
    if not path.exists():
        print(f"  SKIP: capture missing at {path}")
        return False

    bundle = load(path)
    report = _verify_bundle_dict(bundle, anchor_for(bundle),
                                 base64.b64decode(genesis_b64))
    print(f"  [1] evidence verified: {report.genesis_id}  txid {report.txid[:16]}... "
          f"round {report.round}")
    print(f"      trust root: {report.trust_root}")

    settlement = {"chain": report.genesis_id, "txid": report.txid,
                  "round": report.round, "amount": "0", "asset": 586896}

    # The payer, read out of the authenticated transaction bytes.
    sender = ac2.sender_from_bundle(bundle, report.genesis_id)
    print(f"  [2] payer from authenticated STIB: "
          f"{base64.b32encode(sender).decode().rstrip('=')}")

    ok = True

    # --- the machinery on a key the demo holds -------------------------------
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    envelope, consent = sealed_with_consent(settlement, bundle, (sk, pk))

    out = ac2.verify_consent(envelope, expected_sender=pk)
    print(f"  [3] consent verified, level: {out['level']}")
    ok &= out["level"] == "sender_bound"

    combined = ac2.consent_level(envelope, report, expected_sender=pk)
    print(f"  [4] with the proofpack: {combined['level']}")
    ok &= combined["level"] == "consensus_bound"

    # --- refusals ------------------------------------------------------------
    sk2 = Ed25519PrivateKey.generate()
    pk2 = sk2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    try:
        ac2.verify_consent(envelope, expected_sender=sender)
        print("  [5] WRONG-KEY CHECK FAILED (a foreign consent was accepted)")
        ok = False
    except MeshError as exc:
        print(f"  [5] payer binding enforced: {str(exc)[:64]}...")

    tampered = dict(settlement, amount="999999999")
    replayed = sealed.seal({"version": 1, "settlement": tampered,
                            "ac2_consent": consent}, bundle, "mem://demo",
                           trusted_voters=anchor_for(bundle))
    try:
        ac2.verify_consent(replayed)
        print("  [6] REPLAY CHECK FAILED (a consent for another settlement passed)")
        ok = False
    except MeshError as exc:
        print(f"  [6] replay refused: {str(exc)[:64]}...")

    content = json.loads(base64.b64decode(envelope["canonical_bytes_b64"]))
    content["ac2_consent"]["did"] = "did:key:z6MkAttacker"
    edited = dict(envelope)
    edited["canonical_bytes_b64"] = base64.b64encode(
        ac2.canonical_bytes(content)).decode()
    try:
        ac2.verify_consent(edited)
        print("  [7] TAMPER CHECK FAILED (an edited consent passed)")
        ok = False
    except MeshError as exc:
        print(f"  [7] edit detected: {str(exc)[:64]}...")

    print(f"  --> {'PASS' if ok else 'FAIL'} on {report.genesis_id}")
    print(f"      NOTE: the consent key above is generated by this demo "
          f"({base64.b32encode(pk).decode().rstrip('=')[:12]}...),")
    print(f"      not the real payer. The chain evidence is real; the approval "
          f"is synthetic.")
    return ok


def main() -> int:
    print("AC2 <-> avm-mesh consent binding, on real mainnet captures")
    results = [run_chain(*c) for c in CHAINS]
    print(f"\n{'=' * 72}")
    if all(results):
        print("RESULT: PASS -- consent binding works on Algorand and Voi; "
              "every refusal held")
        return 0
    print("RESULT: FAIL -- see the FAIL line above")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
