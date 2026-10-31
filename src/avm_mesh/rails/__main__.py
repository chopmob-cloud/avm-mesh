"""``python -m avm_mesh.rails`` -- the rails-shaped entry point.

The rails verifier exits 0 (verified), 1 (not verified), 2 (usage). The shared CLI
exits 0, 2, 3. A drop-in has to match the tool it replaces, or an operator's
existing scripts read a failed verification as a usage error -- so the codes are
translated here rather than the behaviour being re-implemented.

    python -m avm_mesh.rails verify receipt.json --evidence ./proofpacks \\
        --genesis <b64> --voters-commitment <b64> --ln-proven-weight <n>
"""
import sys

from ..cli import main as cli_main

#: shared CLI code -> rails code
_EXIT_MAP = {0: 0, 2: 1, 3: 2}


def main(argv=None):
    # The rails receipt signs the hex digest, not the raw one. Delegating without
    # saying so verifies rails receipts under the wrong convention.
    code = cli_main(argv if argv is not None else sys.argv[1:], signature_style="hex")
    return _EXIT_MAP.get(code, code)


if __name__ == "__main__":
    raise SystemExit(main())
