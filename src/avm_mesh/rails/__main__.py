"""``python -m avm_mesh.rails`` -- the rails-shaped entry point.

Delegates to the existing CLI so there is exactly one implementation of the
command-line behaviour and its exit codes (0 verified, 2 failed, 3 usage):

    python -m avm_mesh.rails verify receipt.json --evidence ./proofpacks \
        --genesis <b64> --voters-commitment <b64> --ln-proven-weight <n>
"""
import sys

from ..cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
