"""Module entrypoint enabling `python -m chaoslab`."""

import sys

from chaoslab.cli import main

if __name__ == "__main__":
    sys.exit(main())
