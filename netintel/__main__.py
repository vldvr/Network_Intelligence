"""``python -m netintel`` — runs the CLI."""

from __future__ import annotations

import sys

from netintel.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
