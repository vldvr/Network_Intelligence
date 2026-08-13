#!/usr/bin/env python3
"""Launches the GUI.

Kept at the repository root because that is how the tool has always been
started. The real entry points are the ``netintel-gui`` and ``netintel``
console scripts installed by ``pip install -e .``.
"""

from __future__ import annotations

import sys

from netintel.errors import NetIntelError


def main() -> int:
    from netintel.ui.app import run

    return run(sys.argv)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except NetIntelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
