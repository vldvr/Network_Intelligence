"""PyQt5 front end.

Presentation only. Every module here is allowed to import from ``core``;
nothing in ``core`` is allowed to import from here, and the test suite
enforces that (see ``tests/test_layering.py``).
"""

from netintel.ui.app import run

__all__ = ["run"]
