"""Exception hierarchy.

Every error raised deliberately by this package derives from
:class:`NetIntelError`, so front ends can catch one type and know the message
is safe (and useful) to show a user. Anything else escaping ``core`` is a bug.
"""

from __future__ import annotations


class NetIntelError(Exception):
    """Base class for all errors raised by NetworkIntelligence."""


class TargetError(NetIntelError):
    """The user supplied a host, address or range that cannot be used."""


class ScopeViolationError(NetIntelError):
    """The requested target is outside the configured authorised scope.

    Active scanning of hosts you do not own is unlawful in many jurisdictions.
    The scope guard (:mod:`netintel.core.scope`) turns that from a policy note
    in the README into something the code actually enforces.
    """


class BackendUnavailableError(NetIntelError):
    """A required optional dependency or system tool is missing.

    Carries an actionable hint rather than a bare ``ImportError`` traceback.
    """

    def __init__(self, backend: str, hint: str) -> None:
        super().__init__(f"{backend} is unavailable: {hint}")
        self.backend = backend
        self.hint = hint


class GeoIPError(NetIntelError):
    """A geolocation lookup failed or was refused by the provider."""


class PrivilegeError(NetIntelError):
    """The operation needs raw-socket privileges that the process lacks."""


class CancelledError(NetIntelError):
    """Raised when a cooperative cancellation token was tripped."""
