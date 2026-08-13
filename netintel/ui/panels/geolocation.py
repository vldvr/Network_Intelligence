"""Geolocation panel."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from PyQt5.QtWidgets import QFormLayout, QLineEdit, QVBoxLayout

from netintel.adapters.factory import build_geoip_provider, build_resolver
from netintel.cancellation import CancellationToken
from netintel.core.targets import is_hostname, parse_address
from netintel.errors import TargetError
from netintel.models import GeoLocation
from netintel.ports import NameResolver
from netintel.ui.panels.base import OperationPanel
from netintel.ui.workers import Worker


def _run_lookup(
    provider: Any,
    resolver: NameResolver,
    targets: Sequence[str],
    *,
    token: CancellationToken,
    on_progress: Callable[[Any], None],
) -> list[tuple[str, GeoLocation | None]]:
    pairs: list[tuple[str, str]] = []
    for target in targets:
        # Resolution is I/O and belongs on the worker, not in the click handler.
        ip = resolver.resolve(target) if is_hostname(target) else str(parse_address(target))
        pairs.append((target, ip))

    located = provider.lookup_many([ip for _, ip in pairs], token=token)
    results: list[tuple[str, GeoLocation | None]] = []
    for target, ip in pairs:
        location = located.get(ip)
        results.append((target, location))
        on_progress((target, ip, location))
    return results


class GeolocationPanel(OperationPanel):
    title = "Geolocation"
    description = (
        "Looks up the approximate location of hosts. GeoIP is inference from "
        "registry and routing data — it identifies a network, not a person, "
        "and is frequently wrong about anything finer than a country."
    )
    start_label = "Look up"

    def build_controls(self, layout: QVBoxLayout) -> None:
        form = QFormLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("one or more hosts, separated by spaces or commas")
        self.target_input.returnPressed.connect(self.start)
        form.addRow("Targets", self.target_input)
        layout.addLayout(form)

    def create_worker(self) -> Worker:
        raw = self.target_input.text().strip()
        targets = [item for item in raw.replace(",", " ").split() if item]
        if not targets:
            raise TargetError("enter at least one hostname or IP address")

        return Worker(_run_lookup, build_geoip_provider(), build_resolver(), targets)

    def on_progress(self, item: Any) -> None:
        target, ip, location = item
        if location is None:
            self.append(f"{target} ({ip}): no location available")
            return

        self.append(f"{target} ({ip})")
        self.append(f"    {location.describe()}")
        self.append(
            f"    {location.latitude:.4f}, {location.longitude:.4f}  ({location.accuracy_note})"
        )
        if location.autonomous_system:
            self.append(f"    network: {location.autonomous_system}")
        if location.is_hosting or location.is_proxy:
            self.append(
                "    datacentre or proxy address — the coordinates describe the "
                "hosting facility, not whoever is using it"
            )

    def on_finished(self, result: Any) -> None:
        if result is None:
            self.set_status("cancelled")
            return
        located = sum(1 for _, location in result if location is not None)
        self.set_status(f"{located}/{len(result)} located")
