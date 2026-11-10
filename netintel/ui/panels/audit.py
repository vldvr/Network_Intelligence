"""Domain audit and port scan panels."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PyQt5.QtWidgets import QDoubleSpinBox, QFormLayout, QLineEdit, QVBoxLayout

from netintel.adapters.factory import build_resolver
from netintel.cancellation import CancellationToken
from netintel.core.findings import format_findings
from netintel.core.portscan import OpenPort, format_port_report, parse_ports, run_port_scan
from netintel.core.scope import ScopePolicy
from netintel.core.targets import is_hostname
from netintel.errors import TargetError
from netintel.ui.panels.base import OperationPanel
from netintel.ui.workers import Worker


def _run_audit(domain: str, *, token: CancellationToken, on_progress: Callable[[Any], None]) -> Any:
    from netintel.adapters.netprobes import WireDnsClient, fetch_headers, probe_tls
    from netintel.core.audit import AuditProbes, run_audit

    client = WireDnsClient()
    probes = AuditProbes(client.query, client.txt, probe_tls, fetch_headers)
    return run_audit(domain, probes, on_section=lambda name, items: on_progress((name, items)))


class AuditPanel(OperationPanel):
    title = "Domain audit"
    description = (
        "Passive external audit: DNS records, SPF/DMARC (can the domain be "
        "spoofed?), the TLS certificate and HTTP security headers. Sends only "
        "what any visitor sends — no port scanning."
    )
    start_label = "Audit"

    def build_controls(self, layout: QVBoxLayout) -> None:
        form = QFormLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.returnPressed.connect(self.start)
        form.addRow("Domain", self.domain_input)
        layout.addLayout(form)

    def create_worker(self) -> Worker:
        domain = self.domain_input.text().strip()
        if not domain:
            raise TargetError("enter a domain")
        return Worker(_run_audit, domain)

    def on_progress(self, item: Any) -> None:
        name, findings = item
        self.append(f"== {name}")
        self.append(format_findings(findings))
        self.append("")

    def on_finished(self, result: Any) -> None:
        if result is None:
            self.set_status("cancelled")
            return
        for error in result.errors:
            self.append(f"error: {error}")
        grade = f", headers {result.header_grade}" if result.header_grade else ""
        self.set_status(f"worst finding: {result.worst.label}{grade}")


def _run_ports(
    target: str,
    ports: tuple[int, ...],
    timeout: float,
    *,
    token: CancellationToken,
    on_progress: Callable[[Any], None],
) -> Any:
    from netintel.adapters.netprobes import scan_ports

    if is_hostname(target):
        target = build_resolver().resolve(target)
    return run_port_scan(
        target,
        ports,
        scan_ports,
        policy=ScopePolicy.load(),
        timeout=timeout,
        token=token,
        on_open=on_progress,
    )


class PortsPanel(OperationPanel):
    title = "Ports"
    description = (
        "TCP connect scan with banner grabbing — runs without root and without "
        "nmap. Limited to the authorised scope (private ranges by default)."
    )
    start_label = "Scan"

    def build_controls(self, layout: QVBoxLayout) -> None:
        form = QFormLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("127.0.0.1, 192.168.1.0/24, 10.0.0.5-40")
        self.ports_input = QLineEdit("top")
        self.ports_input.setPlaceholderText("22,80,8000-8100, top or all")
        self.timeout_input = QDoubleSpinBox()
        self.timeout_input.setRange(0.1, 10.0)
        self.timeout_input.setValue(1.0)
        self.timeout_input.setSuffix(" s")
        form.addRow("Targets", self.target_input)
        form.addRow("Ports", self.ports_input)
        form.addRow("Timeout", self.timeout_input)
        layout.addLayout(form)

    def create_worker(self) -> Worker:
        target = self.target_input.text().strip()
        if not target:
            raise TargetError("enter a host or range")
        ports = parse_ports(self.ports_input.text())
        return Worker(_run_ports, target, ports, self.timeout_input.value())

    def on_progress(self, item: Any) -> None:
        if isinstance(item, OpenPort):
            self.append(f"open: {item.host}:{item.port}")

    def on_finished(self, result: Any) -> None:
        if result is None:
            self.set_status("cancelled")
            return
        self.output.clear()
        self.append(format_port_report(result))
        if result.findings:
            self.append("")
            self.append(format_findings(result.findings))
        self.set_status(f"{len(result.open_ports)} open")
