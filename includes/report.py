#!/usr/bin/env python3
"""
HTML report generation module for knock_knock security scanner.

Generates comprehensive HTML reports from scan results.
"""

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from includes.scanner import HostScanResult, Port, SSHAuditResult
from includes.nuclei_parser import NucleiFinding

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """Generates HTML security scan reports."""

    def __init__(
        self,
        report_title: str,
        ports_of_interest: List[int]
    ):
        """
        Initialize the report generator.

        Args:
            report_title: Title for the HTML report
            ports_of_interest: List of ports to highlight
        """
        self.report_title = report_title
        self.ports_of_interest = set(ports_of_interest)

    def generate(
        self,
        device_ip_mapping: Dict[str, List[str]],
        scan_results: List[HostScanResult],
        start_time: datetime,
        end_time: datetime
    ) -> str:
        """
        Generate complete HTML report.

        Args:
            device_ip_mapping: Dictionary mapping device names to IP lists
            scan_results: List of HostScanResult objects
            start_time: Scan start timestamp
            end_time: Scan end timestamp

        Returns:
            HTML string
        """
        # Build IP-to-result mapping
        ip_results = {result.ip: result for result in scan_results}

        # Calculate statistics
        stats = self._calculate_stats(scan_results)

        # Build HTML
        html = self._html_header()
        html += self._html_summary(start_time, end_time, device_ip_mapping, stats)

        # Show hosts that timed out, if any
        if stats['timed_out'] > 0:
            html += self._html_timeout_section(scan_results)

        # Per-device sections
        html += self._html_device_sections(device_ip_mapping, ip_results)

        html += self._html_footer()

        return html

    def _calculate_stats(self, results: List[HostScanResult]) -> Dict[str, int]:
        """Calculate summary statistics from scan results."""
        stats = {
            'total_hosts': len(results),
            'successful': 0,
            'errored': 0,
            'timed_out': 0,
            'total_open_ports': 0,
            'tcp_ports': 0,
            'udp_ports': 0,
            'total_nuclei_findings': 0,
            'nuclei_critical': 0,
            'nuclei_high': 0,
            'nuclei_medium': 0,
            'nuclei_low': 0,
            'nuclei_info': 0
        }

        for result in results:
            if result.status == 'success':
                stats['successful'] += 1
            elif result.status == 'timeout':
                stats['timed_out'] += 1
            else:
                stats['errored'] += 1

            stats['total_open_ports'] += len(result.open_ports)

            for port in result.open_ports:
                if port.protocol == 'tcp':
                    stats['tcp_ports'] += 1
                elif port.protocol == 'udp':
                    stats['udp_ports'] += 1

            # Count Nuclei findings by severity
            stats['total_nuclei_findings'] += len(result.nuclei_findings)
            for finding in result.nuclei_findings:
                severity = finding.severity.lower() if finding.severity else 'unknown'
                if severity == 'critical':
                    stats['nuclei_critical'] += 1
                elif severity == 'high':
                    stats['nuclei_high'] += 1
                elif severity == 'medium':
                    stats['nuclei_medium'] += 1
                elif severity == 'low':
                    stats['nuclei_low'] += 1
                elif severity == 'info':
                    stats['nuclei_info'] += 1

        return stats

    def _html_header(self) -> str:
        """Generate HTML header with CSS."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.report_title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-bottom: 2px solid #95a5a6;
            padding-bottom: 5px;
        }}
        h3 {{
            color: #7f8c8d;
            margin-top: 20px;
        }}
        .summary {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .summary-item {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .summary-item .label {{
            font-size: 0.9em;
            color: #7f8c8d;
            margin-bottom: 5px;
        }}
        .summary-item .value {{
            font-size: 1.8em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .device-section {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .ip-section {{
            margin: 20px 0;
            padding: 15px;
            background-color: #f9f9f9;
            border-left: 4px solid #3498db;
        }}
        .ip-header {{
            font-size: 1.1em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .status-success {{
            color: #27ae60;
            font-weight: bold;
        }}
        .status-error {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .status-timeout {{
            color: #e67e22;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background-color: #fff;
        }}
        th {{
            background-color: #34495e;
            color: #fff;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .port-of-interest {{
            background-color: #fff3cd;
            font-weight: bold;
        }}
        .ssh-audit-section {{
            margin: 15px 0;
            padding: 15px;
            background-color: #e8f4f8;
            border-left: 4px solid #3498db;
            border-radius: 3px;
        }}
        .ssh-version {{
            font-family: monospace;
            background-color: #ecf0f1;
            padding: 5px 10px;
            border-radius: 3px;
            display: inline-block;
            margin: 5px 0;
        }}
        .nuclei-findings-section {{
            margin: 15px 0;
            padding: 15px;
            background-color: #fef5e7;
            border-left: 4px solid #e67e22;
            border-radius: 3px;
        }}
        .nuclei-finding {{
            background-color: #fff;
            padding: 12px;
            border-radius: 3px;
            margin: 8px 0;
        }}
        .nuclei-finding code {{
            font-family: monospace;
            background-color: #ecf0f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .algorithm-list {{
            background-color: #fff;
            padding: 10px;
            border-radius: 3px;
            margin: 10px 0;
            font-size: 0.9em;
        }}
        .algorithm-list ul {{
            margin: 5px 0;
            padding-left: 20px;
        }}
        .algorithm-list li {{
            font-family: monospace;
            font-size: 0.85em;
        }}
        .critical-issue {{
            color: #c0392b;
            font-weight: bold;
            background-color: #fadbd8;
            padding: 8px;
            margin: 5px 0;
            border-radius: 3px;
            border-left: 4px solid #c0392b;
        }}
        .warning {{
            color: #d68910;
            background-color: #fcf3cf;
            padding: 8px;
            margin: 5px 0;
            border-radius: 3px;
            border-left: 4px solid #d68910;
        }}
        .error-message {{
            color: #e74c3c;
            background-color: #fadbd8;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .timeout-list {{
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }}
        .timeout-list ul {{
            margin: 10px 0;
            padding-left: 25px;
        }}
        .no-targets {{
            text-align: center;
            padding: 50px;
            background-color: #fff;
            border: 2px dashed #95a5a6;
            border-radius: 5px;
            color: #7f8c8d;
            font-size: 1.2em;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <h1>{self.report_title}</h1>
"""

    def _html_summary(
        self,
        start_time: datetime,
        end_time: datetime,
        device_ip_mapping: Dict[str, List[str]],
        stats: Dict[str, int]
    ) -> str:
        """Generate summary section."""
        duration = end_time - start_time
        duration_str = str(duration).split('.')[0]  # Remove microseconds

        unique_ips = set()
        for ips in device_ip_mapping.values():
            unique_ips.update(ips)

        html = f"""
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Start Time:</strong> {start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>End Time:</strong> {end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Duration:</strong> {duration_str}</p>

        <div class="summary-grid">
            <div class="summary-item">
                <div class="label">Devices</div>
                <div class="value">{len(device_ip_mapping)}</div>
            </div>
            <div class="summary-item">
                <div class="label">Unique IPs</div>
                <div class="value">{len(unique_ips)}</div>
            </div>
            <div class="summary-item">
                <div class="label">Successful</div>
                <div class="value" style="color: #27ae60;">{stats['successful']}</div>
            </div>
            <div class="summary-item">
                <div class="label">Errors</div>
                <div class="value" style="color: #e74c3c;">{stats['errored']}</div>
            </div>
            <div class="summary-item">
                <div class="label">Timeouts</div>
                <div class="value" style="color: #e67e22;">{stats['timed_out']}</div>
            </div>
            <div class="summary-item">
                <div class="label">Total Open Ports</div>
                <div class="value">{stats['total_open_ports']}</div>
            </div>
            <div class="summary-item">
                <div class="label">TCP Ports</div>
                <div class="value">{stats['tcp_ports']}</div>
            </div>
            <div class="summary-item">
                <div class="label">UDP Ports</div>
                <div class="value">{stats['udp_ports']}</div>
            </div>
"""

        # Add Nuclei findings section if any findings exist
        if stats['total_nuclei_findings'] > 0:
            html += f"""
            <div class="summary-item" style="grid-column: span 2;">
                <div class="label">Nuclei Findings</div>
                <div class="value" style="color: #e74c3c;">{stats['total_nuclei_findings']}</div>
            </div>
"""
            if stats['nuclei_critical'] > 0:
                html += f"""
            <div class="summary-item">
                <div class="label">Critical</div>
                <div class="value" style="color: #c0392b;">{stats['nuclei_critical']}</div>
            </div>
"""
            if stats['nuclei_high'] > 0:
                html += f"""
            <div class="summary-item">
                <div class="label">High</div>
                <div class="value" style="color: #e74c3c;">{stats['nuclei_high']}</div>
            </div>
"""
            if stats['nuclei_medium'] > 0:
                html += f"""
            <div class="summary-item">
                <div class="label">Medium</div>
                <div class="value" style="color: #e67e22;">{stats['nuclei_medium']}</div>
            </div>
"""
            if stats['nuclei_low'] > 0:
                html += f"""
            <div class="summary-item">
                <div class="label">Low</div>
                <div class="value" style="color: #f39c12;">{stats['nuclei_low']}</div>
            </div>
"""
            if stats['nuclei_info'] > 0:
                html += f"""
            <div class="summary-item">
                <div class="label">Info</div>
                <div class="value" style="color: #3498db;">{stats['nuclei_info']}</div>
            </div>
"""

        html += """
        </div>
    </div>
"""
        return html

    def _html_timeout_section(self, results: List[HostScanResult]) -> str:
        """Generate section listing timed-out hosts."""
        timed_out = [r for r in results if r.status == 'timeout']

        if not timed_out:
            return ""

        html = """
    <div class="timeout-list">
        <h3>⚠️ Hosts That Timed Out</h3>
        <ul>
"""
        for result in timed_out:
            html += f"            <li><strong>{result.ip}</strong> - {result.error_message}</li>\n"

        html += """        </ul>
    </div>
"""
        return html

    def _html_device_sections(
        self,
        device_ip_mapping: Dict[str, List[str]],
        ip_results: Dict[str, HostScanResult]
    ) -> str:
        """Generate per-device sections."""
        if not device_ip_mapping:
            return """
    <div class="no-targets">
        <p>No targets found</p>
    </div>
"""

        html = """
    <h2>Scan Results by Device</h2>
"""

        # Sort devices alphabetically
        for device_name in sorted(device_ip_mapping.keys()):
            ips = device_ip_mapping[device_name]

            html += f"""
    <div class="device-section">
        <h3>{device_name}</h3>
        <p><strong>WAN IPs:</strong> {', '.join(ips)}</p>
"""

            # Show results for each IP
            for ip in ips:
                result = ip_results.get(ip)

                if result is None:
                    html += f"""
        <div class="ip-section">
            <div class="ip-header">{ip}</div>
            <div class="error-message">No scan results available</div>
        </div>
"""
                    continue

                html += self._html_ip_section(result)

            html += """
    </div>
"""

        return html

    def _html_ip_section(self, result: HostScanResult) -> str:
        """Generate section for a single IP's scan results."""
        # Status indicator
        if result.status == 'success':
            status_class = 'status-success'
            status_text = '✓ Success'
        elif result.status == 'timeout':
            status_class = 'status-timeout'
            status_text = '⏱ Timeout'
        else:
            status_class = 'status-error'
            status_text = '✗ Error'

        # Summary
        open_port_count = len(result.open_ports)
        ssh_count = len(result.ssh_results)
        nuclei_count = len(result.nuclei_findings)
        summary = f"{open_port_count} open port{'s' if open_port_count != 1 else ''}"
        if ssh_count > 0:
            summary += f", {ssh_count} SSH endpoint{'s' if ssh_count != 1 else ''}"
        if nuclei_count > 0:
            summary += f", {nuclei_count} vulnerability finding{'s' if nuclei_count != 1 else ''}"

        html = f"""
        <div class="ip-section">
            <div class="ip-header">{result.ip}</div>
            <p><span class="{status_class}">{status_text}</span> - {summary}</p>
"""

        # Show error message if present
        if result.error_message:
            html += f"""
            <div class="error-message">
                <strong>Error:</strong> {result.error_message}
            </div>
"""

        # Show open ports table
        if result.open_ports:
            html += self._html_ports_table(result.open_ports)

        # Show SSH audit results
        if result.ssh_results:
            for ssh_result in result.ssh_results:
                html += self._html_ssh_audit(ssh_result)

        # Show Nuclei findings
        if result.nuclei_findings:
            html += self._html_nuclei_findings(result.nuclei_findings)

        html += """
        </div>
"""
        return html

    def _html_ports_table(self, ports: List[Port]) -> str:
        """Generate HTML table of open ports."""
        html = """
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
"""

        for port in sorted(ports, key=lambda p: p.port):
            # Highlight ports of interest
            row_class = "port-of-interest" if port.port in self.ports_of_interest else ""

            html += f"""
                    <tr class="{row_class}">
                        <td><strong>{port.port}</strong></td>
                        <td>{port.protocol.upper()}</td>
                        <td>{port.service or '-'}</td>
                        <td>{port.version or '-'}</td>
                        <td>{port.notes or '-'}</td>
                    </tr>
"""

        html += """
                </tbody>
            </table>
"""
        return html

    def _html_ssh_audit(self, ssh_result: SSHAuditResult) -> str:
        """Generate HTML for SSH audit results."""
        html = f"""
            <div class="ssh-audit-section">
                <h4>SSH Audit Results - Port {ssh_result.port}</h4>
"""

        # Handle connection failures
        if ssh_result.connection_failed:
            html += f"""
                <p class="error-message">Connection failed: {ssh_result.error}</p>
"""
        # Handle other errors
        elif ssh_result.error:
            html += f"""
                <p class="error-message">Error: {ssh_result.error}</p>
"""
        # Show SSH info
        else:
            if ssh_result.banner:
                html += f"""
                <p><strong>Banner:</strong> <span class="ssh-version">{ssh_result.banner}</span></p>
"""
            if ssh_result.ssh_version:
                html += f"""
                <p><strong>SSH Version:</strong> {ssh_result.ssh_version}</p>
"""

            # Show algorithms
            if ssh_result.key_exchange or ssh_result.ciphers or ssh_result.macs:
                html += """
                <div class="algorithm-list">
"""
                if ssh_result.key_exchange:
                    html += f"""
                    <p><strong>Key Exchange Algorithms:</strong></p>
                    <ul>
"""
                    for algo in ssh_result.key_exchange[:5]:  # Limit to first 5
                        html += f"                        <li>{algo}</li>\n"
                    if len(ssh_result.key_exchange) > 5:
                        html += f"                        <li><em>... and {len(ssh_result.key_exchange) - 5} more</em></li>\n"
                    html += "                    </ul>\n"

                if ssh_result.ciphers:
                    html += f"""
                    <p><strong>Ciphers:</strong></p>
                    <ul>
"""
                    for cipher in ssh_result.ciphers[:5]:  # Limit to first 5
                        html += f"                        <li>{cipher}</li>\n"
                    if len(ssh_result.ciphers) > 5:
                        html += f"                        <li><em>... and {len(ssh_result.ciphers) - 5} more</em></li>\n"
                    html += "                    </ul>\n"

                if ssh_result.macs:
                    html += f"""
                    <p><strong>MACs:</strong></p>
                    <ul>
"""
                    for mac in ssh_result.macs[:5]:  # Limit to first 5
                        html += f"                        <li>{mac}</li>\n"
                    if len(ssh_result.macs) > 5:
                        html += f"                        <li><em>... and {len(ssh_result.macs) - 5} more</em></li>\n"
                    html += "                    </ul>\n"

                html += """
                </div>
"""

            # Show critical issues
            if ssh_result.critical_issues:
                html += """
                <h5 style="color: #c0392b;">Critical Issues:</h5>
"""
                for issue in ssh_result.critical_issues:
                    html += f"""
                <div class="critical-issue">🔴 {issue}</div>
"""

            # Show warnings
            if ssh_result.warnings:
                html += """
                <h5 style="color: #d68910;">Warnings:</h5>
"""
                for warning in ssh_result.warnings:
                    html += f"""
                <div class="warning">⚠️ {warning}</div>
"""

        html += """
            </div>
"""
        return html

    def _html_nuclei_findings(self, findings: List[NucleiFinding]) -> str:
        """Generate HTML for Nuclei vulnerability findings."""
        html = """
            <div class="nuclei-findings-section">
                <h4>Nuclei Vulnerability Findings</h4>
"""

        # Group findings by severity for better display
        by_severity = defaultdict(list)
        for finding in findings:
            severity = finding.severity.lower() if finding.severity else 'unknown'
            by_severity[severity].append(finding)

        # Display in order: critical, high, medium, low, info, unknown
        severity_order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
        severity_colors = {
            'critical': '#c0392b',
            'high': '#e74c3c',
            'medium': '#e67e22',
            'low': '#f39c12',
            'info': '#3498db',
            'unknown': '#95a5a6'
        }
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': 'ℹ️',
            'unknown': '❓'
        }

        for severity in severity_order:
            if severity not in by_severity:
                continue

            severity_findings = by_severity[severity]
            color = severity_colors.get(severity, '#95a5a6')
            icon = severity_icons.get(severity, '❓')

            html += f"""
                <h5 style="color: {color};">{icon} {severity.upper()} ({len(severity_findings)})</h5>
"""

            for finding in severity_findings:
                # Escape HTML in strings
                name = finding.name.replace('<', '&lt;').replace('>', '&gt;') if finding.name else 'Unknown'
                template_id = finding.template_id.replace('<', '&lt;').replace('>', '&gt;') if finding.template_id else 'Unknown'

                # Generate hyperlink for CVE IDs
                template_id_display = template_id
                if finding.template_id and finding.template_id.upper().startswith('CVE-'):
                    # Extract CVE ID and create NVD link
                    cve_id = finding.template_id.upper()
                    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    template_id_display = f'<a href="{nvd_url}" target="_blank" style="color: #3498db; text-decoration: underline;">{template_id}</a>'

                html += f"""
                <div class="nuclei-finding" style="border-left: 4px solid {color}; margin-left: 10px; padding-left: 10px; margin-bottom: 10px;">
                    <p><strong>{name}</strong></p>
                    <p><em>Template ID:</em> <code>{template_id_display}</code></p>
"""

                if finding.matched_at:
                    matched_at = finding.matched_at.replace('<', '&lt;').replace('>', '&gt;')
                    html += f"                    <p><em>Matched at:</em> <code>{matched_at}</code></p>\n"

                if finding.type:
                    html += f"                    <p><em>Type:</em> {finding.type}</p>\n"

                if finding.extracted_results:
                    html += "                    <p><em>Extracted Results:</em></p>\n"
                    html += "                    <ul>\n"
                    for result in finding.extracted_results[:5]:  # Limit to first 5
                        result_escaped = str(result).replace('<', '&lt;').replace('>', '&gt;')
                        html += f"                        <li>{result_escaped}</li>\n"
                    if len(finding.extracted_results) > 5:
                        html += f"                        <li><em>... and {len(finding.extracted_results) - 5} more</em></li>\n"
                    html += "                    </ul>\n"

                html += """
                </div>
"""

        html += """
            </div>
"""
        return html

    def _html_footer(self) -> str:
        """Generate HTML footer."""
        return f"""
    <div class="footer">
        <p>Generated by knock_knock security scanner on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>
"""
