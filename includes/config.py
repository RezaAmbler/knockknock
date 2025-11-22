#!/usr/bin/env python3
"""
Configuration management for knock_knock security scanner.

This module handles loading and validating the YAML configuration file.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


class Config:
    """Configuration class for knock_knock scanner."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration from YAML file.

        Args:
            config_path: Path to config.yaml. If None, looks in script directory.
        """
        if config_path is None:
            # Default to config.yaml in the conf/ directory at project root
            # Path(__file__).parent is includes/, parent.parent is project root
            project_root = Path(__file__).parent.parent
            config_path = project_root / "conf" / "config.yaml"
        else:
            config_path = Path(config_path)

        if not config_path.exists():
            print(f"Error: Configuration file not found: {config_path}")
            sys.exit(1)

        try:
            with open(config_path, 'r') as f:
                self._config: Dict[str, Any] = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML configuration: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading configuration file: {e}")
            sys.exit(1)

    # Masscan settings
    @property
    def masscan_binary(self) -> str:
        """Path or command for masscan binary."""
        return self._config.get('masscan', {}).get('binary', 'masscan')

    @property
    def masscan_rate(self) -> int:
        """Masscan packet rate limit in packets per second."""
        return self._config.get('masscan', {}).get('rate', 1000)

    @property
    def masscan_interface(self) -> Optional[str]:
        """Network interface for masscan to use (optional)."""
        return self._config.get('masscan', {}).get('interface')

    # Nmap settings
    @property
    def nmap_binary(self) -> str:
        """Path or command for nmap binary."""
        return self._config.get('nmap', {}).get('binary', 'nmap')

    @property
    def nmap_args(self) -> List[str]:
        """List of nmap command-line arguments."""
        return self._config.get('nmap', {}).get('args', ['-sV', '-sC', '-T4', '-Pn'])

    # SSH-audit settings
    @property
    def ssh_audit_binary(self) -> str:
        """Path or command for ssh-audit binary."""
        return self._config.get('ssh_audit', {}).get('binary', 'ssh-audit')

    @property
    def ssh_ports(self) -> List[int]:
        """List of SSH ports to scan."""
        return self._config.get('ssh_audit', {}).get('ports', [22, 830])

    # Nuclei settings
    @property
    def nuclei_enabled(self) -> bool:
        """Whether Nuclei vulnerability scanning is enabled."""
        return self._config.get('nuclei', {}).get('enabled', False)

    @property
    def nuclei_binary(self) -> str:
        """Path to nuclei binary."""
        return self._config.get('nuclei', {}).get('binary', 'nuclei')

    @property
    def nuclei_severity(self) -> str:
        """Severity filter for Nuclei (comma-separated)."""
        return self._config.get('nuclei', {}).get('severity', 'critical,high,medium')

    @property
    def nuclei_timeout(self) -> int:
        """Timeout for Nuclei scan per host in seconds."""
        return self._config.get('nuclei', {}).get('timeout', 300)

    @property
    def nuclei_templates(self) -> Optional[str]:
        """Path to custom Nuclei templates directory."""
        templates = self._config.get('nuclei', {}).get('templates', '')
        return templates if templates else None

    @property
    def nuclei_scan_mode(self) -> str:
        """Nuclei scan mode: 'ips' or 'urls'."""
        return self._config.get('nuclei', {}).get('scan_mode', 'ips')

    # Concurrency and timeout settings
    @property
    def max_concurrent_hosts(self) -> int:
        """Maximum number of hosts to scan concurrently."""
        return self._config.get('concurrency', {}).get('max_concurrent_hosts', 10)

    @property
    def host_timeout_seconds(self) -> int:
        """Per-host scan timeout in seconds."""
        return self._config.get('concurrency', {}).get('host_timeout_seconds', 600)

    # SMTP / Email settings
    @property
    def smtp_host(self) -> Optional[str]:
        """SMTP server hostname."""
        return self._config.get('email', {}).get('smtp_host')

    @property
    def smtp_port(self) -> int:
        """SMTP server port."""
        return self._config.get('email', {}).get('smtp_port', 25)

    @property
    def smtp_use_tls(self) -> bool:
        """Whether to use TLS for SMTP connection."""
        return self._config.get('email', {}).get('smtp_use_tls', False)

    @property
    def smtp_username(self) -> Optional[str]:
        """
        SMTP username for authentication.

        Checks SMTP_USERNAME environment variable first, then falls back to config file.
        """
        return os.environ.get('SMTP_USERNAME') or self._config.get('email', {}).get('smtp_username')

    @property
    def smtp_password(self) -> Optional[str]:
        """
        SMTP password for authentication.

        Checks SMTP_PASSWORD environment variable first, then falls back to config file.
        """
        return os.environ.get('SMTP_PASSWORD') or self._config.get('email', {}).get('smtp_password')

    @property
    def from_address(self) -> Optional[str]:
        """Email 'From' address."""
        return self._config.get('email', {}).get('from_address')

    @property
    def to_addresses(self) -> List[str]:
        """List of email 'To' addresses."""
        return self._config.get('email', {}).get('to_addresses', [])

    @property
    def subject_prefix(self) -> str:
        """Email subject line prefix."""
        return self._config.get('email', {}).get('subject_prefix', 'Knock Knock Security Scan')

    # Database settings
    @property
    def database_enabled(self) -> bool:
        """Whether database logging is enabled."""
        return self._config.get('database', {}).get('enabled', False)

    @property
    def database_path(self) -> str:
        """Path to SQLite database file."""
        return self._config.get('database', {}).get('path', '/var/lib/knockknock/knockknock.db')

    # Reporting settings
    @property
    def ports_of_interest(self) -> List[int]:
        """List of ports to highlight in reports."""
        return self._config.get('reporting', {}).get('ports_of_interest', [22, 80, 443, 8443, 3389])

    @property
    def report_title(self) -> str:
        """Report title for HTML reports."""
        return self._config.get('reporting', {}).get('report_title', 'Knock Knock Security Scan Report')

    def validate_email_config(self) -> bool:
        """
        Validate that required email configuration is present.

        Returns:
            True if email config is valid, False otherwise.
        """
        if not self.smtp_host:
            print("Error: smtp_host is required in email configuration")
            return False
        if not self.from_address:
            print("Error: from_address is required in email configuration")
            return False
        if not self.to_addresses:
            print("Error: to_addresses is required in email configuration")
            return False
        return True
