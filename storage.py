#!/usr/bin/env python3
"""
Storage module for knock_knock security scanner.

Handles SQLite-based append-only logging of scan results and time-range reporting.
"""

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from scanner import HostScanResult, Port, SSHAuditResult

logger = logging.getLogger(__name__)


@dataclass
class RunMetadata:
    """Metadata for a scan run."""
    started_at: str  # ISO-8601 UTC
    finished_at: str  # ISO-8601 UTC
    config_hash: Optional[str] = None
    targets_hash: Optional[str] = None
    cli_args: Optional[str] = None


@dataclass
class PortSummaryRow:
    """Summary row for port history reporting."""
    device_name: str
    ip: str
    port: int
    protocol: str
    first_seen_at: str  # ISO-8601 UTC
    last_seen_at: str   # ISO-8601 UTC
    runs_count: int
    last_product: Optional[str] = None
    last_version: Optional[str] = None
    ssh_issues: Optional[int] = None  # Count of SSH warnings + failures


# SQL schema
SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    config_hash TEXT,
    targets_hash TEXT,
    cli_args TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    device_name TEXT,
    ip TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    scan_duration_seconds REAL
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    nmap_extra TEXT
);

CREATE TABLE IF NOT EXISTS ssh_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id INTEGER NOT NULL REFERENCES ports(id),
    banner TEXT,
    kex_algos TEXT,
    ciphers TEXT,
    macs TEXT,
    issues_count INTEGER,
    raw_json TEXT
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_runs_finished_at ON runs(finished_at);
CREATE INDEX IF NOT EXISTS idx_hosts_run_id ON hosts(run_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_ssh_audit_port_id ON ssh_audit(port_id);
"""


def init_db(path: Path) -> sqlite3.Connection:
    """
    Initialize the SQLite database and ensure schema exists.

    Args:
        path: Path to the SQLite database file

    Returns:
        sqlite3.Connection object
    """
    try:
        # Create parent directory if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        # Connect to database
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row

        # Execute schema
        conn.executescript(SCHEMA)
        conn.commit()

        logger.info(f"Initialized database at {path}")
        return conn

    except Exception as e:
        logger.error(f"Failed to initialize database at {path}: {e}")
        raise


def compute_hash(content: str) -> str:
    """
    Compute SHA-256 hash of content.

    Args:
        content: String content to hash

    Returns:
        Hex digest of SHA-256 hash
    """
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def record_run(
    db_path: Path,
    run_meta: RunMetadata,
    results: List[HostScanResult],
    device_mapping: Optional[dict] = None
) -> None:
    """
    Record a complete scan run to the database.

    This is append-only and never raises exceptions that would break the scan.

    Args:
        db_path: Path to SQLite database
        run_meta: Metadata about the run
        results: List of HostScanResult from the scan
        device_mapping: Optional dict mapping IPs to device names
    """
    try:
        conn = init_db(db_path)

        with conn:
            # Insert run
            cursor = conn.execute(
                """
                INSERT INTO runs (started_at, finished_at, config_hash, targets_hash, cli_args)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run_meta.started_at,
                    run_meta.finished_at,
                    run_meta.config_hash,
                    run_meta.targets_hash,
                    run_meta.cli_args
                )
            )
            run_id = cursor.lastrowid

            # Insert hosts and ports
            for host_result in results:
                # Get device name from mapping if available
                device_name = None
                if device_mapping:
                    for dev_name, ips in device_mapping.items():
                        if host_result.ip in ips:
                            device_name = dev_name
                            break

                # Calculate scan duration if we have timing info
                # (This would need to be added to HostScanResult in future)
                scan_duration = None

                # Insert host
                host_cursor = conn.execute(
                    """
                    INSERT INTO hosts (run_id, device_name, ip, status, error_message, scan_duration_seconds)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        device_name,
                        host_result.ip,
                        host_result.status,
                        host_result.error_message,
                        scan_duration
                    )
                )
                host_id = host_cursor.lastrowid

                # Insert ports
                for port in host_result.open_ports:
                    # Prepare nmap_extra as JSON if there are notes
                    nmap_extra = json.dumps({'notes': port.notes}) if port.notes else None

                    port_cursor = conn.execute(
                        """
                        INSERT INTO ports (host_id, port, protocol, state, service_name, product, version, nmap_extra)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            host_id,
                            port.port,
                            port.protocol,
                            port.state,
                            port.service,
                            None,  # product - would need to parse from version string
                            port.version,
                            nmap_extra
                        )
                    )
                    port_id = port_cursor.lastrowid

                    # Check if this port has SSH audit results
                    for ssh_result in host_result.ssh_results:
                        if ssh_result.port == port.port:
                            # Serialize lists as JSON
                            kex_algos_json = json.dumps(ssh_result.key_exchange) if ssh_result.key_exchange else None
                            ciphers_json = json.dumps(ssh_result.ciphers) if ssh_result.ciphers else None
                            macs_json = json.dumps(ssh_result.macs) if ssh_result.macs else None

                            # Count issues
                            issues_count = len(ssh_result.critical_issues) + len(ssh_result.warnings)

                            # Build raw JSON
                            raw_json = json.dumps({
                                'ssh_version': ssh_result.ssh_version,
                                'banner': ssh_result.banner,
                                'key_exchange': ssh_result.key_exchange,
                                'ciphers': ssh_result.ciphers,
                                'macs': ssh_result.macs,
                                'critical_issues': ssh_result.critical_issues,
                                'warnings': ssh_result.warnings,
                                'connection_failed': ssh_result.connection_failed,
                                'error': ssh_result.error
                            })

                            conn.execute(
                                """
                                INSERT INTO ssh_audit (port_id, banner, kex_algos, ciphers, macs, issues_count, raw_json)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    port_id,
                                    ssh_result.banner,
                                    kex_algos_json,
                                    ciphers_json,
                                    macs_json,
                                    issues_count,
                                    raw_json
                                )
                            )

        conn.close()
        logger.info(f"Recorded run {run_id} with {len(results)} hosts to database")

    except Exception as e:
        logger.warning(f"Failed to record run to database: {e}")
        # Never raise - DB errors should not break the scan


def query_ports_summary(
    db_path: Path,
    from_dt: str,
    to_dt: str,
    host_filter: Optional[str] = None,
    port_filter: Optional[int] = None
) -> List[PortSummaryRow]:
    """
    Query port summary for a time range.

    Args:
        db_path: Path to SQLite database
        from_dt: Start datetime in ISO-8601 format (UTC)
        to_dt: End datetime in ISO-8601 format (UTC)
        host_filter: Optional hostname/IP filter
        port_filter: Optional port number filter

    Returns:
        List of PortSummaryRow objects
    """
    try:
        conn = init_db(db_path)

        # Build query
        query = """
        SELECT
            h.device_name,
            h.ip,
            p.port,
            p.protocol,
            MIN(r.finished_at) as first_seen_at,
            MAX(r.finished_at) as last_seen_at,
            COUNT(DISTINCT r.id) as runs_count,
            -- Get product/version from most recent run
            (SELECT p2.product FROM ports p2
             JOIN hosts h2 ON p2.host_id = h2.id
             JOIN runs r2 ON h2.run_id = r2.id
             WHERE p2.port = p.port
               AND p2.protocol = p.protocol
               AND h2.ip = h.ip
               AND r2.finished_at >= ?
               AND r2.finished_at <= ?
             ORDER BY r2.finished_at DESC
             LIMIT 1) as last_product,
            (SELECT p2.version FROM ports p2
             JOIN hosts h2 ON p2.host_id = h2.id
             JOIN runs r2 ON h2.run_id = r2.id
             WHERE p2.port = p.port
               AND p2.protocol = p.protocol
               AND h2.ip = h.ip
               AND r2.finished_at >= ?
               AND r2.finished_at <= ?
             ORDER BY r2.finished_at DESC
             LIMIT 1) as last_version,
            -- Get SSH issues count from most recent run
            (SELECT s.issues_count FROM ssh_audit s
             JOIN ports p2 ON s.port_id = p2.id
             JOIN hosts h2 ON p2.host_id = h2.id
             JOIN runs r2 ON h2.run_id = r2.id
             WHERE p2.port = p.port
               AND p2.protocol = p.protocol
               AND h2.ip = h.ip
               AND r2.finished_at >= ?
               AND r2.finished_at <= ?
             ORDER BY r2.finished_at DESC
             LIMIT 1) as ssh_issues
        FROM ports p
        JOIN hosts h ON p.host_id = h.id
        JOIN runs r ON h.run_id = r.id
        WHERE r.finished_at >= ?
          AND r.finished_at <= ?
        """

        params = [from_dt, to_dt, from_dt, to_dt, from_dt, to_dt, from_dt, to_dt]

        if host_filter:
            query += " AND (h.device_name LIKE ? OR h.ip LIKE ?)"
            params.extend([f"%{host_filter}%", f"%{host_filter}%"])

        if port_filter is not None:
            query += " AND p.port = ?"
            params.append(port_filter)

        query += """
        GROUP BY h.ip, p.port, p.protocol
        ORDER BY h.device_name, h.ip, p.port
        """

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()

        results = []
        for row in rows:
            results.append(PortSummaryRow(
                device_name=row['device_name'] or 'unknown',
                ip=row['ip'],
                port=row['port'],
                protocol=row['protocol'],
                first_seen_at=row['first_seen_at'],
                last_seen_at=row['last_seen_at'],
                runs_count=row['runs_count'],
                last_product=row['last_product'],
                last_version=row['last_version'],
                ssh_issues=row['ssh_issues']
            ))

        conn.close()
        return results

    except Exception as e:
        logger.error(f"Failed to query ports summary: {e}")
        raise


def get_db_stats(db_path: Path) -> dict:
    """
    Get basic statistics about the database.

    Args:
        db_path: Path to SQLite database

    Returns:
        Dictionary with statistics
    """
    try:
        conn = init_db(db_path)

        stats = {}

        # Count runs
        cursor = conn.execute("SELECT COUNT(*) as count FROM runs")
        stats['total_runs'] = cursor.fetchone()['count']

        # Count hosts
        cursor = conn.execute("SELECT COUNT(*) as count FROM hosts")
        stats['total_hosts'] = cursor.fetchone()['count']

        # Count ports
        cursor = conn.execute("SELECT COUNT(*) as count FROM ports")
        stats['total_ports'] = cursor.fetchone()['count']

        # Get date range
        cursor = conn.execute(
            "SELECT MIN(started_at) as first, MAX(finished_at) as last FROM runs"
        )
        row = cursor.fetchone()
        stats['first_run'] = row['first']
        stats['last_run'] = row['last']

        conn.close()
        return stats

    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        return {}
