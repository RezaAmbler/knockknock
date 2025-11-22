#!/usr/bin/env python3
"""
Tests for storage.py module.

Run with: python3 test_storage.py
"""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from includes.scanner import HostScanResult, Port, SSHAuditResult
from includes.storage import (
    RunMetadata,
    compute_hash,
    init_db,
    record_run,
    query_ports_summary,
    get_db_stats
)


class TestStorage(unittest.TestCase):
    """Test cases for storage module."""

    def setUp(self):
        """Create a temporary database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

    def tearDown(self):
        """Clean up temporary database."""
        self.temp_dir.cleanup()

    def test_init_db(self):
        """Test database initialization."""
        conn = init_db(self.db_path)
        self.assertTrue(self.db_path.exists())

        # Verify tables exist
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]

        self.assertIn('runs', tables)
        self.assertIn('hosts', tables)
        self.assertIn('ports', tables)
        self.assertIn('ssh_audit', tables)

        conn.close()

    def test_compute_hash(self):
        """Test hash computation."""
        hash1 = compute_hash("test content")
        hash2 = compute_hash("test content")
        hash3 = compute_hash("different content")

        # Same content should produce same hash
        self.assertEqual(hash1, hash2)

        # Different content should produce different hash
        self.assertNotEqual(hash1, hash3)

        # Hash should be 64 characters (SHA-256 hex digest)
        self.assertEqual(len(hash1), 64)

    def test_record_and_query_single_run(self):
        """Test recording a single run and querying it."""
        # Create test data
        now = datetime.utcnow()
        run_meta = RunMetadata(
            started_at=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            finished_at=(now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            config_hash=compute_hash("test config"),
            targets_hash=compute_hash("test targets"),
            cli_args="--targets test.csv"
        )

        # Create host results with ports
        host_results = [
            HostScanResult(
                ip="192.168.1.100",
                status="success",
                open_ports=[
                    Port(port=22, protocol="tcp", state="open", service="ssh", version="OpenSSH 8.9"),
                    Port(port=80, protocol="tcp", state="open", service="http", version="nginx 1.24"),
                ],
                ssh_results=[
                    SSHAuditResult(
                        port=22,
                        ssh_version="SSH-2.0-OpenSSH_8.9",
                        banner="SSH-2.0-OpenSSH_8.9",
                        key_exchange=["curve25519-sha256"],
                        ciphers=["aes256-gcm@openssh.com"],
                        macs=["hmac-sha2-512"],
                        critical_issues=[],
                        warnings=["weak cipher"]
                    )
                ]
            )
        ]

        device_mapping = {"test-server": ["192.168.1.100"]}

        # Record run
        record_run(self.db_path, run_meta, host_results, device_mapping)

        # Verify database stats
        stats = get_db_stats(self.db_path)
        self.assertEqual(stats['total_runs'], 1)
        self.assertEqual(stats['total_hosts'], 1)
        self.assertEqual(stats['total_ports'], 2)

        # Query ports
        from_dt = (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        to_dt = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

        rows = query_ports_summary(self.db_path, from_dt, to_dt)

        self.assertEqual(len(rows), 2)  # Should have 2 ports

        # Check first port (22)
        port_22 = next(r for r in rows if r.port == 22)
        self.assertEqual(port_22.device_name, "test-server")
        self.assertEqual(port_22.ip, "192.168.1.100")
        self.assertEqual(port_22.protocol, "tcp")
        self.assertEqual(port_22.runs_count, 1)

    def test_query_with_time_range_filter(self):
        """Test querying with time range that excludes some runs."""
        now = datetime.utcnow()

        # Create two runs at different times
        for i, time_offset in enumerate([timedelta(days=-2), timedelta(days=0)]):
            run_time = now + time_offset
            run_meta = RunMetadata(
                started_at=run_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                finished_at=(run_time + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            )

            host_results = [
                HostScanResult(
                    ip="192.168.1.100",
                    status="success",
                    open_ports=[
                        Port(port=22, protocol="tcp", state="open", service="ssh"),
                    ]
                )
            ]

            record_run(self.db_path, run_meta, host_results)

        # Query only today's run
        from_dt = (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        to_dt = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

        rows = query_ports_summary(self.db_path, from_dt, to_dt)

        # Should only find one run
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].runs_count, 1)

    def test_query_with_host_filter(self):
        """Test querying with host filter."""
        now = datetime.utcnow()
        run_meta = RunMetadata(
            started_at=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            finished_at=(now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        )

        # Create multiple hosts
        host_results = [
            HostScanResult(
                ip="192.168.1.100",
                status="success",
                open_ports=[Port(port=22, protocol="tcp", state="open")]
            ),
            HostScanResult(
                ip="192.168.1.101",
                status="success",
                open_ports=[Port(port=80, protocol="tcp", state="open")]
            )
        ]

        device_mapping = {
            "server1": ["192.168.1.100"],
            "server2": ["192.168.1.101"]
        }

        record_run(self.db_path, run_meta, host_results, device_mapping)

        # Query with host filter
        from_dt = (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        to_dt = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

        rows = query_ports_summary(self.db_path, from_dt, to_dt, host_filter="server1")

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].device_name, "server1")
        self.assertEqual(rows[0].port, 22)

    def test_query_with_port_filter(self):
        """Test querying with port filter."""
        now = datetime.utcnow()
        run_meta = RunMetadata(
            started_at=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            finished_at=(now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        )

        host_results = [
            HostScanResult(
                ip="192.168.1.100",
                status="success",
                open_ports=[
                    Port(port=22, protocol="tcp", state="open"),
                    Port(port=80, protocol="tcp", state="open"),
                    Port(port=443, protocol="tcp", state="open"),
                ]
            )
        ]

        record_run(self.db_path, run_meta, host_results)

        # Query with port filter
        from_dt = (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        to_dt = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

        rows = query_ports_summary(self.db_path, from_dt, to_dt, port_filter=80)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].port, 80)

    def test_multiple_runs_aggregation(self):
        """Test that multiple runs are aggregated correctly."""
        now = datetime.utcnow()

        # Create 3 runs with the same port
        for i in range(3):
            run_time = now + timedelta(minutes=i*10)
            run_meta = RunMetadata(
                started_at=run_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                finished_at=(run_time + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            )

            host_results = [
                HostScanResult(
                    ip="192.168.1.100",
                    status="success",
                    open_ports=[
                        Port(port=22, protocol="tcp", state="open", service="ssh"),
                    ]
                )
            ]

            record_run(self.db_path, run_meta, host_results)

        # Query all runs
        from_dt = (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        to_dt = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

        rows = query_ports_summary(self.db_path, from_dt, to_dt)

        # Should aggregate to one row with runs_count=3
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].runs_count, 3)
        self.assertEqual(rows[0].port, 22)


if __name__ == '__main__':
    unittest.main()
