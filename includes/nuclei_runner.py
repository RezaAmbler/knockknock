#!/usr/bin/env python3
"""
Nuclei runner module for knock_knock security scanner.

Executes Nuclei vulnerability scanner and manages its output.
"""

import logging
import subprocess
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def run_nuclei(
    target: str,
    nuclei_binary: str,
    output_path: Path,
    timeout: int = 300,
    severity_filter: Optional[str] = None,
    templates: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """
    Run Nuclei vulnerability scanner against a target.

    Args:
        target: Target URL or IP (e.g., "https://example.com" or "192.0.2.1")
        nuclei_binary: Path to nuclei binary
        output_path: Path to save JSONL output
        timeout: Timeout in seconds for nuclei scan (default: 300)
        severity_filter: Comma-separated severity levels (e.g., "low,medium,high,critical")
        templates: Path to custom templates directory (optional)

    Returns:
        Tuple of (success: bool, error_message: Optional[str])
    """
    try:
        # Build nuclei command
        cmd = [
            nuclei_binary,
            '-target', target,
            '-jsonl',
            '-silent',
            '-o', str(output_path)
        ]

        # Add severity filter if specified
        if severity_filter:
            cmd.extend(['-severity', severity_filter])

        # Add custom templates if specified
        if templates:
            cmd.extend(['-t', templates])

        # Debug: Log command before execution
        logger.debug(f"[{target}] Executing nuclei: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            logger.error(f"[{target}] nuclei failed with return code {result.returncode}")

            # Debug: Show detailed diagnostics
            logger.debug(f"[{target}] nuclei return code: {result.returncode}")
            if result.stdout:
                logger.debug(f"[{target}] nuclei stdout: {result.stdout.strip()[:500]}")
            if result.stderr:
                logger.debug(f"[{target}] nuclei stderr: {result.stderr.strip()[:500]}")

            error_msg = f"nuclei exited with code {result.returncode}"
            if result.stderr:
                error_msg += f": {result.stderr[:200]}"
            return False, error_msg

        # Verify output file was created
        if not output_path.exists():
            error_msg = "nuclei did not create output file"
            logger.error(f"[{target}] {error_msg}")
            return False, error_msg

        # Check if output file has content
        if output_path.stat().st_size == 0:
            logger.info(f"[{target}] nuclei found no vulnerabilities (empty output)")
            return True, None

        logger.info(f"[{target}] nuclei scan completed successfully")
        return True, None

    except subprocess.TimeoutExpired:
        error_msg = f"nuclei timed out after {timeout} seconds"
        logger.error(f"[{target}] {error_msg}")
        logger.debug(f"[{target}] nuclei timeout (command: {' '.join(cmd)})")
        return False, error_msg

    except Exception as e:
        error_msg = f"Unexpected error running nuclei: {str(e)}"
        logger.error(f"[{target}] {error_msg}")
        logger.debug(f"[{target}] nuclei exception details: {type(e).__name__}: {e}")
        return False, error_msg


def check_nuclei_installed(nuclei_binary: str = 'nuclei') -> Tuple[bool, Optional[str]]:
    """
    Check if Nuclei is installed and available.

    Args:
        nuclei_binary: Path to nuclei binary (default: 'nuclei')

    Returns:
        Tuple of (is_installed: bool, version: Optional[str])
    """
    try:
        result = subprocess.run(
            [nuclei_binary, '-version'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            # Parse version from output
            version = result.stdout.strip() if result.stdout else "unknown"
            logger.info(f"Found nuclei: {version}")
            return True, version
        else:
            return False, None

    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False, None
