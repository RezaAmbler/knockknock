#!/usr/bin/env python3
"""
Nuclei parser module for knock_knock security scanner.

Parses Nuclei JSONL output into structured data.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NucleiFinding:
    """Represents a single Nuclei vulnerability finding."""
    template_id: str
    name: str
    severity: str
    type: str
    host: str
    matched_at: Optional[str] = None
    port: Optional[str] = None
    extracted_results: Optional[List[str]] = field(default_factory=list)
    timestamp: Optional[str] = None
    raw_json: Optional[str] = None

    def __post_init__(self):
        """Normalize fields after initialization."""
        # Normalize severity to lowercase
        if self.severity:
            self.severity = self.severity.lower()


def parse_nuclei_jsonl(jsonl_path: Path) -> List[NucleiFinding]:
    """
    Parse Nuclei JSONL output file.

    Nuclei produces newline-delimited JSON (JSONL), with one JSON object per finding.

    Args:
        jsonl_path: Path to the Nuclei JSONL output file

    Returns:
        List of NucleiFinding objects
    """
    findings = []

    try:
        if not jsonl_path.exists():
            logger.warning(f"Nuclei output file not found: {jsonl_path}")
            return findings

        if jsonl_path.stat().st_size == 0:
            logger.info(f"Nuclei output file is empty (no findings): {jsonl_path}")
            return findings

        with open(jsonl_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    # Parse JSON object
                    data = json.loads(line)

                    # Extract fields from Nuclei JSON format
                    # Example Nuclei JSON structure:
                    # {
                    #   "template-id": "CVE-2021-12345",
                    #   "info": {"name": "...", "severity": "high", "type": "http"},
                    #   "matched-at": "https://example.com/path",
                    #   "host": "example.com",
                    #   "port": "443",
                    #   "extracted-results": ["result1", "result2"],
                    #   "timestamp": "2025-01-20T12:34:56Z"
                    # }

                    template_id = data.get('template-id', data.get('templateID', 'unknown'))

                    # Extract info section
                    info = data.get('info', {})
                    name = info.get('name', template_id)
                    severity = info.get('severity', 'unknown')
                    vuln_type = info.get('type', data.get('type', 'unknown'))

                    # Extract target information
                    host = data.get('host', '')
                    matched_at = data.get('matched-at', data.get('matched_at', data.get('matched', '')))
                    port = data.get('port', '')

                    # Extract results
                    extracted = data.get('extracted-results', data.get('extracted_results', []))
                    if not isinstance(extracted, list):
                        extracted = [str(extracted)] if extracted else []

                    # Extract timestamp
                    timestamp = data.get('timestamp', '')

                    # Store raw JSON for reference
                    raw_json = json.dumps(data)

                    finding = NucleiFinding(
                        template_id=template_id,
                        name=name,
                        severity=severity,
                        type=vuln_type,
                        host=host,
                        matched_at=matched_at,
                        port=str(port) if port else None,
                        extracted_results=extracted,
                        timestamp=timestamp,
                        raw_json=raw_json
                    )

                    findings.append(finding)

                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON on line {line_num} of {jsonl_path}: {e}")
                    logger.debug(f"Problematic line: {line[:200]}")
                    continue

                except Exception as e:
                    logger.warning(f"Error processing line {line_num} of {jsonl_path}: {e}")
                    logger.debug(f"Line content: {line[:200]}")
                    continue

        logger.info(f"Parsed {len(findings)} findings from {jsonl_path}")
        return findings

    except Exception as e:
        logger.error(f"Failed to parse Nuclei output from {jsonl_path}: {e}")
        return findings


def group_findings_by_severity(findings: List[NucleiFinding]) -> dict:
    """
    Group findings by severity level.

    Args:
        findings: List of NucleiFinding objects

    Returns:
        Dictionary with severity levels as keys and counts as values
    """
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
        'unknown': 0
    }

    for finding in findings:
        severity = finding.severity.lower() if finding.severity else 'unknown'
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['unknown'] += 1

    return severity_counts
