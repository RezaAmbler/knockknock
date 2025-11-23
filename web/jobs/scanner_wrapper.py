"""Wrapper around existing scanner library"""

import uuid
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from web.config import settings


class ScanJobResult:
    """Result of scan job execution"""
    def __init__(self):
        self.run_uuid: str = str(uuid.uuid4())
        self.output_dir: Path = None
        self.html_report_path: Path = None
        self.legacy_run_id: int = None
        self.success: bool = False
        self.error_message: str = None
        self.artifacts: List[Dict[str, Any]] = []


def run_scan_job(
    targets: List[Any],
    overrides: Dict[str, Any],
    schedule_meta: Dict[str, Any],
    email_override: Dict[str, Any]
) -> ScanJobResult:
    """
    Execute scan job using existing scanner library

    Args:
        targets: List of Target objects to scan
        overrides: Scan parameter overrides (masscan_rate, max_concurrent, etc)
        schedule_meta: Schedule metadata (if recurring)
        email_override: Email configuration override

    Returns:
        ScanJobResult with paths and IDs
    """
    result = ScanJobResult()

    try:
        from includes.config import Config

        # Check tool availability
        from includes.scanner import check_tools
        tools_ok, missing = check_tools()
        if not tools_ok:
            result.error_message = f"Missing tools: {', '.join(missing)}"
            return result

        # Create output directory
        result.output_dir = Path(settings.REPORTS_DIR) / result.run_uuid
        result.output_dir.mkdir(parents=True, exist_ok=True)

        # Progress file for real-time updates
        progress_file = result.output_dir / "progress.jsonl"

        def progress_callback(event: Dict[str, Any]):
            """Write progress events to file"""
            with open(progress_file, 'a') as f:
                event['timestamp'] = datetime.utcnow().isoformat()
                f.write(json.dumps(event) + '\n')
                f.flush()

        # Load scanner configuration
        config = Config(settings.SCANNER_CONFIG_PATH)

        # Apply overrides
        if 'masscan_rate' in overrides:
            config.masscan_rate = overrides['masscan_rate']
        if 'max_concurrent' in overrides:
            config.max_concurrent_hosts = overrides['max_concurrent']
        if 'host_timeout' in overrides:
            config.host_timeout_seconds = overrides['host_timeout']

        # Prepare target list (convert to format scanner expects)
        target_tuples = [
            (t.friendly_name, t.ip_address or t.dns_name)
            for t in targets
        ]

        # Execute scan
        from includes.scanner import scan_hosts_parallel
        scan_results = scan_hosts_parallel(
            target_tuples,
            config,
            result.output_dir,
            progress_hook=progress_callback
        )

        # Generate HTML report
        from includes.report import HTMLReportGenerator
        report_gen = HTMLReportGenerator(config)
        result.html_report_path = report_gen.generate(
            scan_results,
            result.output_dir,
            f"knock-knock-{result.run_uuid}.html"
        )
        result.artifacts.append({
            'kind': 'html',
            'path': str(result.html_report_path),
            'size_bytes': result.html_report_path.stat().st_size
        })

        # Record to legacy storage.py database
        from includes.storage import record_run
        result.legacy_run_id = record_run(
            config,
            scan_results,
            str(result.output_dir)
        )

        # Collect artifacts
        for artifact_file in result.output_dir.glob("*"):
            if artifact_file.is_file() and artifact_file != result.html_report_path:
                kind = None
                if artifact_file.suffix == '.json':
                    kind = 'masscan_json' if 'masscan' in artifact_file.name else 'ssh_audit_json'
                elif artifact_file.suffix == '.xml':
                    kind = 'nmap_xml'
                elif artifact_file.suffix == '.jsonl':
                    kind = 'nuclei_jsonl' if 'nuclei' in artifact_file.name else 'log'

                if kind:
                    result.artifacts.append({
                        'kind': kind,
                        'path': str(artifact_file),
                        'size_bytes': artifact_file.stat().st_size
                    })

        # Send email if configured
        if email_override.get('send_email'):
            from includes.emailer import EmailSender
            emailer = EmailSender(config)
            # Override recipients if provided
            if email_override.get('recipients'):
                config.email_to_addresses = email_override['recipients']
            if email_override.get('from_address'):
                config.email_from_address = email_override['from_address']

            emailer.send(
                scan_results,
                str(result.html_report_path)
            )

        result.success = True

    except Exception as e:
        result.success = False
        result.error_message = str(e)
        import traceback
        traceback.print_exc()

    return result
