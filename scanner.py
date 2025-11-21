#!/usr/bin/env python3
"""
Scanner module for knock_knock security scanner.

Handles nmap and ssh-audit scanning operations with parallel execution.
"""

import json
import logging
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Port:
    """Represents a scanned network port."""
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    notes: str = ""


@dataclass
class SSHAuditResult:
    """Represents ssh-audit scan results for a single port."""
    port: int
    ssh_version: str = ""
    banner: str = ""
    key_exchange: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    critical_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    connection_failed: bool = False
    error: Optional[str] = None


@dataclass
class HostScanResult:
    """Represents complete scan results for a single host IP."""
    ip: str
    status: str  # 'success', 'error', 'timeout'
    open_ports: List[Port] = field(default_factory=list)
    ssh_results: List[SSHAuditResult] = field(default_factory=list)
    error_message: Optional[str] = None
    nmap_xml_path: Optional[Path] = None


def check_tools() -> Tuple[bool, List[str]]:
    """
    Check if required tools (masscan, nmap, and ssh-audit) are available in PATH.

    Returns:
        Tuple of (success: bool, missing_tools: List[str])
    """
    missing = []

    for tool in ['masscan', 'nmap', 'ssh-audit']:
        try:
            result = subprocess.run(
                ['which', tool],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                missing.append(tool)
            else:
                logger.info(f"Found {tool} at: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            missing.append(tool)

    return (len(missing) == 0, missing)


def run_masscan(
    ip: str,
    masscan_binary: str,
    rate: int,
    output_path: Path,
    timeout: int = 120
) -> Tuple[bool, List[int], Optional[str]]:
    """
    Run masscan to quickly discover open ports across all 65535 ports.

    Args:
        ip: Target IP address
        masscan_binary: Path to masscan binary
        rate: Packet rate limit (packets per second)
        output_path: Path to save JSON output
        timeout: Timeout in seconds for masscan scan (default: 120)

    Returns:
        Tuple of (success: bool, open_ports: List[int], error_message: Optional[str])
    """
    try:
        # Construct masscan command with JSON output
        # Note: masscan requires sudo/root privileges for raw socket access
        cmd = [
            'sudo', masscan_binary,
            ip,
            '-p0-65535',
            f'--rate={rate}',
            '--output-format', 'json',
            '--output-filename', str(output_path)
        ]

        logger.debug(f"Running masscan: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # masscan may return non-zero even on success, check if output file exists
        if not output_path.exists():
            error_msg = "masscan did not create JSON output file"
            logger.error(f"masscan scan failed for {ip}: {error_msg}")
            return False, [], error_msg

        # Parse JSON output to extract open ports
        open_ports = []
        try:
            with open(output_path, 'r') as f:
                # masscan JSON format is array of objects
                # Each object has "ip" and "ports" array
                content = f.read().strip()

                # Handle empty file
                if not content or content == '[]':
                    logger.info(f"masscan found no open ports on {ip}")
                    return True, [], None

                # Parse JSON
                data = json.loads(content)

                # Extract port numbers
                for entry in data:
                    if 'ports' in entry:
                        for port_info in entry['ports']:
                            if port_info.get('status') == 'open':
                                port = port_info.get('port')
                                if port:
                                    open_ports.append(port)

                # Remove duplicates and sort
                open_ports = sorted(list(set(open_ports)))
                logger.info(f"masscan discovered {len(open_ports)} open ports on {ip}")

        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse masscan JSON output: {e}"
            logger.error(f"masscan parse error for {ip}: {error_msg}")
            return False, [], error_msg
        except Exception as e:
            error_msg = f"Error reading masscan output: {e}"
            logger.error(f"masscan output error for {ip}: {error_msg}")
            return False, [], error_msg

        return True, open_ports, None

    except subprocess.TimeoutExpired:
        timeout_minutes = timeout / 60
        error_msg = f"masscan timed out after {timeout_minutes:.1f} minutes"
        logger.error(f"masscan scan failed for {ip}: {error_msg}")
        return False, [], error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(f"masscan scan failed for {ip}: {error_msg}")
        return False, [], error_msg


def run_nmap_scan(
    ip: str,
    nmap_binary: str,
    nmap_args: List[str],
    output_path: Path,
    ports: Optional[List[int]] = None,
    timeout: int = 300
) -> Tuple[bool, Optional[str]]:
    """
    Run nmap scan against a single IP and save XML output.

    Args:
        ip: Target IP address
        nmap_binary: Path to nmap binary
        nmap_args: List of nmap arguments (port args will be filtered out)
        output_path: Path to save XML output
        ports: Optional list of specific ports to scan (overrides any -p args)
        timeout: Timeout in seconds for nmap scan (default: 300)

    Returns:
        Tuple of (success: bool, error_message: Optional[str])
    """
    try:
        # Filter out any existing port arguments from nmap_args
        # We'll add our own based on the ports parameter
        filtered_args = []
        skip_next = False
        for arg in nmap_args:
            if skip_next:
                skip_next = False
                continue
            if arg.startswith('-p'):
                # Skip -p arguments (handles both -p22 and -p 22 styles)
                if arg == '-p':
                    skip_next = True  # Skip next argument too
                continue
            filtered_args.append(arg)

        # Build port specification
        if ports:
            # Scan specific ports discovered by masscan
            port_spec = ','.join(str(p) for p in ports)
            port_args = ['-p', port_spec]
        else:
            # No ports specified - this shouldn't happen in normal flow
            # but handle it gracefully
            logger.warning(f"No ports specified for nmap scan of {ip}, skipping")
            return True, None

        # Construct nmap command with automatic XML output
        cmd = [nmap_binary] + filtered_args + port_args + ['-oX', str(output_path), ip]

        logger.debug(f"Running nmap: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            error_msg = f"nmap exited with code {result.returncode}"
            if result.stderr:
                error_msg += f": {result.stderr[:200]}"
            logger.error(f"nmap scan failed for {ip}: {error_msg}")
            return False, error_msg

        # Verify XML file was created
        if not output_path.exists():
            error_msg = "nmap did not create XML output file"
            logger.error(f"nmap scan failed for {ip}: {error_msg}")
            return False, error_msg

        return True, None

    except subprocess.TimeoutExpired:
        timeout_minutes = timeout / 60
        error_msg = f"nmap scan timed out after {timeout_minutes:.1f} minutes"
        logger.error(f"nmap scan failed for {ip}: {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(f"nmap scan failed for {ip}: {error_msg}")
        return False, error_msg


def parse_nmap_xml(xml_path: Path) -> List[Port]:
    """
    Parse nmap XML output to extract port information.

    Args:
        xml_path: Path to nmap XML output file

    Returns:
        List of Port objects
    """
    ports = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Find all port elements
        for port_elem in root.findall('.//port'):
            port_id = int(port_elem.get('portid', 0))
            protocol = port_elem.get('protocol', 'tcp')

            # Get state
            state_elem = port_elem.find('state')
            state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

            # Only include open ports
            if state != 'open':
                continue

            # Get service info
            service_elem = port_elem.find('service')
            service = ""
            version = ""

            if service_elem is not None:
                service = service_elem.get('name', '')
                product = service_elem.get('product', '')
                service_version = service_elem.get('version', '')

                # Build version string
                version_parts = [p for p in [product, service_version] if p]
                version = ' '.join(version_parts)

            # Get script output notes
            notes_parts = []
            for script_elem in port_elem.findall('script'):
                script_id = script_elem.get('id', '')
                script_output = script_elem.get('output', '')
                if script_output:
                    # Truncate long script output
                    if len(script_output) > 100:
                        script_output = script_output[:100] + '...'
                    notes_parts.append(f"{script_id}: {script_output}")

            notes = '; '.join(notes_parts) if notes_parts else ''

            ports.append(Port(
                port=port_id,
                protocol=protocol,
                state=state,
                service=service,
                version=version,
                notes=notes
            ))

        logger.debug(f"Parsed {len(ports)} open ports from {xml_path}")

    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML {xml_path}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error parsing nmap XML {xml_path}: {e}")

    return ports


def run_ssh_audit(
    ip: str,
    port: int,
    ssh_audit_binary: str
) -> SSHAuditResult:
    """
    Run ssh-audit against a specific IP:port combination.

    Args:
        ip: Target IP address
        port: SSH port to scan
        ssh_audit_binary: Path to ssh-audit binary

    Returns:
        SSHAuditResult object
    """
    result = SSHAuditResult(port=port)

    try:
        cmd = [ssh_audit_binary, '-j', f'{ip}:{port}']

        logger.debug(f"Running ssh-audit: {' '.join(cmd)}")

        proc_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60  # 1-minute timeout for ssh-audit
        )

        # Check for connection failures in output
        if proc_result.stdout and '[exception] cannot connect' in proc_result.stdout:
            result.connection_failed = True
            result.error = "Connection timed out or refused"
            logger.debug(f"ssh-audit connection failed for {ip}:{port}")
            return result

        # Parse JSON output
        if proc_result.stdout and proc_result.stdout.strip():
            try:
                data = json.loads(proc_result.stdout)

                # Extract banner/version
                if 'banner' in data:
                    result.banner = data['banner'].get('raw', '')
                    result.ssh_version = data['banner'].get('protocol', '')

                # Extract algorithm information
                if 'kex' in data:
                    kex_data = data['kex'][0] if isinstance(data['kex'], list) else data['kex']

                    result.key_exchange = kex_data.get('kex_algorithms', [])

                    # Get encryption algorithms (ciphers)
                    enc = kex_data.get('encryption_algorithms', [])
                    result.ciphers = enc if isinstance(enc, list) else []

                    # Get MAC algorithms
                    mac = kex_data.get('mac_algorithms', [])
                    result.macs = mac if isinstance(mac, list) else []

                # Extract recommendations (issues and warnings)
                if 'recommendations' in data:
                    recommendations = data['recommendations']

                    # Critical issues
                    if 'critical' in recommendations:
                        critical = recommendations['critical']
                        result.critical_issues = _parse_recommendations(critical)

                    # Warnings
                    if 'warning' in recommendations:
                        warning = recommendations['warning']
                        result.warnings = _parse_recommendations(warning)

            except json.JSONDecodeError as e:
                result.error = f"Failed to parse ssh-audit JSON output: {e}"
                logger.error(f"ssh-audit JSON parse error for {ip}:{port}: {e}")
        else:
            result.error = "ssh-audit produced no output"
            logger.warning(f"ssh-audit produced no output for {ip}:{port}")

    except subprocess.TimeoutExpired:
        result.error = "ssh-audit timed out after 60 seconds"
        logger.error(f"ssh-audit timeout for {ip}:{port}")
    except Exception as e:
        result.error = f"Unexpected error: {str(e)}"
        logger.error(f"ssh-audit unexpected error for {ip}:{port}: {e}")

    return result


def _parse_recommendations(rec_data: Dict[str, Any]) -> List[str]:
    """
    Parse ssh-audit recommendation data into human-readable strings.

    Args:
        rec_data: Recommendation data dictionary

    Returns:
        List of recommendation strings
    """
    recommendations = []

    for action in ['del', 'add', 'chg']:
        if action not in rec_data:
            continue

        action_verb = {
            'del': 'Remove',
            'add': 'Add',
            'chg': 'Change'
        }.get(action, action)

        for category, items in rec_data[action].items():
            for item in items:
                msg = f"{action_verb} {category}: {item.get('name', 'unknown')}"
                if item.get('notes'):
                    msg += f" - {item['notes']}"
                recommendations.append(msg)

    return recommendations


def scan_host(
    ip: str,
    masscan_binary: str,
    masscan_rate: int,
    nmap_binary: str,
    nmap_args: List[str],
    ssh_audit_binary: str,
    ssh_ports: List[int],
    output_dir: Path,
    timeout_seconds: int = 600
) -> HostScanResult:
    """
    Scan a single host with masscan, nmap, and ssh-audit.

    Two-stage scanning approach:
    1. Use masscan to quickly discover open ports across all 65535 ports
    2. Use nmap to do detailed scanning of only the discovered open ports
    3. Run ssh-audit on SSH ports found to be open

    This function is designed to be called by a ProcessPoolExecutor worker.

    Args:
        ip: Target IP address
        masscan_binary: Path to masscan binary
        masscan_rate: Masscan packet rate limit (packets/second)
        nmap_binary: Path to nmap binary
        nmap_args: List of nmap arguments
        ssh_audit_binary: Path to ssh-audit binary
        ssh_ports: List of SSH ports to scan
        output_dir: Directory to save scan outputs
        timeout_seconds: Total timeout for this host's scan (default: 600)

    Returns:
        HostScanResult object
    """
    # Set up logging for the worker process
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info(f"Starting two-stage scan of {ip} (masscan → nmap → ssh-audit)")

    result = HostScanResult(ip=ip, status='success')

    # Allocate timeout intelligently across three stages:
    # - masscan: 20% (fast port discovery)
    # - nmap: 70% (detailed scanning of discovered ports)
    # - ssh-audit: 10% (SSH analysis)
    masscan_timeout = int(timeout_seconds * 0.20)
    nmap_timeout = int(timeout_seconds * 0.70)

    # Stage 1: Run masscan for fast port discovery
    logger.info(f"[{ip}] Stage 1: Running masscan for port discovery")
    masscan_json_path = output_dir / f'masscan-{ip}.json'
    masscan_success, open_ports, masscan_error = run_masscan(
        ip, masscan_binary, masscan_rate, masscan_json_path, timeout=masscan_timeout
    )

    if not masscan_success:
        result.status = 'error'
        result.error_message = f"masscan scan failed: {masscan_error}"
        logger.error(f"Scan of {ip} failed: {result.error_message}")
        return result

    # If no open ports found, we're done (no need to run nmap)
    if not open_ports:
        logger.info(f"[{ip}] No open ports discovered, scan complete")
        return result

    logger.info(f"[{ip}] Discovered {len(open_ports)} open ports: {open_ports[:10]}{'...' if len(open_ports) > 10 else ''}")

    # Stage 2: Run nmap on discovered ports only
    logger.info(f"[{ip}] Stage 2: Running nmap on {len(open_ports)} discovered ports")
    nmap_xml_path = output_dir / f'nmap-{ip}.xml'
    nmap_success, nmap_error = run_nmap_scan(
        ip, nmap_binary, nmap_args, nmap_xml_path, ports=open_ports, timeout=nmap_timeout
    )

    if not nmap_success:
        result.status = 'error'
        result.error_message = f"nmap scan failed: {nmap_error}"
        logger.error(f"Scan of {ip} failed: {result.error_message}")
        return result

    result.nmap_xml_path = nmap_xml_path

    # Parse nmap results
    result.open_ports = parse_nmap_xml(nmap_xml_path)
    logger.info(f"[{ip}] nmap detailed scan complete: {len(result.open_ports)} ports analyzed")

    # Stage 3: Run ssh-audit on configured SSH ports (only if they're open)
    logger.info(f"[{ip}] Stage 3: Checking for SSH services")
    for ssh_port in ssh_ports:
        # Check if this port is actually open (from nmap results)
        port_is_open = any(p.port == ssh_port for p in result.open_ports)

        if port_is_open:
            logger.info(f"Running ssh-audit on {ip}:{ssh_port}")
            ssh_result = run_ssh_audit(ip, ssh_port, ssh_audit_binary)
            result.ssh_results.append(ssh_result)

    logger.info(f"Completed scan of {ip}")
    return result


def scan_hosts_parallel(
    ips: List[str],
    masscan_binary: str,
    masscan_rate: int,
    nmap_binary: str,
    nmap_args: List[str],
    ssh_audit_binary: str,
    ssh_ports: List[int],
    output_dir: Path,
    max_workers: int,
    timeout_seconds: int
) -> List[HostScanResult]:
    """
    Scan multiple hosts in parallel using batched phase approach.

    Optimized three-phase workflow:
    1. PHASE 1: Run masscan on ALL hosts in parallel (fast port discovery)
    2. PHASE 2: Run nmap on hosts with discovered ports in parallel (detailed analysis)
    3. PHASE 3: Run ssh-audit on hosts with SSH ports in parallel (security audit)

    This batched approach is much faster than per-host sequential because:
    - Fast masscan scans don't get blocked by slow nmap scans
    - Maximum parallelism is achieved in each phase
    - Resources are utilized more efficiently

    Args:
        ips: List of IP addresses to scan
        masscan_binary: Path to masscan binary
        masscan_rate: Masscan packet rate limit (packets/second)
        nmap_binary: Path to nmap binary
        nmap_args: List of nmap arguments
        ssh_audit_binary: Path to ssh-audit binary
        ssh_ports: List of SSH ports to scan
        output_dir: Directory to save scan outputs
        max_workers: Maximum number of concurrent workers
        timeout_seconds: Per-host timeout in seconds

    Returns:
        List of HostScanResult objects
    """
    logger.info(f"Starting batched three-phase scan of {len(ips)} hosts with {max_workers} workers")
    logger.info(f"Masscan rate: {masscan_rate} pps/host → Max total PPS: {max_workers * masscan_rate}")

    # Calculate phase-specific timeouts
    masscan_timeout = int(timeout_seconds * 0.20)
    nmap_timeout = int(timeout_seconds * 0.70)

    # Initialize results dictionary
    results_dict = {ip: HostScanResult(ip=ip, status='success') for ip in ips}

    # =========================================================================
    # PHASE 1: MASSCAN - Fast port discovery on ALL hosts
    # =========================================================================
    logger.info("=" * 80)
    logger.info(f"PHASE 1: Running masscan on {len(ips)} hosts")
    logger.info("=" * 80)

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {}
        for ip in ips:
            masscan_json_path = output_dir / f'masscan-{ip}.json'
            future = executor.submit(
                run_masscan,
                ip,
                masscan_binary,
                masscan_rate,
                masscan_json_path,
                masscan_timeout
            )
            future_to_ip[future] = ip

        # Collect masscan results
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                success, open_ports, error = future.result(timeout=masscan_timeout + 10)

                if not success:
                    results_dict[ip].status = 'error'
                    results_dict[ip].error_message = f"masscan failed: {error}"
                    logger.error(f"[{ip}] masscan failed: {error}")
                else:
                    # Store discovered ports for Phase 2
                    results_dict[ip].open_ports = [
                        Port(port=p, protocol='tcp', state='open')
                        for p in open_ports
                    ]
                    if open_ports:
                        logger.info(f"[{ip}] masscan found {len(open_ports)} open ports")
                    else:
                        logger.info(f"[{ip}] masscan found no open ports - skipping nmap")

            except TimeoutError:
                results_dict[ip].status = 'timeout'
                results_dict[ip].error_message = f"masscan timed out"
                logger.error(f"[{ip}] masscan timed out")
            except Exception as e:
                results_dict[ip].status = 'error'
                results_dict[ip].error_message = f"masscan exception: {str(e)}"
                logger.error(f"[{ip}] masscan exception: {e}")

    # =========================================================================
    # PHASE 2: NMAP - Detailed analysis of discovered ports
    # =========================================================================
    # Only scan hosts that have open ports and didn't error in Phase 1
    hosts_for_nmap = [
        ip for ip, result in results_dict.items()
        if result.status == 'success' and result.open_ports
    ]

    if hosts_for_nmap:
        logger.info("=" * 80)
        logger.info(f"PHASE 2: Running nmap on {len(hosts_for_nmap)} hosts with open ports")
        logger.info("=" * 80)

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {}
            for ip in hosts_for_nmap:
                # Get ports discovered by masscan
                discovered_ports = [p.port for p in results_dict[ip].open_ports]
                nmap_xml_path = output_dir / f'nmap-{ip}.xml'

                future = executor.submit(
                    run_nmap_scan,
                    ip,
                    nmap_binary,
                    nmap_args,
                    nmap_xml_path,
                    discovered_ports,
                    nmap_timeout
                )
                future_to_ip[future] = ip

            # Collect nmap results
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    success, error = future.result(timeout=nmap_timeout + 10)

                    if not success:
                        results_dict[ip].status = 'error'
                        results_dict[ip].error_message = f"nmap failed: {error}"
                        logger.error(f"[{ip}] nmap failed: {error}")
                    else:
                        # Parse nmap XML results
                        nmap_xml_path = output_dir / f'nmap-{ip}.xml'
                        results_dict[ip].nmap_xml_path = nmap_xml_path
                        results_dict[ip].open_ports = parse_nmap_xml(nmap_xml_path)
                        logger.info(f"[{ip}] nmap analyzed {len(results_dict[ip].open_ports)} ports")

                except TimeoutError:
                    results_dict[ip].status = 'timeout'
                    results_dict[ip].error_message = f"nmap timed out"
                    logger.error(f"[{ip}] nmap timed out")
                except Exception as e:
                    results_dict[ip].status = 'error'
                    results_dict[ip].error_message = f"nmap exception: {str(e)}"
                    logger.error(f"[{ip}] nmap exception: {e}")
    else:
        logger.info("=" * 80)
        logger.info("PHASE 2: Skipped - no hosts with open ports")
        logger.info("=" * 80)

    # =========================================================================
    # PHASE 3: SSH-AUDIT - Security analysis of SSH services
    # =========================================================================
    # Build list of (ip, port) tuples for SSH services
    ssh_targets = []
    for ip, result in results_dict.items():
        if result.status == 'success' and result.open_ports:
            for ssh_port in ssh_ports:
                if any(p.port == ssh_port for p in result.open_ports):
                    ssh_targets.append((ip, ssh_port))

    if ssh_targets:
        logger.info("=" * 80)
        logger.info(f"PHASE 3: Running ssh-audit on {len(ssh_targets)} SSH endpoints")
        logger.info("=" * 80)

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {}
            for ip, port in ssh_targets:
                future = executor.submit(run_ssh_audit, ip, port, ssh_audit_binary)
                future_to_target[future] = (ip, port)

            # Collect ssh-audit results
            for future in as_completed(future_to_target):
                ip, port = future_to_target[future]
                try:
                    ssh_result = future.result(timeout=60)
                    results_dict[ip].ssh_results.append(ssh_result)

                    if ssh_result.error:
                        logger.warning(f"[{ip}:{port}] ssh-audit: {ssh_result.error}")
                    else:
                        logger.info(f"[{ip}:{port}] ssh-audit complete")

                except TimeoutError:
                    logger.error(f"[{ip}:{port}] ssh-audit timed out")
                except Exception as e:
                    logger.error(f"[{ip}:{port}] ssh-audit exception: {e}")
    else:
        logger.info("=" * 80)
        logger.info("PHASE 3: Skipped - no SSH services detected")
        logger.info("=" * 80)

    # Convert results dict to list
    results = list(results_dict.values())

    logger.info("=" * 80)
    logger.info(f"Scan complete: {len(results)} hosts processed")
    logger.info("=" * 80)

    return results
