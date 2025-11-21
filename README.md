# Knock Knock Security Scanner

A production-quality command-line security scanning tool that uses a two-stage scanning approach (`masscan` → `nmap`) combined with `ssh-audit` to efficiently scan network devices, generate comprehensive HTML reports, and send them via email.

## Features

- **Two-Stage Scanning**: Ultra-fast port discovery with masscan, followed by detailed nmap analysis
  - Stage 1: masscan scans all 65,535 ports in ~75 seconds (at 1000 pps)
  - Stage 2: nmap performs deep analysis on only the discovered open ports
  - Stage 3: ssh-audit analyzes SSH security on detected SSH services
- **Parallel Execution**: Scans multiple hosts concurrently for faster results
- **Network Safety**: Configurable packet rate limits with PPS calculations to prevent network congestion
- **Comprehensive Analysis**: Version detection, vulnerability scanning, and security auditing
- **HTML Reports**: Generates clean, readable HTML reports with embedded CSS
- **Email Delivery**: Sends reports via SMTP with both embedded HTML and file attachment
- **Flexible Configuration**: YAML-based configuration for all settings
- **Robust Error Handling**: Gracefully handles timeouts, connection failures, and errors
- **Cron-Ready**: Designed for automated weekly/daily scanning

## Quick Start

The easiest way to get started is to use the automated setup script:

```bash
# Clone the repository
git clone https://github.com/RezaAmbler/knockknock.git
cd knockknock

# Run the setup script (interactive)
./setup.sh

# Or run with options
./setup.sh --venv        # Force virtual environment
./setup.sh --no-venv     # Skip virtual environment
./setup.sh --check-only  # Just check dependencies
```

The setup script will:
- ✓ Check Python version (3.8+ required)
- ✓ Install system tools (masscan, nmap, ssh-audit)
- ✓ Set up Python virtual environment (optional)
- ✓ Install Python dependencies (PyYAML)
- ✓ Configure sudo access for masscan (optional)
- ✓ Verify configuration files

After setup completes:

```bash
# If you used a virtual environment, activate it
source venv/bin/activate

# Copy the example targets file
cp targets.csv.example targets.csv

# Edit targets.csv with your devices
# Edit config.yaml with your settings

# Run your first scan
python3 knock_knock.py --targets targets.csv
```

## Prerequisites

### System Requirements

- **OS**: Linux (tested on Ubuntu/Debian) or macOS
- **Python**: 3.8 or higher
- **Tools**: `masscan`, `nmap`, and `ssh-audit` must be installed and available in PATH
- **Privileges**: masscan requires `sudo`/root access for raw socket operations

### Manual Installation (if not using setup.sh)

#### Installing Required Tools

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y masscan nmap ssh-audit

# macOS with Homebrew
brew install masscan nmap
pip3 install ssh-audit

# Verify installation
which masscan
which nmap
which ssh-audit

# Test masscan works with sudo
sudo masscan --version
```

**Important**: masscan requires sudo privileges because it uses raw sockets. The knock_knock script automatically prepends `sudo` when calling masscan.

#### Python Dependencies

Install required Python packages:

```bash
# System-wide installation
pip3 install -r requirements.txt

# Or using a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Edit `config.yaml` to customize the scanner behavior:

### Two-Stage Scanning Workflow

This tool uses an efficient two-stage scanning approach:

**Stage 1 - Fast Port Discovery (masscan)**:
- Scans ALL 65,535 ports on each host in ~75 seconds (at 1000 pps)
- Identifies which ports are open
- Generates JSON output for parsing

**Stage 2 - Detailed Analysis (nmap)**:
- Scans ONLY the ports discovered by masscan
- Performs version detection, vulnerability scanning, and script execution
- Much faster than traditional `-p-` scanning

### Masscan Settings

```yaml
masscan:
  binary: "masscan"
  rate: 1000  # Packets per second per host
```

**⚠️ CRITICAL: Packet Rate Safety**

Total network PPS = `max_concurrent_hosts` × `masscan_rate`

Examples:
- 10 hosts × 1000 pps = **10,000 total PPS** ✅ Safe
- 20 hosts × 500 pps = **10,000 total PPS** ✅ Safe
- 20 hosts × 2000 pps = **40,000 total PPS** ⚠️ May cause network issues!

**Recommendations**:
- Keep total PPS under 10,000 for production networks
- Start conservative (500-1000 pps per host)
- Monitor network impact during first runs

**Timing per host (all 65,535 ports)**:
- 100 pps: ~11 minutes
- 500 pps: ~2 minutes
- 1000 pps: ~75 seconds
- 5000 pps: ~15 seconds (use with caution!)

### Nmap Settings

```yaml
nmap:
  binary: "nmap"
  args:
    - "-sV"   # Version detection
    - "-sC"   # Run default scripts
    - "-T4"   # Aggressive timing
    - "-Pn"   # Skip host discovery
```

**Important**:
- Do NOT include `-p` or `-oX` in the args list - these are added automatically
- Port list comes from masscan results, so `-p-` and `-F` are unnecessary
- nmap only scans the open ports discovered by masscan, making scans much faster

### SSH Audit Settings

```yaml
ssh_audit:
  binary: "ssh-audit"
  ports:
    - 22    # Standard SSH
    - 830   # NETCONF over SSH
```

Add additional ports if your environment uses non-standard SSH ports.

### Concurrency and Timeouts

```yaml
concurrency:
  max_concurrent_hosts: 10       # Number of parallel scans
  host_timeout_seconds: 1200     # 20 minutes per host
```

**Important**: The `host_timeout_seconds` is the total time for all three scanning stages:
- **Stage 1 (masscan)**: Gets 20% of timeout for fast port discovery
- **Stage 2 (nmap)**: Gets 70% of timeout for detailed port analysis
- **Stage 3 (ssh-audit)**: Gets 10% of timeout for SSH security checks

**Recommended timeouts with two-stage scanning**:
- **Normal usage**: 600-900 seconds (10-15 minutes)
- **Conservative**: 1200 seconds (20 minutes)
- **Many open ports**: 1800 seconds (30 minutes)

The two-stage approach is **much faster** than the old `-p-` method because nmap only scans discovered ports!

### Email/SMTP Settings

```yaml
email:
  smtp_host: "mail.example.com"
  smtp_port: 25
  smtp_use_tls: false            # Set true for port 587
  from_address: "security-scanner@company.com"
  to_addresses:
    - "netops@company.com"
    - "security@company.com"
  subject_prefix: "Knock Knock Weekly Security Scan"
```

**Note**: This tool is designed for internal SMTP servers that don't require authentication. If your SMTP server requires username/password, you'll need to modify `emailer.py`.

### Reporting Settings

```yaml
reporting:
  ports_of_interest:
    - 22     # SSH
    - 80     # HTTP
    - 443    # HTTPS
    - 8443   # HTTPS alternate
    - 3389   # RDP
  report_title: "Knock Knock Security Scan Report"
```

## Input CSV Format

Create a CSV file with device names and WAN IPs:

```csv
device_name,wan_ip
DAL1-FW1,64.255.192.53
DAL1-FW1,45.205.47.82
LAX1-FW1,203.0.113.10
NYC1-RTR1,198.51.100.5
```

### CSV Requirements

- **Header row**: Must have columns `device_name` and `wan_ip`
- **Multiple IPs**: Same device can appear multiple times with different IPs
- **IP Validation**: Invalid IPs are logged and skipped
- **Deduplication**: Identical rows are automatically deduplicated
- **Comments**: Not supported (remove or prefix with device name)

### Example CSV

Create `targets.csv`:

```csv
device_name,wan_ip
DAL1-FW1,64.255.192.53
DAL1-FW1,45.205.47.82
LAX1-FW1,203.0.113.10
```

## Usage

### Basic Usage

```bash
# Scan targets and generate HTML report only
python3 knock_knock.py --targets targets.csv

# Scan targets and send email
python3 knock_knock.py --targets targets.csv --send-email

# Specify custom output directory
python3 knock_knock.py --targets targets.csv --output-dir /tmp/reports

# Specify custom report filename
python3 knock_knock.py --targets targets.csv --html-report weekly-scan.html
```

### Command-Line Options

```
--targets PATH          Path to CSV file with targets (required)
--output-dir PATH       Directory to save reports (default: /tmp/knockknock-YYYYMMDD-HHMMSS/)
--html-report NAME      Filename for HTML report (default: knock-knock-YYYYMMDD-HHMMSS.html)
--send-email            Send email with report (requires valid SMTP config)
```

### Exit Codes

- **0**: Success (even if some hosts had errors, but overall scan completed)
- **1**: Fatal error (CSV not found, tools missing, invalid SMTP config when --send-email specified)
- **130**: Interrupted by user (Ctrl+C)

## Running from Cron

### Example Crontab Entries

```bash
# Edit crontab
crontab -e
```

Add one of these entries:

```bash
# Run weekly on Sunday at 2 AM with email
0 2 * * 0 /usr/bin/flock -n /tmp/knockknock.lock /usr/bin/python3 /path/to/reporting/knockknock/knock_knock.py --targets /path/to/targets.csv --send-email >> /var/log/knockknock.log 2>&1

# Run daily at 3 AM without email (just generate report)
0 3 * * * /usr/bin/python3 /path/to/reporting/knockknock/knock_knock.py --targets /path/to/targets.csv --output-dir /var/reports/knockknock >> /var/log/knockknock.log 2>&1
```

### Cron Best Practices

1. **Use `flock`** to prevent concurrent runs:
   ```bash
   /usr/bin/flock -n /tmp/knockknock.lock <command>
   ```

2. **Use full paths** to Python and script:
   ```bash
   /usr/bin/python3 /full/path/to/knock_knock.py
   ```

3. **Redirect output** to a log file:
   ```bash
   >> /var/log/knockknock.log 2>&1
   ```

4. **Set up log rotation** for `/var/log/knockknock.log`:
   ```bash
   # Create /etc/logrotate.d/knockknock
   /var/log/knockknock.log {
       weekly
       rotate 12
       compress
       missingok
       notifempty
   }
   ```

## Output

### Directory Structure

When you run the scanner, it creates an output directory with:

```
/tmp/knockknock-20250114-143022/
├── knock-knock-20250114-143022.html
├── masscan-64.255.192.53.json
├── masscan-45.205.47.82.json
├── masscan-203.0.113.10.json
├── nmap-64.255.192.53.xml
├── nmap-45.205.47.82.xml
└── nmap-203.0.113.10.xml
```

- **HTML report**: Human-readable security report
- **masscan JSON files**: Port discovery results from Stage 1
- **nmap XML files**: Detailed analysis data from Stage 2 (for forensic analysis or re-parsing)

### HTML Report Contents

The generated HTML report includes:

1. **Summary Section**:
   - Scan timestamps and duration
   - Device and IP counts
   - Success/error/timeout statistics
   - Total open ports by protocol

2. **Per-Device Sections**:
   - Device name and associated IPs
   - For each IP:
     - Scan status (success/error/timeout)
     - Table of open ports with service/version info
     - Highlighted ports of interest
     - SSH audit results (if SSH detected)

3. **SSH Audit Details** (when applicable):
   - SSH version and banner
   - Key exchange algorithms
   - Ciphers and MACs
   - Critical security issues (highlighted in red)
   - Warnings (highlighted in yellow)

### Email

When `--send-email` is specified, the tool sends an email with:

- **Subject**: `<subject_prefix> - YYYY-MM-DD`
- **Body**: HTML report embedded in email
- **Attachment**: HTML file for offline viewing

## Troubleshooting

### Tools Not Found

```
Error: Required tools not found in PATH: masscan, nmap, ssh-audit
```

**Solution**: Install missing tools with apt-get (see Prerequisites section)

```bash
sudo apt-get install -y masscan nmap ssh-audit
```

### Invalid SMTP Configuration

```
Error: smtp_host is required in email configuration
```

**Solution**: Edit `config.yaml` and ensure all email settings are configured

### CSV File Not Found

```
Error: CSV file not found: targets.csv
```

**Solution**: Verify the path to your CSV file is correct

### Empty CSV or No Valid Targets

```
No valid targets found in CSV
```

**Solution**: Check your CSV file format (must have `device_name` and `wan_ip` columns with valid data)

### Timeouts

If many hosts are timing out:

1. **Increase `host_timeout_seconds` in `config.yaml`**
   - Recommended: 1200-1800 seconds (20-30 minutes)
   - Remember timeout allocation:
     - masscan gets 20%
     - nmap gets 70%
     - ssh-audit gets 10%

2. **Reduce `masscan_rate`** if masscan is timing out
   - Lower rate = slower but more reliable
   - Try reducing from 1000 to 500 pps

3. **Reduce `max_concurrent_hosts`** to avoid network congestion
   - Lower concurrency = less network congestion = more reliable scans
   - Also reduces total PPS (remember: total PPS = hosts × rate)

4. **Adjust nmap timing** if nmap stage is slow
   - Change `-T4` to `-T5` for even more aggressive timing
   - Or use `-T3` or `-T2` for slower but more reliable scans

### Permission Denied / Sudo Issues

**masscan requires sudo** because it uses raw sockets. If you see permission errors:

```
Error: masscan requires root privileges
```

**Solutions**:

1. **Ensure passwordless sudo for masscan** (recommended for automation):
   ```bash
   # Add to /etc/sudoers.d/masscan
   youruser ALL=(root) NOPASSWD: /usr/bin/masscan
   ```

2. **Run the entire script with sudo**:
   ```bash
   sudo python3 knock_knock.py --targets targets.csv --send-email
   ```

3. **Configure masscan capabilities** (alternative to sudo):
   ```bash
   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/masscan
   ```
   Note: If using setcap, you'll need to modify scanner.py to remove the `sudo` from the masscan command.

## Development and Customization

### Adding Custom Scans

To add additional security scans beyond nmap and ssh-audit:

1. Modify `scanner.py` → `scan_host()` function
2. Add new result fields to `HostScanResult` dataclass
3. Update `report.py` to display the new data

### Customizing HTML Output

Edit `report.py`:

- Modify CSS styles in `_html_header()`
- Adjust report sections in `_html_*()` methods
- Change color schemes, fonts, or layout

### Adding SMTP Authentication

If your SMTP server requires authentication, modify `emailer.py`:

```python
# In EmailSender.send_report(), add:
if self.smtp_use_tls:
    with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
        server.starttls()
        server.login(username, password)  # Add this line
        server.send_message(msg)
```

Then add `smtp_username` and `smtp_password` fields to `config.yaml`.

## Security Considerations

1. **Credentials**: This tool does not store or require credentials for target devices
2. **Network Impact**: Scanning can be detected by IDS/IPS systems
3. **Authorization**: Only scan devices you have permission to scan
4. **Data Handling**: Reports may contain sensitive information; protect accordingly
5. **SMTP**: Email reports are sent unencrypted unless using TLS

## License

This tool was generated by Claude Code for network security assessment purposes.

## Support

For issues, questions, or contributions, contact your network operations team or the tool maintainer.
