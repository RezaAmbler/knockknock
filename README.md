# Knock Knock Security Scanner

A production-quality command-line security scanning tool that uses a multi-stage scanning approach (`masscan` → `nmap` → `ssh-audit` → `nuclei`) to efficiently scan network devices, generate comprehensive HTML reports, and send them via email.

## Features

- **Four-Stage Scanning Pipeline**: Ultra-fast port discovery with masscan, followed by detailed nmap analysis, SSH security auditing, and optional vulnerability scanning
  - Stage 1: masscan scans all 65,535 ports in ~75 seconds (at 1000 pps)
  - Stage 2: nmap performs deep analysis with SYN scan on only the discovered open ports
  - Stage 3: ssh-audit analyzes SSH security on detected SSH services
  - Stage 4: nuclei performs vulnerability scanning on discovered services (optional)
- **Parallel Execution**: Scans multiple hosts concurrently with progress tracking
- **Network Safety**: Configurable packet rate limits with PPS calculations to prevent network congestion
- **Comprehensive Analysis**: Version detection, vulnerability scanning, and SSH security auditing
- **Historical Database Logging**: SQLite-based append-only logging of all scan results for trend analysis
- **Multiple Report Types**:
  - Port history reports (first/last seen, frequency)
  - SSH security audit reports (warnings, critical failures)
  - Comprehensive reports (both port + SSH data)
  - Table and CSV output formats
- **HTML Reports**: Generates clean, readable HTML reports with embedded CSS and SSH security findings
- **Email Delivery**: Sends reports via SMTP with both embedded HTML and file attachment
- **Debug Mode**: Comprehensive diagnostic logging for troubleshooting scan failures
- **Flexible Configuration**: YAML-based configuration for all settings
- **Robust Error Handling**: Gracefully handles timeouts, connection failures, and errors
- **Cron-Ready**: Designed for automated weekly/daily scanning with database tracking

## sou Start

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
source activate
# Or: source venv/bin/activate

# Copy the example targets file
cp targets.csv.example targets.csv

# Edit targets.csv with your devices
# Edit conf/config.yaml with your settings

# Run your first scan
python3 knock_knock.py --targets targets.csv
```

## Prerequisites

### System Requirements

- **OS**: Linux (tested on Ubuntu/Debian) or macOS
- **Python**: 3.8 or higher
- **Required Tools**: `masscan`, `nmap`, and `ssh-audit` must be installed and available in PATH
- **Optional Tools**: `nuclei` for vulnerability scanning (highly recommended)
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

# Install Nuclei (optional but recommended)
# Option 1: Using Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Option 2: Using pre-built binary
# Download from https://github.com/projectdiscovery/nuclei/releases
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.x.x_linux_amd64.zip
unzip nuclei_3.x.x_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei

# Verify installation
which masscan
which nmap
which ssh-audit
which nuclei  # Optional

# Test masscan works with sudo
sudo masscan --version

# Update Nuclei templates (if installed)
nuclei -update-templates
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

Edit `conf/config.yaml` to customize the scanner behavior:

### Multi-Stage Scanning Workflow

This tool uses an efficient multi-stage scanning approach:

**Stage 1 - Fast Port Discovery (masscan)**:
- Scans ALL 65,535 ports on each host in ~75 seconds (at 1000 pps)
- Identifies which ports are open
- Generates JSON output for parsing

**Stage 2 - Detailed Analysis (nmap)**:
- Scans ONLY the ports discovered by masscan
- Performs version detection, service detection, and script execution
- Much faster than traditional `-p-` scanning

**Stage 3 - SSH Security Audit (ssh-audit)**:
- Analyzes SSH services on configured ports (default: 22, 830)
- Detects weak ciphers, key exchange algorithms, and MACs
- Identifies critical security issues and warnings

**Stage 4 - Vulnerability Scanning (nuclei - optional)**:
- Performs automated vulnerability scanning using community templates
- Can scan IPs directly or construct URLs from HTTP/HTTPS ports
- Filters by severity level (critical, high, medium, low, info)
- Results stored in database and displayed in HTML reports

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

### Nuclei Settings (Optional Vulnerability Scanner)

Nuclei is an optional but highly recommended vulnerability scanner that runs after port discovery. When enabled, it performs automated vulnerability scanning using thousands of community-maintained templates.

```yaml
nuclei:
  # Enable/disable Nuclei vulnerability scanning
  enabled: false  # Set to true to enable

  # Path to nuclei binary (use 'nuclei' if in PATH)
  binary: "nuclei"

  # Severity levels to include (comma-separated)
  # Options: critical, high, medium, low, info
  # Leave empty to include all severities
  severity: "critical,high,medium"

  # Timeout for Nuclei scan per host (in seconds)
  # Nuclei can take significant time if many templates are enabled
  # Recommended: 300-600 seconds (5-10 minutes)
  timeout: 300

  # Path to custom templates directory (optional)
  # Leave empty to use Nuclei's default templates
  templates: ""

  # Scan mode: "ips" or "urls"
  # - "ips": Scan IP addresses directly (default)
  # - "urls": Build URLs from http/https ports (e.g., https://192.0.2.1:443)
  scan_mode: "ips"
```

**Scan Modes Explained**:

1. **`ips` mode** (default): Scans the IP address directly
   - Example: `nuclei -target 192.0.2.1`
   - Good for: Network-level vulnerability scanning
   - Faster and covers all services

2. **`urls` mode**: Constructs URLs from discovered HTTP/HTTPS ports
   - Example: `nuclei -target https://192.0.2.1:443`
   - Good for: Web application vulnerability scanning
   - More targeted for web services

**Template Management**:

```bash
# Update Nuclei templates (do this regularly)
nuclei -update-templates

# Use custom templates
nuclei:
  templates: "/path/to/custom/nuclei-templates"
```

**Performance Considerations**:
- Nuclei scanning can take 5-10 minutes per host with default templates
- Adjust `timeout` based on your network and number of templates
- Use `severity` filter to reduce scan time (e.g., only scan for critical/high)
- Nuclei runs in parallel across multiple hosts (respects `max_concurrent_hosts`)

### Concurrency and Timeouts

```yaml
concurrency:
  max_concurrent_hosts: 10       # Number of parallel scans
  host_timeout_seconds: 1200     # 20 minutes per host
```

**Important**: The `host_timeout_seconds` is the total time for all scanning stages (masscan, nmap, ssh-audit):
- **Stage 1 (masscan)**: Gets 20% of timeout for fast port discovery
- **Stage 2 (nmap)**: Gets 70% of timeout for detailed port analysis
- **Stage 3 (ssh-audit)**: Gets 10% of timeout for SSH security checks
- **Stage 4 (nuclei)**: Has its own dedicated timeout setting (not part of host_timeout_seconds)

**Recommended timeouts**:
- **Normal usage**: 600-900 seconds (10-15 minutes)
- **Conservative**: 1200 seconds (20 minutes)
- **Many open ports**: 1800 seconds (30 minutes)

**Note**: Nuclei has its own separate timeout (`nuclei.timeout`) and runs independently after the three core scanning stages.

The multi-stage approach is **much faster** than the old `-p-` method because nmap only scans discovered ports!

### Email/SMTP Settings

```yaml
email:
  smtp_host: "mail.example.com"
  smtp_port: 25
  smtp_use_tls: false            # Set true for port 587
  smtp_username: null            # Optional, or use SMTP_USERNAME env var
  smtp_password: null            # Optional, or use SMTP_PASSWORD env var
  from_address: "security-scanner@company.com"
  to_addresses:
    - "netops@company.com"
    - "security@company.com"
  subject_prefix: "Knock Knock Weekly Security Scan"
```

**SMTP Authentication**: For Gmail and other authenticated SMTP servers, you can provide credentials in two ways:

1. **Environment variables (recommended for security)**:
   ```bash
   export SMTP_USERNAME="your-email@gmail.com"
   export SMTP_PASSWORD="your-app-password"
   python3 knock_knock.py --targets targets.csv --send-email
   ```

2. **Config file** (less secure, credentials stored in plaintext):
   ```yaml
   smtp_username: "your-email@gmail.com"
   smtp_password: "your-app-password"
   ```

Environment variables take precedence over config file values.

**Gmail Setup**: For Gmail, you need to:
- Use `smtp.gmail.com` on port `587` with `smtp_use_tls: true`
- Generate an App Password at https://myaccount.google.com/apppasswords
- Use the App Password, not your regular Gmail password

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
SITE1-FW1,192.0.2.10
SITE1-FW1,192.0.2.11
SITE2-FW1,198.51.100.20
SITE3-RTR1,203.0.113.30
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
SITE1-FW1,192.0.2.10
SITE1-FW1,192.0.2.11
SITE2-FW1,198.51.100.20
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

#### Scanning Mode
```
--targets PATH          Path to CSV file with targets (required for scan mode)
--output-dir PATH       Directory to save reports (default: /tmp/knockknock-YYYYMMDD-HHMMSS/)
--html-report NAME      Filename for HTML report (default: knock-knock-YYYYMMDD-HHMMSS.html)
--send-email            Send email with report (requires valid SMTP config)
--test-email            Send a test email and exit (validates SMTP configuration)
--quiet                 Reduce log output (only show warnings and errors)
--debug                 Enable debug logging (shows commands, detailed errors, diagnostics)
```

#### Database Logging
```
--db-path PATH          Path to SQLite database (enables DB logging, overrides config)
--no-db                 Explicitly disable database logging (overrides config)
```

#### Reporting Mode
```
--report TYPE           Generate report from database
                        Choices: ports, ssh-audit, all
  ports                 Port history report (first/last seen, runs count)
  ssh-audit             SSH security findings (warnings, critical failures)
  all                   Comprehensive report (ports + SSH audit)

--from DATE             Start datetime for report range (ISO-8601: YYYY-MM-DDTHH:MM:SSZ)
--to DATE               End datetime for report range (ISO-8601: YYYY-MM-DDTHH:MM:SSZ)
--host FILTER           Filter report by hostname or IP (optional)
--port NUMBER           Filter report by port number (optional)
--output FORMAT         Output format for reports
                        Choices: table (default), csv
```

### Exit Codes

- **0**: Success (even if some hosts had errors, but overall scan completed)
- **1**: Fatal error (CSV not found, tools missing, invalid SMTP config when --send-email specified)
- **130**: Interrupted by user (Ctrl+C)

## Database Logging and Historical Reporting

Knock Knock can optionally log all scan results to a SQLite database for historical tracking and trend analysis.

### Configuring Database Logging

Edit `conf/config.yaml`:

```yaml
database:
  enabled: true
  path: "/var/lib/knockknock/knockknock.db"
```

Or use command-line flags:

```bash
# Enable database logging for this run (overrides config)
python3 knock_knock.py --targets targets.csv --db-path /path/to/database.db

# Explicitly disable database logging (even if enabled in config)
python3 knock_knock.py --targets targets.csv --no-db
```

**Precedence**:
1. `--no-db` disables database logging
2. `--db-path PATH` enables logging to specified path
3. `database.enabled: true` in conf/config.yaml uses `database.path`

### Database Behavior

- **Append-only**: All scan runs are recorded; nothing is ever deleted
- **Never fails scans**: Database errors are logged as warnings but don't stop scanning
- **Automatic schema creation**: Database and tables are created automatically on first use

### Viewing Historical Reports

Query the database for historical information across time ranges. Three report types are available:

#### 1. Port History Report (`--report ports`)

Shows port observation history (when ports were first/last seen, how often):

```bash
# Show all open ports observed in January 2025
python3 knock_knock.py --report ports \
  --from 2025-01-01T00:00:00Z \
  --to   2025-01-31T23:59:59Z \
  --db-path /var/lib/knockknock/knockknock.db

# Show ports for a specific host
python3 knock_knock.py --report ports \
  --host site1-fw1 \
  --db-path /var/lib/knockknock/knockknock.db

# Show only port 22 (SSH) across all hosts
python3 knock_knock.py --report ports \
  --port 22 \
  --db-path /var/lib/knockknock/knockknock.db

# Export to CSV format
python3 knock_knock.py --report ports \
  --output csv \
  --db-path /var/lib/knockknock/knockknock.db > ports-report.csv
```

**Ports report shows:**
- Hostname and IP address
- Port and Protocol
- First Seen / Last Seen timestamps
- Runs Count (how many scans detected this port)
- Product and Version (from most recent scan)

Example output:
```
HOSTNAME        IP           PORT PROTO FIRST_SEEN              LAST_SEEN               RUNS PRODUCT          VERSION
--------------  -----------  ---- ----- ----------------------- ----------------------- ---- ---------------  --------------
site1-fw1       192.0.2.10   22   tcp   2025-01-01T01:00:05Z    2025-01-31T23:00:10Z    124  OpenSSH          9.5p1
site1-fw1       192.0.2.10   443  tcp   2025-01-01T01:00:05Z    2025-01-31T23:00:10Z    124  nginx            1.24.0

Total: 2 unique port(s)
```

#### 2. SSH Security Audit Report (`--report ssh-audit`)

Shows SSH security findings (warnings and critical failures):

```bash
# Show SSH security issues for all hosts
python3 knock_knock.py --report ssh-audit \
  --db-path /var/lib/knockknock/knockknock.db

# Show SSH issues for specific host in date range
python3 knock_knock.py --report ssh-audit \
  --from 2025-01-01T00:00:00Z \
  --to   2025-01-31T23:59:59Z \
  --host site1-fw1 \
  --db-path /var/lib/knockknock/knockknock.db

# Export SSH audit findings to CSV
python3 knock_knock.py --report ssh-audit \
  --output csv \
  --db-path /var/lib/knockknock/knockknock.db > ssh-issues.csv
```

**SSH audit report shows:**
- Hostname, IP, and port
- Scan date (most recent)
- SSH banner
- Total issues count (warnings + failures)
- Top 3 warnings (e.g., weak modulus, encrypt-and-MAC mode)
- Top 3 critical failures (e.g., NSA-backdoored elliptic curves)

Example output:
```
HOSTNAME    IP              PORT  SCAN_DATE                 BANNER                ISSUES
----------  --------------  ----  ------------------------  --------------------  ------
site1-fw1   192.0.2.10      22    2025-01-20T15:30:45Z      SSH-2.0-OpenSSH_8.9   6
  ⚠️  WARNINGS: KEX diffie-hellman-group14-sha256: 2048-bit modulus only provides 112-bits
  🔴 FAILURES: KEX ecdh-sha2-nistp256: using elliptic curves suspected as backdoored by NSA

Total: 1 SSH endpoint(s)
```

#### 3. Comprehensive Report (`--report all`)

Shows both port history AND SSH security audit in one report:

```bash
# Generate comprehensive report
python3 knock_knock.py --report all \
  --from 2025-01-01T00:00:00Z \
  --to   2025-01-31T23:59:59Z \
  --db-path /var/lib/knockknock/knockknock.db

# Comprehensive CSV export
python3 knock_knock.py --report all \
  --output csv \
  --db-path /var/lib/knockknock/knockknock.db > complete-report.csv
```

**All report shows:**
- PORT HISTORY section (same as `--report ports`)
- SSH SECURITY AUDIT section (same as `--report ssh-audit`)

### Time Range Defaults

- `--from`: Defaults to earliest run in database
- `--to`: Defaults to current time (UTC)
- **Format**: ISO-8601 with Z suffix (e.g., `2025-01-01T00:00:00Z`)

### Combining with Scanning

You can enable database logging during regular scans:

```bash
# Scan and log to database
python3 knock_knock.py --targets targets.csv --db-path /var/lib/knockknock/knockknock.db

# Scan, log to DB, and send email
python3 knock_knock.py --targets targets.csv --db-path /var/lib/knockknock/knockknock.db --send-email
```

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
├── masscan-192.0.2.10.json
├── masscan-192.0.2.11.json
├── masscan-198.51.100.20.json
├── nmap-192.0.2.10.xml
├── nmap-192.0.2.11.xml
└── nmap-198.51.100.20.xml
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

**Solution**: Edit `conf/config.yaml` and ensure all email settings are configured

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

## Security Considerations

1. **Credentials**: This tool does not store or require credentials for target devices
2. **Network Impact**: Scanning can be detected by IDS/IPS systems
3. **Authorization**: Only scan devices you have permission to scan
4. **Data Handling**: Reports may contain sensitive information; protect accordingly
5. **SMTP Credentials**: Use environment variables (`SMTP_USERNAME`, `SMTP_PASSWORD`) instead of storing credentials in `config.yaml`
6. **SMTP Transport**: Email reports are sent unencrypted unless using TLS (`smtp_use_tls: true`)

## License

This tool was generated by Claude Code for network security assessment purposes.

## Support

For issues, questions, or contributions, contact your network operations team or the tool maintainer.
