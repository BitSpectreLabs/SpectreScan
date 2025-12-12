<p align="center">
  <img src="spectrescan/assets/logo.png" alt="SpectreScan Logo" width="200"/>
</p>

# SpectreScan
<p align="left">
  <img src="https://skillicons.dev/icons?i=python,linux,windows,apple" alt="Platform Support" height="30"/>
</p>

**Professional-grade Open Source Port Scanner**

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/BitSpectreLabs/SpectreScan)

```
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
                                                             
   ███████╗ ██████╗ █████╗ ███╗   ██╗                      
   ██╔════╝██╔════╝██╔══██╗████╗  ██║                      
   ███████╗██║     ███████║██╔██╗ ██║                      
   ╚════██║██║     ██╔══██║██║╚██╗██║                      
   ███████║╚██████╗██║  ██║██║ ╚████║                      
   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                      
                                                             
        Professional Port Scanner by BitSpectreLabs
```

---

## <img src="https://cdn.simpleicons.org/readme/018EF5" width="20" height="20" style="vertical-align: middle;"/> Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [CLI Interface](#cli-interface)
  - [TUI Interface](#tui-interface)
  - [GUI Interface](#gui-interface)
- [Scan Modes](#-scan-modes)
- [Output Formats](#-output-formats)
- [Examples](#-examples)
- [Development](#-development)
- [Testing](#-testing)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## <img src="https://cdn.simpleicons.org/starship/DD0B78" width="20" height="20" style="vertical-align: middle;"/> Features

### Core Scanning Capabilities

- **TCP Connect Scan** - Full TCP three-way handshake
- **TCP SYN Scan** - Stealth half-open scanning (requires elevated privileges)
- **UDP Scan** - UDP port scanning with intelligent heuristics
- **Async High-Speed Scan** - Concurrent scanning using asyncio
- **Threaded Scan** - Multi-threaded scanning fallback
- **Stealth Mode** - Low-profile scanning with randomization

### Advanced Features

- **Multi-Target Scanning** - Scan multiple targets from command line or file
- **Host Discovery** - ICMP ping, TCP ping, ARP scanning
- **Service Detection** - Automatic service/version identification with **7000+ signatures**
- **Banner Grabbing** - Capture service banners for fingerprinting
- **OS Detection** - TTL-based and TCP fingerprinting
- **Scan Profiles** - Save and reuse scan configurations
- **Scan History** - Track and review previous scans
- **Rate Limiting** - Control scan speed to avoid detection
- **Timing Templates** - Paranoid to Insane (0-5)
- **Randomized Scanning** - Randomize target and port order
- **Graceful Error Handling** - Robust exception management

### Enterprise Features

- **IPv6 Support** - Full IPv6 address and network scanning
- **SSL/TLS Analysis** - Certificate validation, cipher suite analysis, vulnerability detection
- **CVE Matching** - Automatic CVE lookup for detected services
- **REST API Server** - Full-featured FastAPI server with WebSocket support
- **Scan Resume/Checkpoint** - Save and resume interrupted scans
- **Configuration Files** - TOML-based configuration with layered settings
- **DNS Enumeration** - Subdomain discovery, zone transfers, record lookup
- **Markdown Reports** - Generate Markdown-formatted scan reports
- **Shell Completion** - Tab completion for Bash, Zsh, Fish, PowerShell

### NSE Compatibility

- **NSE Script Engine** - Execute Nmap-compatible Lua scripts
- **10 Bundled Scripts** - http-title, ssl-cert, ssh-hostkey, ftp-anon, and more
- **Script Categories** - auth, brute, discovery, exploit, vuln, safe, default
- **Script Arguments** - Pass custom arguments to scripts
- **Lua Runtime** - Powered by Lupa (LuaJIT Python binding)

### Distributed Scanning

- **Master-Worker Architecture** - Coordinate large-scale scans across multiple machines
- **Worker Registration** - Automatic worker discovery and registration
- **Task Distribution** - Intelligent load balancing across workers
- **Result Aggregation** - Combine results from all workers automatically
- **Health Monitoring** - Track worker status with heartbeat checks
- **Automatic Failover** - Retry failed tasks on healthy workers
- **Secure Communication** - TLS encryption between master and workers
- **Message Queue Support** - Redis/RabbitMQ for reliable task delivery

### Web Dashboard

- **Real-time Monitoring** - Live scan progress via WebSocket
- **Interactive Dashboard** - Modern responsive web interface
- **User Authentication** - Session-based login with secure password hashing
- **Role-Based Access Control** - 5 roles with 30+ granular permissions
- **Scan Management** - Start, stop, pause scans from the browser
- **History Browser** - View and search past scan results
- **Profile Management** - Create and manage scan profiles via UI
- **Dark Theme** - Professional dark mode interface
- **Mobile Responsive** - Works on desktop and mobile devices

### Scan Scheduling and Automation

- **Cron-like Scheduling** - Full cron expression support with wildcards, ranges, lists, and steps
- **Multiple Schedule Types** - One-time, cron, interval, daily, weekly, and monthly schedules
- **Pre/Post Scan Hooks** - Execute shell commands or Python functions before and after scans
- **Conditional Execution** - Run scans only if host is up, port changed, or within time window
- **Scan Chaining** - Link scans together to create automated workflows
- **Background Daemon** - Persistent scheduler daemon for continuous monitoring
- **Schedule Persistence** - SQLite-based storage for reliable schedule management
- **Schedule Management CLI** - Full CRUD operations via `spectrescan schedule` command

### Proxy Support

- **SOCKS4/4a/5 Support** - Full SOCKS proxy protocol support with authentication
- **HTTP/HTTPS Proxy** - HTTP CONNECT method proxy support
- **Proxy Chaining** - Route traffic through multiple proxies (multi-hop)
- **Proxy Pool** - Manage multiple proxies with automatic rotation
- **Rotation Strategies** - Round-robin, random, least-used, or fastest proxy selection
- **Tor Integration** - Built-in Tor network support with circuit renewal
- **Health Checking** - Automatic proxy health monitoring and validation
- **Per-target Configuration** - Different proxies for different targets

### IDS/IPS Evasion

- **Packet Fragmentation** - Split packets to evade signature detection
- **Decoy Scanning** - Send packets from spoofed source IPs
- **Source Port Manipulation** - Use common ports (53, 80, 443) as source
- **TTL Manipulation** - Control time-to-live values for stealth
- **Bad Checksum Packets** - Send malformed packets that IDS may ignore
- **Idle/Zombie Scanning** - Use third-party hosts for stealth scanning
- **Timing-based Evasion** - Slow scans to avoid rate-based detection
- **Host Randomization** - Randomize target scan order
- **Custom Packet Crafting** - Full control over packet construction
- **Evasion Profiles** - Preset configurations (stealth, paranoid, aggressive)

### Comprehensive Signature Databases

SpectreScan includes **extensive signature databases** for professional-grade service detection:

#### **CPE Dictionary** (`cpe-dictionary.json`)
- **200+ CPE mappings** for Common Platform Enumeration
- Covers: Web servers, databases, containers, DevOps tools, security software
- Categories: 10 major categories (web_servers, databases, app_servers, network_services, dev_tools, containers, monitoring, messaging, storage, security)
- **Services included:**
  - Web Servers: Apache, Nginx, IIS, Lighttpd, Caddy, Tomcat, Jetty, Undertow, WildFly, WebLogic, WebSphere
  - Databases: MySQL, MariaDB, PostgreSQL, Redis, MongoDB, Elasticsearch, Cassandra, CouchDB, Oracle, MSSQL, DB2, InfluxDB, Neo4j
  - Containers: Docker, Kubernetes, Containerd, Podman, OpenShift, Rancher
  - DevOps: Jenkins, GitLab, GitHub Enterprise, Bitbucket, TeamCity, Bamboo, Ansible, Puppet, Chef, Terraform, Vault, Consul
  - Monitoring: Grafana, Prometheus, Nagios, Zabbix, Datadog, NewRelic, Splunk, Kibana, Logstash, Fluentd
  - Messaging: RabbitMQ, Kafka, ActiveMQ, MQTT/Mosquitto, NATS, ZeroMQ
  - Proxies: HAProxy, Squid, Varnish, Traefik, Envoy
  - Storage: MinIO, Ceph, GlusterFS, NFS, Samba, Nextcloud, ownCloud
  - Security: Snort, Suricata, Fail2Ban, OSSEC, Wazuh, OpenVAS, Nessus

#### **Service Signatures** (`service-signatures.json`)
- **150+ service signatures** with regex patterns
- Port mappings, protocols, confidence scores, CPE identifiers
- **Categories:** container, orchestration, database, web_server, app_server, monitoring, ci_cd, messaging, cache, proxy, security, storage
- **Modern services included:**
  - Containers: Docker, Kubernetes, Containerd, Podman, Rancher, OpenShift
  - Databases: All major SQL/NoSQL databases with version detection
  - Web/App Servers: Full coverage of enterprise and open-source servers
  - DevOps: Complete CI/CD pipeline tool detection
  - Monitoring: Full observability stack (Prometheus, Grafana, ELK, etc.)
  - Messaging: AMQP, MQTT, Kafka and other queue systems
  - CMS: WordPress, Drupal, Joomla, Magento
  - Frameworks: Django, Flask, Rails, Laravel, Spring, Express, Next.js, React, Angular, Vue

#### **Version Patterns** (`version-patterns.json`)
- **100+ version extraction patterns** with multiple regex variants per service
- Generic fallback patterns for unknown services
- OS version patterns for Ubuntu, Debian, CentOS, RHEL, Alpine, Windows, macOS
- **Extracts versions from:**
  - HTTP headers (Server, X-Powered-By, X-AspNet-Version, etc.)
  - Service banners (SSH, FTP, SMTP, database handshakes)
  - API responses (JSON version endpoints)
  - Binary protocol handshakes

#### **Nmap Service Probes** (`nmap-service-probes`)
- **100+ service probes** based on Nmap format (GPLv2 compatible)
- NULL probe + specialized probes for each service category
- **Probe categories:**
  - **Web Services:** HTTP GET, SSL/TLS handshake
  - **Remote Access:** SSH, RDP, VNC, TeamViewer, Telnet
  - **Databases:** MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Elasticsearch, Cassandra, CouchDB, InfluxDB, Neo4j
  - **Mail:** SMTP, IMAP, POP3, Exchange
  - **File Transfer:** FTP (vsftpd, ProFTPD, Pure-FTPd, FileZilla), Samba/SMB
  - **Containers:** Docker API, Kubernetes API, Containerd, Rancher, OpenShift
  - **DevOps:** Jenkins, GitLab, Ansible Tower, GitLab Runner, Portainer
  - **Monitoring:** Grafana, Prometheus, Nagios, Zabbix, Splunk, Kibana, Logstash
  - **Messaging:** RabbitMQ (AMQP + Management), Kafka, MQTT/Mosquitto, NATS, ActiveMQ
  - **Proxies:** HAProxy, Squid, Varnish, Traefik
  - **Security:** LDAP, Nagios NRPE, Zabbix Agent
  - **CMS/Web Apps:** WordPress, Drupal, Joomla, Magento, Nextcloud/ownCloud
  - **Enterprise:** Tomcat, WebLogic, WebSphere, WildFly/JBoss
  - **IoT/Network:** Home Assistant, Node-RED, Pi-hole, pfSense, OPNsense, UniFi Controller
  - **Network Services:** DNS, SNMP, NTP, SIP, RTSP
  - **Storage:** MinIO, etcd, Consul, Vault

**Total Detection Coverage:**
- **200+ CPE entries** for precise product identification
- **150+ service signatures** with pattern matching
- **100+ version patterns** with multiple regex variants
- **100+ Nmap-compatible probes** covering modern and legacy services
- **7000+ combined detection rules** for comprehensive coverage

### Multiple Interfaces

- **CLI** - Powerful command-line interface with Typer and shell completion
- **TUI** - Beautiful terminal UI with Textual framework
- **GUI** - User-friendly tkinter graphical interface
- **REST API** - FastAPI server with WebSocket support and JWT authentication

### Professional Reporting

- **JSON** - Structured data export
- **CSV** - Spreadsheet-compatible format
- **XML** - Standardized markup format
- **HTML** - Professional branded reports with logo and summary
- **PDF** - Charts and executive summaries with ReportLab
- **Markdown** - Documentation-friendly format

### Scan Presets

- `--quick` - Fast scan of top 100 ports
- `--top-ports` - Scan top 1000 most common ports
- `--full` - Comprehensive scan of all 65535 ports
- `--stealth` - Low-profile SYN scan with rate limiting
- `--safe` - Non-intrusive conservative scan
- `--aggressive` - Fast comprehensive scan with all features

---

## <img src="https://cdn.simpleicons.org/diagramsdotnet/F08705" width="20" height="20" style="vertical-align: middle;"/> Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SpectreScan System                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                User Interfaces Layer                 │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │  CLI (Typer)  │  TUI (Textual)  │  GUI (Tkinter)     │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Core Scanning Engine                    │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │                                                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐   │   │
│  │  │ TCP Connect  │  │   TCP SYN    │  │ UDP Scan  │   │   │
│  │  │    Scan      │  │     Scan     │  │           │   │   │
│  │  └──────────────┘  └──────────────┘  └───────────┘   │   │
│  │                                                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐   │   │
│  │  │ Async Scan   │  │   Threaded   │  │   Host    │   │   │
│  │  │              │  │     Scan     │  │ Discovery │   │   │
│  │  └──────────────┘  └──────────────┘  └───────────┘   │   │
│  │                                                      │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Detection & Analysis Layer                 │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │  Service Detection │ Banner Grabbing │ OS Detection  │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Report Generation Layer                 │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │    JSON    │    CSV    │    XML    │    HTML         │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Module Structure

```
spectrescan/
├── core/                  # Core scanning engine
│   ├── scanner.py         # Main port scanner
│   ├── syn_scan.py        # SYN scan implementation
│   ├── udp_scan.py        # UDP scan implementation
│   ├── async_scan.py      # Async scanning
│   ├── host_discovery.py  # Host discovery
│   ├── banners.py         # Banner grabbing
│   ├── os_detect.py       # OS detection
│   ├── presets.py         # Scan presets
│   └── utils.py           # Utility functions
│
├── cli/                   # Command-line interface
│   └── main.py            # CLI application
│
├── tui/                   # Terminal user interface
│   ├── app.py             # TUI application
│   └── widgets/           # Custom widgets
│       ├── results_table.py
│       ├── progress.py
│       └── logs.py
│
├── gui/                   # Graphical user interface
│   └── app.py             # GUI application
│
├── reports/               # Report generators
│   ├── __init__.py        # JSON, CSV, XML
│   └── html_report.py     # HTML report generator
│
├── tests/                 # Unit tests
│   └── test_scanner.py
│
└── assets/                # Assets
    ├── logo.txt
    └── logo.png
```

---

## <img src="https://cdn.simpleicons.org/anaconda/44A833" width="20" height="20" style="vertical-align: middle;"/> Installation

### Requirements

- Python 3.11 or higher
- pip package manager
- (Optional) Administrator/root privileges for SYN scanning

### Quick Setup (Recommended)

Use the automated setup scripts for hassle-free installation:

**Windows PowerShell:**
```powershell
# Clone and navigate to the repository
git clone https://github.com/BitSpectreLabs/SpectreScan.git
cd SpectreScan

# Run the setup script
.\setup.ps1
```

**Linux/macOS:**
```bash
# Clone and navigate to the repository
git clone https://github.com/BitSpectreLabs/SpectreScan.git
cd SpectreScan

# Make the setup script executable
chmod +x setup.sh

# Run the setup script
./setup.sh
```

The setup script will:
1. <img src="https://cdn.simpleicons.org/checkmarx/54B435" width="14" height="14" style="vertical-align: middle;"/> Check Python installation
2. <img src="https://cdn.simpleicons.org/checkmarx/54B435" width="14" height="14" style="vertical-align: middle;"/> Create virtual environment
3. <img src="https://cdn.simpleicons.org/checkmarx/54B435" width="14" height="14" style="vertical-align: middle;"/> Install all dependencies
4. <img src="https://cdn.simpleicons.org/checkmarx/54B435" width="14" height="14" style="vertical-align: middle;"/> Install SpectreScan
5. <img src="https://cdn.simpleicons.org/checkmarx/54B435" width="14" height="14" style="vertical-align: middle;"/> Verify installation

### Manual Installation

If you prefer manual setup:

```bash
# Clone the repository
git clone https://github.com/BitSpectreLabs/SpectreScan.git
cd SpectreScan

# Create virtual environment (recommended)
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Windows CMD:
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

# Install dependencies using venv's pip
.venv/Scripts/python -m pip install -r requirements.txt  # Windows
.venv/bin/python -m pip install -r requirements.txt      # Linux/macOS

# Install SpectreScan in editable mode
.venv/Scripts/python -m pip install -e .  # Windows
.venv/bin/python -m pip install -e .      # Linux/macOS
```

> **Note**: Always use the virtual environment's Python/pip to ensure packages are installed correctly.

---

## <img src="https://cdn.simpleicons.org/windowsterminal/4D4D4D" width="20" height="20" style="vertical-align: middle;"/> Quick Start

### Basic Scan

```bash
# Quick scan of a single target (top 100 ports)
spectrescan 192.168.1.1 --quick

# Scan with custom ports
spectrescan scanme.nmap.org -p 1-1000

# Full scan with all features
spectrescan 10.0.0.1 --aggressive

# List available scan presets
spectrescan presets

# Show version
spectrescan version
```

### Launch TUI

```bash
# Launch TUI interface
spectrescan tui

# Or with pre-filled target and ports
spectrescan tui 192.168.1.1 -p 1-1000
```

### Launch GUI

```bash
# Launch GUI interface
spectrescan gui
```

---

## <img src="https://cdn.simpleicons.org/gitbook/3884FF" width="20" height="20" style="vertical-align: middle;"/> Usage

### CLI Interface

#### Basic Commands

```bash
# Scan single host (scan command is optional)
spectrescan 192.168.1.1
spectrescan scan 192.168.1.1

# Scan CIDR range
spectrescan 192.168.1.0/24

# Scan IP range
spectrescan 192.168.1.1-254

# Scan hostname
spectrescan scanme.nmap.org
```

#### Multi-Target Scanning

```bash
# Scan multiple targets (comma-separated)
spectrescan 192.168.1.1,192.168.1.10,scanme.nmap.org

# Scan multiple ranges
spectrescan 192.168.1.1-10,192.168.2.1-10

# Scan from target file
spectrescan --target-file targets.txt

# Short option
spectrescan -iL targets.txt
```

**Target File Format** (`targets.txt`):
```text
# Web servers
192.168.1.1
scanme.nmap.org

# Database servers
10.0.0.10-15

# Development network
192.168.100.0/24

# External servers
example.com
test.example.org
```

**Target File Features:**
- One target per line
- Supports all target formats (IP, CIDR, range, hostname)
- Comments with `#` prefix
- Empty lines ignored
- Duplicates automatically removed

#### Port Specifications

```bash
# Single port
spectrescan 192.168.1.1 -p 80

# Port range
spectrescan 192.168.1.1 -p 1-1000

# Multiple ports
spectrescan 192.168.1.1 -p 22,80,443,8080

# Mixed specification
spectrescan 192.168.1.1 -p 22,80-100,443,8000-9000
```

#### Scan Types

```bash
# TCP connect scan (default)
spectrescan 192.168.1.1 --tcp

# TCP SYN scan (requires privileges)
sudo spectrescan 192.168.1.1 --syn

# UDP scan
spectrescan 192.168.1.1 --udp

# Async high-speed scan
spectrescan 192.168.1.1 --async --threads 1000
```

#### Presets

```bash
# Quick scan (top 100 ports)
spectrescan 192.168.1.1 --quick

# Top ports scan (top 1000 ports)
spectrescan 192.168.1.1 --top-ports

# Full scan (all 65535 ports)
spectrescan 192.168.1.1 --full

# Stealth scan
sudo spectrescan 192.168.1.1 --stealth

# Safe scan
spectrescan 192.168.1.1 --safe

# Aggressive scan
spectrescan 192.168.1.1 --aggressive
```

#### Advanced Options

```bash
# Custom threads and timeout
spectrescan 192.168.1.1 -p 1-1000 --threads 500 --timeout 1.5

# Rate limiting
spectrescan 192.168.1.1 --rate-limit 100

# Enable OS detection
spectrescan 192.168.1.1 --os-detection

# Disable service detection
spectrescan 192.168.1.1 --no-service-detection

# Randomize scan order
spectrescan 192.168.1.1 --randomize
```

#### Output Formats

```bash
# Save JSON report
spectrescan 192.168.1.1 --json results.json

# Save CSV report
spectrescan 192.168.1.1 --csv results.csv

# Save XML report
spectrescan 192.168.1.1 --xml results.xml

# Save HTML report
spectrescan 192.168.1.1 --html report.html

# Save all formats
spectrescan 192.168.1.1 --json out.json --csv out.csv --html report.html
```

#### Scan Profiles

Save and reuse scan configurations:

```bash
# List available profiles
spectrescan profile list

# View profile details
spectrescan profile load "Quick Scan"

# Export profile to file
spectrescan profile export "My Profile" --file myprofile.json

# Import profile from file
spectrescan profile import --file myprofile.json

# Delete a profile
spectrescan profile delete "Old Profile"
```

**Profile Structure:**
Profiles store complete scan configurations including:
- Target and port specifications
- Scan types (TCP, SYN, UDP, Async)
- Performance settings (threads, timeout, rate limit)
- Feature flags (service detection, OS detection, banner grabbing)
- Timing templates and randomization options

**Example Use Case:**
```bash
# Create a profile for web server scanning
# (Profiles are automatically saved during scans or can be created manually)

# Later, load and use the profile
spectrescan profile load "Web Server Scan"
# Shows: ports [80, 443, 8080, 8443], TCP scan, service detection enabled

# Use profile settings for new scan
spectrescan 192.168.1.1 -p 80,443,8080,8443 --tcp --service-detection
```

#### Scan History

Track and review previous scans:

```bash
# List recent scans
spectrescan history list

# List with filters
spectrescan history list --limit 20 --target 192.168.1.1
spectrescan history list --scan-type tcp

# View scan details
spectrescan history show abc123def456

# Search history
spectrescan history search "example.com"
spectrescan history search "192.168"

# View statistics
spectrescan history stats

# Delete specific scan
spectrescan history delete abc123def456

# Clear all history
spectrescan history clear
```

**History Output Example:**
```
┌─────────────────────────────────── Scan History ───────────────────────────────────┐
│ ID           Target            Type  Ports  Open  Duration  Timestamp              │
├────────────────────────────────────────────────────────────────────────────────────┤
│ a1b2c3d4e5f6 192.168.1.1       tcp   1000   15    12.5s    2025-01-15 14:30       │
│ f6e5d4c3b2a1 scanme.nmap.org   syn   100    5     3.2s     2025-01-15 12:15       │
│ b2c3d4e5f6a1 10.0.0.0/24       tcp   65535  234   185.4s   2025-01-14 18:45       │
└────────────────────────────────────────────────────────────────────────────────────┘
```

**Statistics Example:**
```
┌─────────────────────────── Scan History Statistics ───────────────────────────────┐
│ Total Scans: 47                                                                    │
│ Total Ports Scanned: 1,245,890                                                     │
│ Total Open Ports Found: 3,452                                                      │
│ Total Scan Time: 2,847.32s                                                         │
│                                                                                     │
│ Scan Types:                                                                         │
│   • tcp: 35                                                                         │
│   • syn: 8                                                                          │
│   • udp: 4                                                                          │
│                                                                                     │
│ Most Scanned Target: 192.168.1.1                                                   │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

#### Scan Comparison

Compare two scans to identify changes over time:

```bash
# Compare two specific scans by ID
spectrescan compare abc123def456 def456ghi789

# Compare the two most recent scans for a target
spectrescan compare --target 192.168.1.1
```

**Comparison Output Example:**
```
======================================================================
SCAN COMPARISON REPORT
======================================================================

Scan 1 ID: abc123def456
Scan 1 Time: 2025-01-15T10:00:00
Scan 1 Open Ports: 15

Scan 2 ID: def456ghi789
Scan 2 Time: 2025-01-15T14:00:00
Scan 2 Open Ports: 17

Target: 192.168.1.1
Change in Open Ports: +2
Total Changes: 4

NEWLY OPENED PORTS:
----------------------------------------------------------------------
  8080/tcp - http-proxy
    Changed from: closed -> open
  3306/tcp - mysql
    Changed from: filtered -> open

NEWLY CLOSED PORTS:
----------------------------------------------------------------------
  21/tcp - ftp
    Changed from: open -> closed

SERVICE CHANGES:
----------------------------------------------------------------------
  80/tcp
    Service: http -> nginx

======================================================================
```

**Use Cases:**
- Monitor infrastructure changes over time
- Detect unauthorized service deployments
- Verify firewall rule changes
- Track service version updates
- Identify security posture drift

#### Complete Examples

**Single Network Scan:**
```bash
spectrescan 192.168.1.0/24 \
  --top-ports \
  --async \
  --threads 500 \
  --timeout 2 \
  --os-detection \
  --banner-grab \
  --randomize \
  --json scan_results.json \
  --html report.html
```

**Multi-Target Enterprise Scan:**
```bash
# Create targets file with all enterprise infrastructure
cat > enterprise_targets.txt << EOF
# Production Web Servers
192.168.10.0/24
10.0.1.1-50

# Database Cluster
192.168.20.10
192.168.20.11
192.168.20.12

# External Endpoints
api.example.com
www.example.com
mail.example.com
EOF

# Perform comprehensive scan
spectrescan --target-file enterprise_targets.txt \
  --top-ports \
  --async \
  --threads 1000 \
  --os-detection \
  --banner-grab \
  --json enterprise_scan.json \
  --html enterprise_report.html
```

### TUI Interface

Launch the TUI:

```bash
spectrescan --tui
```

Or with pre-filled target:

```bash
spectrescan 192.168.1.1 -p 1-1000 --tui
```

**TUI Features:**
- Real-time scan progress visualization
- Live results table with filtering
- Comprehensive logs panel
- Keyboard shortcuts (`s` = start, `x` = stop, `c` = clear, `q` = quit, `p` = profiles, `h` = history)
- Dark/light theme toggle (`d`)
- Statistics dashboard
- **Profile Management** - Press `p` to open profile selection screen
- **History Browser** - Press `h` to view scan history (coming soon)
- Profile loading with auto-configuration
- Multi-target support with file import

### GUI Interface

Launch the GUI:

```bash
spectrescan --gui
```

**GUI Features:**
- Intuitive point-and-click interface
- Target input with validation
- Port range selector
- Scan preset dropdown
- Real-time progress bar
- Results table with sorting
- Export buttons (JSON, CSV, HTML)
- Dark theme with BitSpectreLabs branding
- Error dialog handling
- **Profile Manager Dialog** - Save, load, delete, export, and import scan profiles
- **History Browser Dialog** - View, search, and filter scan history with statistics
- Multi-target file import with visual feedback
- Profile-based configuration loading

---

## <img src="https://cdn.simpleicons.org/radar/00C853" width="20" height="20" style="vertical-align: middle;"/> Scan Modes

### TCP Connect Scan

Full TCP three-way handshake. Most reliable but most detectable.

```bash
spectrescan 192.168.1.1 --tcp
```

### TCP SYN Scan (Stealth)

Half-open scan using SYN packets. Less detectable but requires privileges.

```bash
sudo spectrescan 192.168.1.1 --syn
```

Requires:
- Root/Administrator privileges
- Scapy library installed
- Raw socket support

### UDP Scan

Scan UDP ports with intelligent probes and heuristics.

```bash
spectrescan 192.168.1.1 --udp -p 53,123,161
```

**Note:** UDP scanning is slower and may produce false positives (open|filtered).

### Async High-Speed Scan

Ultra-fast concurrent scanning using Python's asyncio.

```bash
spectrescan 192.168.1.1 --async --threads 2000
```

---

## <img src="https://cdn.simpleicons.org/json/000000" width="20" height="20" style="vertical-align: middle;"/> Output Formats

### JSON Format

```json
{
  "scan_info": {
    "tool": "SpectreScan",
    "vendor": "BitSpectreLabs",
    "timestamp": "2025-11-25 14:30:00"
  },
  "summary": {
    "total_ports": 1000,
    "open_ports": 5,
    "scan_duration": "2m 15s"
  },
  "results": [
    {
      "host": "192.168.1.1",
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.2"
    }
  ]
}
```

### HTML Report

Professional HTML report with:
- BitSpectreLabs branding
- Summary statistics dashboard
- Interactive tables
- Host information section
- Modern responsive design
- Print-friendly layout

### PDF Report (Enhanced Reporting)

Generate professional PDF reports with charts:

```bash
spectrescan scan 192.168.1.1 --quick --pdf report.pdf
```

Features:
- Executive summary section
- Port status pie charts
- Service distribution graphs
- Host information tables
- Professional branding
- Print-ready format

**Requires:** `pip install reportlab`

### Executive Summary

Generate high-level security assessments:

```bash
spectrescan scan 192.168.1.0/24 --quick --exec-summary summary.txt
```

Includes:
- **Risk scoring** (0-100 with severity levels)
- **Critical findings** identification
- **Security recommendations**
- **Service distribution** analysis
- **Host information** summary

Risk Levels:
- 🔴 **CRITICAL** (75-100): Immediate action required
- 🟠 **HIGH** (50-74): Significant vulnerabilities
- 🟡 **MEDIUM** (25-49): Moderate concerns
- 🟢 **LOW** (0-24): Minimal risk

### Comparison Reports

Generate detailed scan comparison reports:

```bash
# Text format
spectrescan compare scan1_id scan2_id --output comparison.txt

# HTML format with styling
spectrescan compare --target 192.168.1.1 --format html --output diff.html

# JSON format for automation
spectrescan compare scan1_id scan2_id --format json --output changes.json
```

Comparison formats:
- **Text**: Terminal-friendly plain text
- **HTML**: Styled report with color-coded changes
- **JSON**: Machine-readable structured data

### ASCII Charts

View quick charts in the terminal:

```python
from spectrescan.reports import get_ascii_chart

# Port distribution
print(get_ascii_chart(results, 'port_distribution'))

# Service distribution
print(get_ascii_chart(results, 'service_distribution'))
```

Output example:
```
Top 5 Services:
──────────────────────────────────────────────────
http            │███████████████████████ 12
ssh             │██████████████ 8
https           │████████████ 6
mysql           │████████ 4
ftp             │█████ 3
──────────────────────────────────────────────────
```

---

### Custom Report Templates

Create custom report layouts using the advanced templating engine with Jinja2:

```bash
# Install Jinja2 for template support (included in requirements.txt)
pip install jinja2

# Create default template examples
spectrescan template init

# List all templates
spectrescan template list

# Use custom template in scan
spectrescan scan 192.168.1.1 --quick --custom-template my_report.html --output report.html
```

#### Template Management CLI

**List Templates:**
```bash
# List all templates
spectrescan template list

# List by category
spectrescan template list --category security

# List by format
spectrescan template list --format html
```

**Create Templates:**
```bash
# Create from file
spectrescan template create my_report.html --file template.html

# Create with metadata
spectrescan template create security_audit.md \
  --file template.md \
  --author "Your Name" \
  --description "Security audit report" \
  --category security \
  --tags scan,audit,security
```

**Validate Templates:**
```bash
# Check syntax and show variables
spectrescan template validate my_report.html
```

**Search Templates:**
```bash
# Search by name or description
spectrescan template search security

# Filter by tags
spectrescan template search --tags vulnerability,cve
```

**Import/Export:**
```bash
# Export template with metadata
spectrescan template export my_report.html --output template.zip

# Import template from marketplace
spectrescan template import downloaded_template.zip
```

#### Template Features

**1. Custom Jinja2 Filters:**

Built-in filters for common formatting needs:

```jinja2
<!-- Format bytes -->
{{ file_size|format_bytes }}  <!-- Output: "1.5 MB" -->

<!-- Format duration -->
{{ scan_time|format_duration }}  <!-- Output: "2m 30s" -->

<!-- Severity color -->
{{ vulnerability.severity|severity_color }}  <!-- Output: "#dc2626" -->

<!-- Port category -->
{{ port|port_category }}  <!-- Output: "well-known" -->
```

**2. Template Metadata:**

Every template includes structured metadata:

```json
{
  "name": "security_audit.html",
  "version": "1.0.0",
  "author": "Security Team",
  "description": "Comprehensive security audit report",
  "category": "security",
  "tags": ["audit", "compliance", "vulnerability"],
  "format": "html",
  "license": "MIT",
  "created_at": "2025-01-15T10:00:00Z"
}
```

**3. Company Branding:**

Add your company's branding to templates:

```python
from spectrescan.reports.templates import CompanyBranding

branding = CompanyBranding(
    company_name="Your Company",
    logo_path="/path/to/logo.png",
    colors={
        'primary': '#0066cc',
        'secondary': '#333333',
        'accent': '#ff6600'
    },
    footer_text="Confidential - Internal Use Only",
    contact_email="security@yourcompany.com",
    website="https://yourcompany.com"
)

# Use in template
context = {
    'branding': branding,
    'results': scan_results,
    # ... other variables
}
```

**4. Template Validation:**

Validate templates before use:

```python
from spectrescan.reports.templates import TemplateValidator

# Validate syntax
is_valid, error = TemplateValidator.validate_syntax(template_content)

# Extract variables
variables = TemplateValidator.extract_variables(template_content)

# Check required variables
all_present, missing = TemplateValidator.check_required_variables(
    template_content,
    required=['tool', 'vendor', 'results']
)
```

#### Template Context Variables

Standard variables available in all templates:

| Variable | Type | Description |
|----------|------|-------------|
| `tool` | str | "SpectreScan" |
| `vendor` | str | "BitSpectreLabs" |
| `timestamp` | str | Current timestamp |
| `results` | List[ScanResult] | All scan results |
| `open_ports` | List[ScanResult] | Open ports only |
| `closed_ports` | List[ScanResult] | Closed ports only |
| `filtered_ports` | List[ScanResult] | Filtered ports only |
| `summary` | Dict | Scan summary statistics |
| `host_info` | Dict[str, HostInfo] | Host information |
| `branding` | CompanyBranding | Company branding (optional) |

**Custom variables** can be passed via `custom_vars` parameter.

#### Example Templates

**Simple Text Report:**
```jinja2
# {{ tool }} Scan Report
Generated: {{ timestamp }}
by {{ vendor }}

## Summary
- Total Ports: {{ results|length }}
- Open Ports: {{ open_ports|length }}
- Closed Ports: {{ closed_ports|length }}

## Open Ports
{% for result in open_ports %}
- {{ result.port }}/{{ result.protocol }}: {{ result.service }}
  {% if result.banner %}Banner: {{ result.banner }}{% endif %}
{% endfor %}
```

**HTML Report with Branding:**
```jinja2
<!DOCTYPE html>
<html>
<head>
    <title>{{ branding.company_name }} - Security Scan Report</title>
    <style>
        :root {
            --primary: {{ branding.colors.primary }};
            --secondary: {{ branding.colors.secondary }};
        }
        /* ... styles ... */
    </style>
</head>
<body>
    <header>
        <img src="{{ branding.logo_path }}" alt="Logo">
        <h1>Security Scan Report</h1>
    </header>
    
    <section class="summary">
        <h2>Scan Summary</h2>
        <table>
            <tr><td>Target</td><td>{{ summary.target }}</td></tr>
            <tr><td>Duration</td><td>{{ summary.duration|format_duration }}</td></tr>
            <tr><td>Open Ports</td><td>{{ open_ports|length }}</td></tr>
        </table>
    </section>
    
    <section class="results">
        <h2>Open Ports</h2>
        {% for result in open_ports %}
        <div class="port">
            <span class="port-number">{{ result.port }}</span>
            <span class="service">{{ result.service }}</span>
            <span class="category">{{ result.port|port_category }}</span>
        </div>
        {% endfor %}
    </section>
    
    <footer>
        <p>{{ branding.footer_text }}</p>
        <p>Contact: {{ branding.contact_email }}</p>
    </footer>
</body>
</html>
```

**Markdown Report:**
```jinja2
# {{ branding.company_name if branding else tool }} Scan Report

**Generated:** {{ timestamp }}  
**Target:** {{ summary.target }}  
**Duration:** {{ summary.duration|format_duration }}

---

## 📊 Executive Summary

- **Total Ports Scanned:** {{ results|length }}
- **Open Ports:** {{ open_ports|length }}
- **Closed Ports:** {{ closed_ports|length }}
- **Filtered Ports:** {{ filtered_ports|length }}

## 🔓 Open Ports

| Port | Protocol | Service | Category | Banner |
|------|----------|---------|----------|--------|
{% for result in open_ports -%}
| {{ result.port }} | {{ result.protocol }} | {{ result.service or 'unknown' }} | {{ result.port|port_category }} | {{ result.banner or '-' }} |
{% endfor %}

---

*Report generated by {{ tool }} - {{ vendor }}*
{% if branding %}
*{{ branding.footer_text }}*
{% endif %}
```

#### Template Categories

- **general** - Basic scan reports
- **security** - Security audit reports
- **compliance** - Compliance and regulatory reports
- **executive** - Executive summaries
- **technical** - Detailed technical reports
- **comparison** - Scan comparison reports

#### Python API

```python
from spectrescan.reports.templates import TemplateManager, TemplateMetadata, CompanyBranding

# Initialize manager
manager = TemplateManager()

# Create template
template_content = """
# Scan Report for {{ target }}
Open Ports: {{ open_ports|length }}
"""
template_path = manager.create_template("my_report.md", template_content)

# Set metadata
metadata = TemplateMetadata(
    name="my_report.md",
    version="1.0.0",
    author="Your Name",
    description="Custom scan report",
    category="general",
    tags=["scan", "report"],
    format="markdown"
)
manager.set_metadata("my_report.md", metadata)

# Render template
context = {
    'target': '192.168.1.1',
    'results': scan_results,
    'open_ports': [r for r in scan_results if r.state == 'open'],
    'branding': CompanyBranding("My Company")
}
rendered = manager.render_template("my_report.md", context)

# Add custom filter
def uppercase_filter(value):
    return value.upper()

manager.add_custom_filter('uppercase', uppercase_filter)

# Export template
manager.export_template("my_report.md", Path("template.zip"))

# Import template
manager.import_template(Path("downloaded_template.zip"))
```

**Requirements:** `pip install jinja2`

---

### Interactive HTML Reports

Generate interactive HTML reports with advanced features:

```bash
spectrescan scan 192.168.1.0/24 --quick --interactive-html report.html
```

**Features:**
- 🔍 **Live Search**: Real-time filtering across all fields
- 📊 **Sortable Columns**: Click headers to sort by any column
- 🎯 **State Filtering**: Filter by open/closed/filtered ports
- 🌙 **Dark Mode**: Toggle between light and dark themes
- 📋 **Copy to Clipboard**: Quick copy of host:port combinations
- 📱 **Responsive Design**: Works on desktop and mobile
- ⚡ **No Server Required**: Pure client-side JavaScript

**Interactive Features:**
- Search by host, port, service, or banner content
- Expandable port details with banner information
- Visual state badges (color-coded)
- Statistics dashboard
- Persistent theme preference (localStorage)

---

## 💡 Examples

### Example 1: Quick Network Reconnaissance

```bash
spectrescan 192.168.1.0/24 --quick --json network_scan.json
```

### Example 2: Comprehensive Service Analysis

```bash
spectrescan scanme.nmap.org \
  --top-ports \
  --service-detection \
  --banner-grab \
  --os-detection \
  --html detailed_report.html
```

### Example 3: Stealth Penetration Testing

```bash
sudo spectrescan 10.0.0.50 \
  --stealth \
  --randomize \
  --rate-limit 20 \
  -p 1-10000
```

### Example 4: High-Speed Data Center Scan

```bash
spectrescan 172.16.0.0/16 \
  --async \
  --threads 2000 \
  --timeout 0.5 \
  --quick \
  --csv dc_scan.csv
```

### Example 5: Web Server Discovery

```bash
spectrescan 192.168.0.0/22 \
  -p 80,443,8000,8080,8443 \
  --banner-grab \
  --threads 500
```

---

## <img src="https://cdn.simpleicons.org/lua/2C2D72" width="20" height="20" style="vertical-align: middle;"/> NSE Script Scanning

SpectreScan supports Nmap Script Engine (NSE) compatibility, allowing you to run Lua-based scripts for advanced service detection and vulnerability scanning.

### Quick Start

```bash
# Run default scripts on open ports
spectrescan scan 192.168.1.1 -sC

# Run specific script
spectrescan script run http-title -t 192.168.1.1 -p 80

# Run scripts by category
spectrescan scan 192.168.1.1 --script discovery

# Run multiple scripts with wildcards
spectrescan scan 192.168.1.1 --script "http-*,ssl-*"
```

### Script Management

```bash
# List all available scripts
spectrescan script list

# Show script categories
spectrescan script categories

# Get detailed script information
spectrescan script info http-title

# Run script with arguments
spectrescan script run http-title -t example.com -p 80 --script-args "path=/admin"
```

### Bundled Scripts

| Script | Description | Category |
|--------|-------------|----------|
| `http-title` | Extract HTTP page titles | discovery, safe |
| `ssl-cert` | SSL certificate information | discovery, safe |
| `ssh-hostkey` | SSH host key fingerprints | discovery, safe |
| `ftp-anon` | Check for anonymous FTP login | auth, safe |
| `smb-os-discovery` | SMB operating system discovery | discovery, safe |
| `http-headers` | HTTP response headers | discovery, safe |
| `http-methods` | HTTP allowed methods | discovery, safe |
| `mysql-info` | MySQL server information | discovery, safe |
| `redis-info` | Redis server information | discovery, safe |
| `smtp-commands` | SMTP supported commands | discovery, safe |

### Script Categories

- **auth** - Authentication testing
- **brute** - Brute-force password attacks
- **discovery** - Host and service discovery
- **exploit** - Exploitation scripts
- **vuln** - Vulnerability detection
- **safe** - Non-intrusive, safe scripts
- **default** - Scripts run with `-sC`

**Requirements:** Install Lupa for Lua support: `pip install lupa`

---

## <img src="https://cdn.simpleicons.org/sqlite/003B57" width="20" height="20" style="vertical-align: middle;"/> Custom Vulnerability Database

Manage your own local vulnerability database with custom definitions, severity scores, and matching rules.

### Quick Start

```bash
# Initialize the database
spectrescan vulndb init

# Add a vulnerability
spectrescan vulndb add \
  --id "CVE-2023-1234" \
  --title "Example Vulnerability" \
  --severity "High" \
  --cvss 8.5 \
  --product "Apache.*" \
  --version "< 2.4.50"

# Search for vulnerabilities
spectrescan vulndb search "Apache"

# List all vulnerabilities
spectrescan vulndb list
```

### Features

- **Local SQLite Storage** - Fast, self-contained database
- **Custom Definitions** - Define your own vulnerabilities
- **Regex Matching** - Match products using regular expressions
- **Version Ranges** - Support for complex version constraints (`<`, `<=`, `>`, `>=`, `==`, `!=`)
- **Import/Export** - JSON and CSV support for bulk operations
- **CVSS Scoring** - Track severity with standard CVSS scores

### Import/Export

```bash
# Import from JSON
spectrescan vulndb import vulns.json

# Export to JSON
spectrescan vulndb export backup.json
```

---

## <img src="https://cdn.simpleicons.org/kubernetes/326CE5" width="20" height="20" style="vertical-align: middle;"/> Distributed Scanning

Scale your scans across multiple machines with the distributed scanning feature.

### Architecture

```
┌─────────────────┐
│  Master Node    │
│  (Coordinator)  │
└────────┬────────┘
         │
    ┌────┴────┬────────┬────────┐
    ▼         ▼        ▼        ▼
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│Worker1│ │Worker2│ │Worker3│ │Worker4│
└───────┘ └───────┘ └───────┘ └───────┘
```

### Quick Start

**Start Master Node:**
```bash
# Initialize cluster with 4 workers
spectrescan cluster init --workers 4

# Check cluster status
spectrescan cluster status
```

**Start Worker Nodes:**
```bash
# On each worker machine
spectrescan cluster worker --master 192.168.1.100:5000
```

**Run Distributed Scan:**
```bash
# Scan large network across all workers
spectrescan cluster scan 10.0.0.0/8 --workers all

# Scan with specific workers
spectrescan cluster scan 192.168.0.0/16 --workers worker1,worker2
```

### CLI Commands

```bash
# Cluster management
spectrescan cluster init              # Initialize master node
spectrescan cluster status            # Show cluster status
spectrescan cluster workers           # List registered workers
spectrescan cluster shutdown          # Shutdown cluster

# Worker management
spectrescan cluster worker            # Start worker node
spectrescan cluster worker --id node1 # Start with custom ID

# Distributed scanning
spectrescan cluster scan <target>     # Run distributed scan
spectrescan cluster results <scan-id> # Get aggregated results
```

### Features

- **Automatic Load Balancing** - Tasks distributed evenly across workers
- **Health Monitoring** - Continuous heartbeat checks
- **Automatic Failover** - Failed tasks reassigned to healthy workers
- **Result Aggregation** - Results merged from all workers
- **Secure Communication** - TLS encryption (optional)
- **Message Queue** - Redis/RabbitMQ support for reliability

---

## <img src="https://cdn.simpleicons.org/googlechrome/4285F4" width="20" height="20" style="vertical-align: middle;"/> Web Dashboard

Access SpectreScan through a modern web interface with real-time updates.

### Quick Start

```bash
# Start web dashboard on default port (8080)
spectrescan web

# Custom port
spectrescan web --port 9000

# Don't auto-open browser
spectrescan web --no-browser

# Enable debug mode
spectrescan web --debug
```

Then open your browser to `http://localhost:8080`

### Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin | Super Admin |

**Important:** Change the default password after first login!

### Features

**Dashboard:**
- Real-time scan progress with WebSocket updates
- Live results streaming
- Statistics overview (open ports, services, scan history)
- Recent scan activity feed

**Scan Management:**
- Start new scans from the browser
- Configure scan parameters (ports, timing, detection options)
- Stop/pause running scans
- View detailed scan results

**History Browser:**
- Search and filter past scans
- Compare scans side-by-side
- Export results in multiple formats
- Delete old scan records

**Profile Management:**
- Create and save scan profiles
- Load profiles for quick scanning
- Share profiles across team

### Role-Based Access Control (RBAC)

| Role | Permissions |
|------|-------------|
| **Viewer** | View scans and results only |
| **Operator** | Execute scans, manage own profiles |
| **Analyst** | Full scan access, export data |
| **Admin** | User management, system settings |
| **Super Admin** | Full access, security settings |

### API Endpoints

The web dashboard exposes a REST API:

```bash
# Authentication
POST /api/auth/login          # Login with credentials
POST /api/auth/logout         # Logout current session

# Scans
GET  /api/scans               # List all scans
POST /api/scans               # Start new scan
GET  /api/scans/{id}          # Get scan details
DELETE /api/scans/{id}        # Delete scan

# Profiles
GET  /api/profiles            # List profiles
POST /api/profiles            # Create profile

# WebSocket
WS   /ws                      # Real-time updates
```

### Screenshots

**Dashboard View:**
- Dark theme with BitSpectreLabs branding
- Real-time scan progress indicator
- Statistics cards with key metrics
- Recent activity feed

**Scan Results:**
- Interactive results table
- Sortable columns
- State filtering (open/closed/filtered)
- Expandable port details

---

## <img src="https://cdn.simpleicons.org/clockify/03A9F4" width="20" height="20" style="vertical-align: middle;"/> Scan Scheduling and Automation

Automate your scans with the powerful scheduling engine. Schedule one-time, recurring, or conditional scans with pre/post hooks.

### Quick Start

```bash
# List all schedules
spectrescan schedule list

# Add a daily scan at 2 AM
spectrescan schedule add --name "Nightly Scan" --target 192.168.1.0/24 --type daily --at "02:00"

# Add a cron-based scan (every Monday at 9 AM)
spectrescan schedule add --name "Weekly Audit" --target 10.0.0.1 --type cron --cron "0 9 * * 1"

# Add an interval scan (every 4 hours)
spectrescan schedule add --name "Frequent Check" --target example.com --type interval --interval "4h"

# Start the scheduler daemon
spectrescan schedule run --daemon
```

### Schedule Types

| Type | Description | Example |
|------|-------------|---------|
| `once` | One-time scan at specific datetime | `--type once --at "2025-01-20 14:00"` |
| `cron` | Full cron expression support | `--type cron --cron "0 2 * * *"` |
| `interval` | Repeat every N seconds/minutes/hours | `--type interval --interval "30m"` |
| `daily` | Run daily at specific time | `--type daily --at "09:00"` |
| `weekly` | Run on specific days of week | `--type weekly --days "mon,wed,fri" --at "08:00"` |
| `monthly` | Run on specific day of month | `--type monthly --day 1 --at "00:00"` |

### Cron Expression Syntax

```
 ┌───────────── minute (0-59)
 │ ┌───────────── hour (0-23)
 │ │ ┌───────────── day of month (1-31)
 │ │ │ ┌───────────── month (1-12)
 │ │ │ │ ┌───────────── day of week (0-6, Monday=0)
 │ │ │ │ │
 * * * * *
```

**Supported Patterns:**
- `*` - Any value
- `5` - Specific value
- `1-5` - Range of values
- `1,3,5` - List of values
- `*/15` - Step values (every 15)
- `1-10/2` - Range with step (1,3,5,7,9)

**Shorthand Expressions:**
- `@hourly` - Every hour (0 * * * *)
- `@daily` - Every day at midnight (0 0 * * *)
- `@weekly` - Every Monday at midnight (0 0 * * 0)
- `@monthly` - First day of month at midnight (0 0 1 * *)

### CLI Commands

```bash
# Schedule Management
spectrescan schedule list                    # List all schedules
spectrescan schedule add [options]           # Create new schedule
spectrescan schedule remove <id>             # Delete schedule
spectrescan schedule pause <id>              # Pause schedule
spectrescan schedule resume <id>             # Resume schedule

# Execution
spectrescan schedule run <id>                # Run schedule now (manual trigger)
spectrescan schedule run --daemon            # Start scheduler daemon

# Status & History
spectrescan schedule status <id>             # View schedule status
spectrescan schedule history <id>            # View execution history
```

### Schedule Options

```bash
spectrescan schedule add \
  --name "Production Audit" \           # Schedule name (required)
  --target 192.168.1.0/24 \             # Target to scan (required)
  --type cron \                         # Schedule type
  --cron "0 2 * * *" \                  # Cron expression
  --ports "1-1000" \                    # Port range
  --scan-type tcp \                     # Scan type (tcp/syn/udp/async)
  --profile "Quick Scan" \              # Use saved profile
  --pre-hook "echo Starting scan" \     # Pre-scan hook command
  --post-hook "notify-send Done" \      # Post-scan hook command
  --enabled                             # Enable immediately
```

### Pre/Post Scan Hooks

Execute commands or scripts before and after scans:

```bash
# Shell command hooks
spectrescan schedule add --name "Audit" --target 10.0.0.1 \
  --type daily --at "03:00" \
  --pre-hook "echo 'Scan starting' >> /var/log/scans.log" \
  --post-hook "/scripts/process_results.sh"

# Multiple hooks (in Python API)
from spectrescan.core.scheduler import ScanScheduler, ScanHook, HookType

scheduler = ScanScheduler()
schedule = scheduler.create_schedule(
    name="Audit",
    target="192.168.1.1",
    schedule_type="daily",
    time_spec={"at": "03:00"},
    hooks=[
        ScanHook(type=HookType.PRE_SCAN, command="backup_config.sh"),
        ScanHook(type=HookType.POST_SCAN, command="send_report.py"),
        ScanHook(type=HookType.ON_ERROR, command="alert_team.sh"),
        ScanHook(type=HookType.ON_CHANGE, command="notify_changes.py"),
    ]
)
```

### Conditional Execution

Run scans only when conditions are met:

```python
from spectrescan.core.scheduler import ExecutionCondition, ConditionType

# Only scan if host responds to ping
condition = ExecutionCondition(
    type=ConditionType.HOST_UP,
    parameters={"timeout": 5}
)

# Only during business hours
condition = ExecutionCondition(
    type=ConditionType.TIME_WINDOW,
    parameters={"start": "09:00", "end": "17:00"}
)

# Only if previous scan succeeded
condition = ExecutionCondition(
    type=ConditionType.PREVIOUS_SUCCESS
)
```

### Scan Chaining

Create automated workflows by chaining scans:

```python
from spectrescan.core.scheduler import ScanScheduler

scheduler = ScanScheduler()

# Create parent scan
parent = scheduler.create_schedule(
    name="Initial Discovery",
    target="192.168.1.0/24",
    schedule_type="daily",
    time_spec={"at": "01:00"}
)

# Chain child scan (runs after parent completes)
child = scheduler.create_schedule(
    name="Deep Scan",
    target="192.168.1.1",  # Specific host found
    schedule_type="once",
    time_spec={},
    chain_from=parent.id
)
```

### Background Daemon

Run the scheduler as a persistent background service:

```bash
# Start daemon (foreground)
spectrescan schedule run --daemon

# Run as background process
nohup spectrescan schedule run --daemon > scheduler.log 2>&1 &

# Or use systemd (Linux)
# Create /etc/systemd/system/spectrescan-scheduler.service
```

**Systemd Service Example:**
```ini
[Unit]
Description=SpectreScan Scheduler Daemon
After=network.target

[Service]
Type=simple
User=scanner
ExecStart=/usr/local/bin/spectrescan schedule run --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## <img src="https://cdn.simpleicons.org/hackaday/1A1A1A" width="20" height="20" style="vertical-align: middle;"/> IDS/IPS Evasion

Evade intrusion detection systems with advanced evasion techniques. SpectreScan provides multiple methods to avoid detection during reconnaissance.

### Quick Start

```bash
# Use stealth evasion profile
spectrescan scan 192.168.1.1 --evasion stealth

# Use paranoid profile (maximum stealth)
spectrescan scan 192.168.1.1 --evasion paranoid

# Custom decoy scanning with 5 random decoys
spectrescan scan 192.168.1.1 -D RND:5

# Specific decoy IPs
spectrescan scan 192.168.1.1 -D 10.0.0.1,10.0.0.2,ME,10.0.0.3

# Fragment packets to evade signature detection
spectrescan scan 192.168.1.1 -f --mtu 8

# Manipulate source port (use DNS port)
spectrescan scan 192.168.1.1 -g 53

# Use common source ports (random from 53, 80, 443)
spectrescan scan 192.168.1.1 --common-source-port

# TTL manipulation
spectrescan scan 192.168.1.1 --ttl 64 --ttl-style random

# Slow scan to avoid rate-based detection
spectrescan scan 192.168.1.1 --scan-delay 5.0 --max-parallelism 1
```

### Evasion Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `none` | No evasion techniques | Normal scanning |
| `stealth` | Balanced stealth and speed | General IDS evasion |
| `paranoid` | Maximum stealth, very slow | High-security networks |
| `aggressive` | Fast with basic evasion | Quick reconnaissance |
| `custom` | User-configured options | Fine-tuned evasion |

### Evasion Techniques

#### Decoy Scanning (`-D`)

Send packets appearing to come from multiple source IPs:

```bash
# 5 random decoys (ME = your real IP position)
spectrescan scan 192.168.1.1 -D RND:5

# Specific decoys with your position
spectrescan scan 192.168.1.1 -D 10.0.0.1,ME,10.0.0.2

# Control number of random decoys
spectrescan scan 192.168.1.1 --decoy-count 10
```

#### Packet Fragmentation (`-f`)

Fragment IP packets to evade signature-based detection:

```bash
# Enable fragmentation
spectrescan scan 192.168.1.1 -f

# Custom MTU (fragment size)
spectrescan scan 192.168.1.1 -f --mtu 8

# Requires scapy for raw packet crafting
```

#### Source Port Manipulation (`-g`)

Use specific source ports that may bypass firewall rules:

```bash
# Use DNS port (53) as source
spectrescan scan 192.168.1.1 -g 53

# Use HTTP port (80) as source
spectrescan scan 192.168.1.1 -g 80

# Random source port
spectrescan scan 192.168.1.1 --random-source-port

# Random from common ports (53, 80, 443, 20, 21, 25)
spectrescan scan 192.168.1.1 --common-source-port
```

#### TTL Manipulation (`--ttl`)

Control Time-To-Live values:

```bash
# Fixed TTL
spectrescan scan 192.168.1.1 --ttl 64

# TTL styles
spectrescan scan 192.168.1.1 --ttl-style fixed      # Use exact TTL
spectrescan scan 192.168.1.1 --ttl-style random     # Random 32-128
spectrescan scan 192.168.1.1 --ttl-style incremental # Increment each packet
spectrescan scan 192.168.1.1 --ttl-style decremental # Decrement each packet
spectrescan scan 192.168.1.1 --ttl-style os_mimic   # Mimic OS defaults
```

#### Bad Checksums (`--badsum`)

Send packets with intentionally bad checksums:

```bash
# IDS may ignore packets with bad checksums
spectrescan scan 192.168.1.1 --badsum
```

#### Idle/Zombie Scanning (`-sI`)

Use an idle host to scan through (stealth scanning):

```bash
# Use zombie host for scanning
spectrescan scan 192.168.1.1 -sI 10.0.0.100

# Specify zombie port (default: 80)
spectrescan scan 192.168.1.1 -sI 10.0.0.100 --zombie-port 443
```

#### Timing-Based Evasion

Slow scans to avoid rate-based detection:

```bash
# Delay between packets (seconds)
spectrescan scan 192.168.1.1 --scan-delay 5.0

# Limit parallel connections
spectrescan scan 192.168.1.1 --max-parallelism 1

# Random delay jitter (0.5-1.5x delay)
spectrescan scan 192.168.1.1 --scan-delay 2.0
```

#### Host Randomization

Randomize the order of target hosts:

```bash
spectrescan scan 192.168.1.0/24 --randomize-hosts
```

### CLI Options Summary

| Option | Description |
|--------|-------------|
| `-e/--evasion` | Evasion profile (none/stealth/paranoid/aggressive) |
| `-D/--decoys` | Decoy IPs (comma-separated, RND:N for random) |
| `--decoy-count` | Number of random decoys |
| `-g/--source-port` | Specific source port |
| `--random-source-port` | Use random source port |
| `--common-source-port` | Use common ports (53,80,443) |
| `--ttl` | TTL value (1-255) |
| `--ttl-style` | TTL style (fixed/random/incremental/decremental/os_mimic) |
| `-f/--fragment` | Enable packet fragmentation |
| `--mtu` | Fragment MTU size |
| `--badsum` | Send bad checksums |
| `--randomize-hosts` | Randomize host scan order |
| `--scan-delay` | Delay between probes (seconds) |
| `--max-parallelism` | Max concurrent connections |
| `-sI/--idle-scan` | Zombie host for idle scan |
| `--zombie-port` | Zombie host port |
| `--data-length` | Append random data to packets |

### Python API

```python
from spectrescan.core.evasion import (
    EvasionManager,
    EvasionConfig,
    EvasionProfile,
    DecoyConfig,
    FragmentConfig,
    TimingConfig,
    TimingLevel
)

# Create evasion configuration
config = EvasionConfig(
    profile=EvasionProfile.STEALTH,
    decoys=DecoyConfig(
        enabled=True,
        decoy_ips=["10.0.0.1", "10.0.0.2"],
        random_count=3,
        include_real_ip=True
    ),
    fragmentation=FragmentConfig(
        enabled=True,
        mtu=8
    ),
    timing=TimingConfig(
        level=TimingLevel.SNEAKY,
        scan_delay=2.0,
        max_parallelism=5
    ),
    source_port=53,
    ttl=64,
    randomize_hosts=True
)

# Create evasion manager
evasion = EvasionManager(config)

# Use with scanner
from spectrescan.core.scanner import PortScanner
scanner = PortScanner(evasion=evasion)
results = scanner.scan("192.168.1.1")
```

### Requirements

- **Scapy** (optional): Required for advanced packet crafting (fragmentation, decoys, TTL manipulation)
- **Root/Admin**: Some techniques require elevated privileges
- Without scapy: Basic timing and ordering evasion still available

---

## <img src="https://cdn.simpleicons.org/git/F05032" width="20" height="20" style="vertical-align: middle;"/> Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/BitSpectreLabs/SpectreScan.git
cd SpectreScan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dev dependencies
pip install -r requirements.txt
pip install -e .[dev]
```

### Code Style

```bash
# Format code
black spectrescan/

# Sort imports
isort spectrescan/

# Lint code
flake8 spectrescan/

# Type checking
mypy spectrescan/
```

### Project Structure Best Practices

- **Type Hints**: All functions use type hints
- **Docstrings**: Google-style docstrings everywhere
- **Modularity**: Clean separation of concerns
- **Error Handling**: Comprehensive exception handling
- **Logging**: Structured logging throughout
- **Testing**: Unit tests for all modules

---

## <img src="https://cdn.simpleicons.org/pytest/0A9EDC" width="20" height="20" style="vertical-align: middle;"/> Testing

### Run Unit Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=spectrescan --cov-report=html

# Run specific test file
pytest spectrescan/tests/test_scanner.py

# Run with verbose output
pytest -v
```

### Test Coverage

```bash
# Generate coverage report
pytest --cov=spectrescan --cov-report=term-missing
```

---

## <img src="https://cdn.simpleicons.org/firefoxbrowser/FF7139" width="20" height="20" style="vertical-align: middle;"/> Troubleshooting

### SYN Scan Not Working

SYN scanning requires:
1. Scapy library: `pip install scapy`
2. Administrator/root privileges: `sudo spectrescan ...` (Linux/macOS) or run terminal as Administrator (Windows)
3. Raw socket support

### Permission Denied Errors

For certain scan types (SYN, OS detection), run with elevated privileges:
- **Linux/macOS**: `sudo spectrescan ...`
- **Windows**: Run terminal as Administrator

### Import Errors

If you get import errors, ensure SpectreScan is installed:
```bash
pip install -e .
```

### Module Not Found

Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### "No module named 'typer'" Error

This occurs when packages are installed to your user directory instead of the virtual environment. Solutions:

**Option 1: Use virtual environment (recommended)**
```bash
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # Windows PowerShell
# source .venv/bin/activate    # Linux/macOS

# Install dependencies in virtual environment
pip install -r requirements.txt
pip install -e .

# Run spectrescan
spectrescan --help
```

**Option 2: Install directly to virtual environment**
```bash
# Use virtual environment's Python directly
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\spectrescan.exe --help
```

**Option 3: Fix PATH issues**
```bash
# Ensure virtual environment is activated
# Check with:
where python     # Windows
which python     # Linux/macOS

# Should point to .venv directory
```

---

## <img src="https://cdn.simpleicons.org/github/181717" width="20" height="20" style="vertical-align: middle;"/> Contributing

We welcome contributions from the community!

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Guidelines

- Follow PEP 8 style guide
- Add unit tests for new features
- Update documentation
- Ensure all tests pass
- Add type hints to all functions

---

## <img src="https://cdn.simpleicons.org/opensourceinitiative/3DA639" width="20" height="20" style="vertical-align: middle;"/> License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2025 BitSpectreLabs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## <img src="https://cdn.simpleicons.org/letsencrypt/003A70" width="20" height="20" style="vertical-align: middle;"/> Legal & Ethical Use

**IMPORTANT:** This tool is designed for:

- **Authorized security testing**
- **Network administration**
- **Educational purposes**
- **Penetration testing with permission**

**DO NOT:**
- Scan networks without authorization
- Use for malicious purposes
- Violate any laws or regulations
- Attack systems you don't own

**You are responsible for your actions.** Always obtain proper authorization before scanning any network or system you do not own.

---

## <img src="https://cdn.simpleicons.org/github/181717" width="20" height="20" style="vertical-align: middle;"/> Acknowledgments

Built with <img src="https://cdn.simpleicons.org/github/E44C65" width="14" height="14" style="vertical-align: middle;"/> by **BitSpectreLabs**

Special thanks to:
- The Python community
- Typer and Textual framework developers
- Open source security tools community
- All contributors and testers

---

**SpectreScan** - *Professional Port Scanning for the Modern Age*

© 2025 BitSpectreLabs | Open Source Security Tools
