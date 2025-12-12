# SpectreScan Agent Architecture

**Internal Agent System Documentation**

by BitSpectreLabs

---

## 📋 Table of Contents

- [Overview](#overview)
- [Agent Architecture](#agent-architecture)
- [Core Agents](#core-agents)
- [Data Flow](#data-flow)
- [Agent Communication](#agent-communication)
- [API Reference](#api-reference)

---

## Overview

SpectreScan employs an **agent-based architecture** where specialized agents handle distinct responsibilities in the scanning pipeline. This modular design ensures:

- **Separation of concerns**
- **Scalability**
- **Maintainability**
- **Testability**
- **Extensibility**

Each agent operates independently but communicates through well-defined interfaces, allowing for parallel execution and efficient resource utilization.

---

## Agent Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SpectreScan Agent System                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                            │
│  │ Interface Agent │ ◄──── User Input (CLI/TUI/GUI)             │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ ScanEngine      │ ◄──── Orchestrates scanning workflow       │
│  │ Agent           │                                            │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ├─────────┬──────────┬─────────────┬─────────────┐    │
│           ▼         ▼          ▼             ▼             ▼    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │HostDisc  │ │TCPScan   │ │SYNScan   │ │UDPScan   │ │AsyncScan││
│  │Agent     │ │Agent     │ │Agent     │ │Agent     │ │Agent    ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘ │
│       │            │            │            │            │     │
│       └────────────┴────────────┴────────────┴────────────┘     │
│                                 │                               │
│                                 ▼                               │
│                    ┌─────────────────────┐                      │
│                    │ Detection Agents    │                      │
│                    ├─────────────────────┤                      │
│           ┌────────┤ BannerGrab Agent    │                      │
│           │        │ ServiceDetect Agent │                      │
│           │        │ OSDetect Agent      │                      │
│           │        └──────────┬──────────┘                      │
│           │                   │                                 │
│           ▼                   ▼                                 │
│  ┌─────────────────┐ ┌─────────────────┐                        │
│  │ ReportGenerator │ │ OutputFormatter │                        │
│  │ Agent           │ │ Agent           │                        │
│  └─────────────────┘ └─────────────────┘                        │
│                                                                 |
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Agents

### 1. ScanEngine Agent

**Responsibility:** Main orchestrator for all scanning operations

**Input:**
- Target specification (IP, CIDR, hostname)
- Port list
- Scan configuration
- Callback functions

**Output:**
- List of ScanResult objects
- Scan summary statistics
- Host information

**API:**

```python
class PortScanner:
    def __init__(self, config: ScanConfig)
    def scan(
        self, 
        target: str, 
        ports: Optional[List[int]], 
        callback: Optional[Callable]
    ) -> List[ScanResult]
    def get_open_ports(self, host: Optional[str]) -> List[ScanResult]
    def get_scan_summary(self) -> dict
```

**Data Flow:**

```
User Request
    │
    ├─► Parse Target
    ├─► Parse Ports
    ├─► Select Scan Method
    │
    ├─► Execute Scans (parallel)
    │   ├─► TCP Scan
    │   ├─► SYN Scan
    │   └─► UDP Scan
    │
    ├─► Collect Results
    │
    ├─► Run Detection (if enabled)
    │   ├─► Banner Grabbing
    │   ├─► Service Detection
    │   └─► OS Detection
    │
    └─► Return Results
```

---

### 2. HostDiscovery Agent

**Responsibility:** Identify live hosts on network before port scanning

**Input:**
- Target specification
- Discovery method (ping/tcp/arp)
- Timeout settings
- Thread count

**Output:**
- List of HostInfo objects
- Response times
- TTL values
- Resolved hostnames

**API:**

```python
class HostDiscovery:
    def __init__(self, timeout: float, threads: int)
    def discover_hosts(
        self, 
        target: str, 
        method: str, 
        callback: Optional[Callable]
    ) -> List[HostInfo]
    def check_single_host(self, ip: str, method: str) -> Optional[HostInfo]
```

**Discovery Methods:**

1. **ICMP Ping Sweep**
   - Sends ICMP echo requests
   - Fastest method
   - May be blocked by firewalls

2. **TCP Ping**
   - Connects to common ports
   - More reliable than ICMP
   - Slower but more stealthy

3. **ARP Sweep** (planned)
   - Layer 2 discovery
   - Most reliable on local network
   - Requires raw socket access

---

### 3. TCPScan Agent

**Responsibility:** Perform TCP connect scans

**Input:**
- Target host
- Port list
- Timeout
- Thread count

**Output:**
- ScanResult for each port (open/closed/filtered)

**API:**

```python
class PortScanner:
    def _tcp_scan(
        self, 
        host: str, 
        ports: List[int], 
        callback: Optional[Callable]
    ) -> List[ScanResult]
    def _tcp_connect(self, host: str, port: int) -> ScanResult
```

**Process:**

```
For each port:
    1. Create TCP socket
    2. Set timeout
    3. Attempt connection
    4. Check result
       - 0 = Open
       - Other = Closed/Filtered
    5. Close socket
    6. Return ScanResult
```

---

### 4. SYNScan Agent

**Responsibility:** Perform TCP SYN (half-open) scans

**Input:**
- Target host
- Port list
- Timeout

**Output:**
- ScanResult for each port

**API:**

```python
class SynScanner:
    def __init__(self, timeout: float, use_scapy: bool)
    def scan_port(self, host: str, port: int) -> ScanResult
    def scan_ports(
        self, 
        host: str, 
        ports: List[int], 
        callback: Optional[Callable]
    ) -> List[ScanResult]
```

**Process:**

```
For each port:
    1. Send SYN packet
    2. Wait for response
    3. Analyze response:
       - SYN-ACK (0x12) = Open
       - RST-ACK (0x14) = Closed
       - No response = Filtered
       - ICMP unreachable = Filtered
    4. If open, send RST to close
    5. Return ScanResult
```

**Requirements:**
- Scapy library
- Root/Administrator privileges
- Raw socket support

---

### 5. UDPScan Agent

**Responsibility:** Perform UDP port scans

**Input:**
- Target host
- Port list
- Timeout

**Output:**
- ScanResult for each port (open/closed/open|filtered)

**API:**

```python
class UdpScanner:
    def __init__(self, timeout: float)
    def scan_port(self, host: str, port: int) -> ScanResult
    def scan_ports(
        self, 
        host: str, 
        ports: List[int], 
        callback: Optional[Callable]
    ) -> List[ScanResult]
```

**Process:**

```
For each port:
    1. Create UDP socket
    2. Send service-specific probe
    3. Wait for response:
       - Response received = Open
       - ICMP port unreachable = Closed
       - No response = Open|Filtered
    4. Return ScanResult
```

**Challenges:**
- UDP is connectionless
- Many false positives
- Slower than TCP scanning
- Requires service-specific probes

---

### 6. AsyncScan Agent

**Responsibility:** High-speed concurrent TCP scanning using asyncio

**Input:**
- Target host
- Port list
- Timeout
- Max concurrent connections
- Optional rate limit

**Output:**
- ScanResult for each port

**API:**

```python
class AsyncScanner:
    def __init__(
        self, 
        timeout: float, 
        max_concurrent: int, 
        rate_limit: Optional[int]
    )
    async def scan_port(self, host: str, port: int) -> ScanResult
    async def scan_ports(
        self, 
        host: str, 
        ports: List[int], 
        callback: Optional[Callable]
    ) -> List[ScanResult]
```

**Advantages:**
- Extremely fast (1000+ concurrent connections)
- Efficient resource usage
- Non-blocking I/O
- Ideal for large port ranges

---

### 7. BannerGrab Agent

**Responsibility:** Capture service banners for fingerprinting

**Input:**
- Host and port
- Protocol (TCP/UDP)
- Timeout

**Output:**
- Banner text
- Identified service name

**API:**

```python
class BannerGrabber:
    def __init__(self, timeout: float)
    def grab_banner(
        self, 
        host: str, 
        port: int, 
        protocol: str
    ) -> Tuple[Optional[str], Optional[str]]
    def grab_multiple(
        self, 
        host: str, 
        ports: List[int], 
        protocol: str
    ) -> dict
```

**Process:**

```
1. Connect to service
2. Wait for initial banner (some services send immediately)
3. If no banner, send service-specific probe
4. Receive response
5. Format and analyze banner
6. Identify service from banner signatures
7. Return banner text and service name
```

**Supported Services:**
- HTTP/HTTPS
- FTP
- SSH
- SMTP
- POP3
- IMAP
- MySQL
- PostgreSQL
- And more...

---

### 8. ServiceDetect Agent

**Responsibility:** Identify services running on open ports using comprehensive signature databases

**Input:**
- ScanResult objects with open ports
- Optional banner data

**Output:**
- Updated ScanResults with:
  - Service name
  - Version number
  - CPE identifier
  - Confidence score

**API:**

```python
def get_service_name(port: int, protocol: str) -> Optional[str]
def detect_service_version(banner: Optional[str]) -> Optional[str]
def match_service_signature(banner: str, port: int) -> ServiceMatch
def extract_version_from_banner(banner: str, service: str) -> Optional[str]
```

**Process:**

```
1. Check port number against known services database
2. Analyze banner for service signatures (150+ signatures)
3. Extract version information using regex patterns (100+ patterns)
4. Lookup CPE identifier (200+ mappings)
5. Calculate confidence score
6. Return service name, version, and CPE
```

**Detection Methods:**
1. **Port-based detection** - Match against known port assignments
2. **Banner analysis** - Regex pattern matching against 150+ signatures
3. **Version extraction** - Extract version using 100+ specific patterns
4. **CPE mapping** - Map service to Common Platform Enumeration
5. **Confidence scoring** - Calculate match confidence (0-100%)

---

### 8a. Service Signature Databases

**Responsibility:** Provide comprehensive service detection data

SpectreScan v1.2.0 includes **four major signature databases** for professional-grade service detection:

#### **1. CPE Dictionary** (`spectrescan/data/cpe-dictionary.json`)

**Purpose:** Map detected services to Common Platform Enumeration identifiers

**Statistics:**
- **200+ CPE entries** across 10 major categories
- **719 lines** of structured JSON data
- Vendor, product, CPE base, category, and aliases for each service

**Categories:**
- `web_servers` - Apache, Nginx, IIS, Lighttpd, Caddy, etc.
- `app_servers` - Tomcat, Jetty, Undertow, WildFly, WebLogic, WebSphere
- `databases` - MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Cassandra, Oracle, MSSQL, etc.
- `network_services` - SSH, FTP, SMTP, IMAP, RDP, VNC, etc.
- `dev_tools` - Jenkins, GitLab, Ansible, Puppet, Chef, Terraform, Vault, Consul
- `containers` - Docker, Kubernetes, Containerd, Podman, OpenShift, Rancher
- `monitoring` - Grafana, Prometheus, Nagios, Zabbix, Splunk, Kibana, Logstash, Datadog
- `messaging` - RabbitMQ, Kafka, ActiveMQ, MQTT, NATS, ZeroMQ
- `storage` - MinIO, Ceph, GlusterFS, Samba, Nextcloud, ownCloud
- `security` - Snort, Suricata, Fail2Ban, OSSEC, Wazuh, OpenVAS, Nessus

**Example Entry:**
```json
"nginx": {
  "vendor": "nginx",
  "product": "nginx",
  "cpe_base": "cpe:/a:nginx:nginx",
  "category": "web_server",
  "aliases": ["nginx-core"]
}
```

#### **2. Service Signatures** (`spectrescan/data/service-signatures.json`)

**Purpose:** Match services using regex patterns and port mappings

**Statistics:**
- **150+ service signatures** with full detection metadata
- **1,085 lines** of structured JSON data
- Port lists, protocols, regex patterns, version extractors, CPE links, confidence scores

**Signature Structure:**
```json
{
  "name": "nginx",
  "ports": [80, 443, 8080],
  "protocol": "tcp",
  "patterns": [
    "nginx/",
    "Server: nginx"
  ],
  "version_pattern": "nginx/(\\d+\\.\\d+\\.\\d+)",
  "cpe": "cpe:/a:nginx:nginx",
  "confidence": 95,
  "category": "web_server"
}
```

**Categories Covered:**
- `container` - Docker, Kubernetes, Containerd, Podman, Rancher, OpenShift
- `orchestration` - Kubernetes, OpenShift, Rancher
- `database` - All major SQL and NoSQL databases
- `web_server` - Apache, Nginx, IIS, Lighttpd, Caddy
- `app_server` - Tomcat, Jetty, WildFly, WebLogic, WebSphere, Undertow
- `monitoring` - Grafana, Prometheus, Nagios, Zabbix, Splunk, ELK stack
- `ci_cd` - Jenkins, GitLab, GitHub Enterprise, Bitbucket, TeamCity, Bamboo
- `messaging` - RabbitMQ, Kafka, ActiveMQ, MQTT, NATS
- `cache` - Memcached, Redis
- `proxy` - HAProxy, Squid, Varnish, Traefik, Envoy
- `security` - Snort, Suricata, Wazuh, OpenVAS
- `storage` - MinIO, Samba, Nextcloud, ownCloud
- `cms` - WordPress, Drupal, Joomla, Magento
- `framework` - Django, Flask, Rails, Laravel, Spring, Express, Next.js, React, Angular, Vue

#### **3. Version Patterns** (`spectrescan/data/version-patterns.json`)

**Purpose:** Extract version numbers from service banners and headers

**Statistics:**
- **100+ service-specific patterns** with multiple regex variants
- **526 lines** of structured JSON data
- Generic fallback patterns for unknown services
- OS version extraction patterns

**Pattern Structure:**
```json
"nginx": [
  "nginx/(\\d+\\.\\d+\\.\\d+)",
  "nginx (\\d+\\.\\d+\\.\\d+)"
],
"mysql": [
  "(\\d+\\.\\d+\\.\\d+)",
  "MySQL (\\d+\\.\\d+\\.\\d+)"
]
```

**Extraction Sources:**
- HTTP headers (Server, X-Powered-By, X-AspNet-Version, X-Jenkins, X-Grafana-Version, etc.)
- Service banners (SSH, FTP, SMTP, database handshakes)
- JSON API responses (version endpoints)
- Binary protocol handshakes
- HTML meta tags
- Error messages

**Generic Patterns:**
```json
"generic_patterns": [
  "(\\d+\\.\\d+\\.\\d+\\.\\d+)",  # Quad version
  "(\\d+\\.\\d+\\.\\d+)",          # Triple version
  "v(\\d+\\.\\d+\\.\\d+)",         # Version with 'v'
  "version[:\\s]+(\\d+\\.\\d+\\.\\d+)",  # Version keyword
  "(\\d+\\.\\d+)",                 # Double version
  "(\\d{4}-\\d{2}-\\d{2})"        # Date-based version
]
```

**OS Version Patterns:**
```json
"os_version_patterns": {
  "ubuntu": ["Ubuntu (\\d+\\.\\d+)", "ubuntu-(\\d+\\.\\d+)"],
  "debian": ["Debian (\\d+\\.\\d+)", "debian/(\\d+)"],
  "centos": ["CentOS (\\d+\\.\\d+)", "centos:(\\d+)"],
  "rhel": ["Red Hat Enterprise Linux (\\d+\\.\\d+)", "rhel (\\d+)"],
  "windows": ["Windows (\\d+)", "Microsoft Windows.*?(\\d+\\.\\d+)"],
  "macos": ["Mac OS X (\\d+\\.\\d+)", "macOS (\\d+\\.\\d+)"]
}
```

#### **4. Nmap Service Probes** (`spectrescan/data/nmap-service-probes`)

**Purpose:** Active service probing using Nmap-compatible probe format (GPLv2)

**Statistics:**
- **100+ service probes** covering modern and legacy services
- **530 lines** in Nmap probe format
- NULL probe + specialized probes for each service category
- Match directives with regex patterns and version extraction

**Probe Format:**
```
Probe <protocol> <probename> q|<probe string>|
ports <port list>
rarity <1-9>
totalwaitms <milliseconds>
match <service> m|<regex>| p/<product>/ v/<version>/ cpe:<cpe>
```

**Example Probe:**
```
Probe TCP GrafanaAPI q|GET /api/health HTTP/1.0\r\n\r\n|
ports 3000
rarity 5
totalwaitms 3000

match grafana m|"database":\s*"ok"| p/Grafana/
match grafana m|X-Grafana-| p/Grafana/
```

**Probe Categories:**

**Web Services** (10+ probes):
- HTTP GET, SSL/TLS, HTTPS, HTTP/2

**Remote Access** (8+ probes):
- SSH (OpenSSH, Dropbear), RDP, VNC, TeamViewer, Telnet

**Databases** (20+ probes):
- MySQL, MariaDB, PostgreSQL, MSSQL, Oracle TNS
- Redis, MongoDB, Elasticsearch, Cassandra, CouchDB
- InfluxDB, Neo4j, Memcached

**Mail Services** (10+ probes):
- SMTP (Postfix, Sendmail, Exim), IMAP, POP3
- Dovecot, Courier, Exchange

**File Transfer** (8+ probes):
- FTP (vsftpd, ProFTPD, Pure-FTPd, FileZilla)
- Samba/SMB, NFS

**Containers & Orchestration** (8+ probes):
- Docker API, Kubernetes API, Containerd
- Rancher, OpenShift, Portainer

**DevOps & CI/CD** (10+ probes):
- Jenkins, GitLab, Ansible Tower, GitLab Runner
- Terraform, Vault, Consul, etcd

**Monitoring & Observability** (12+ probes):
- Grafana, Prometheus, Nagios, Zabbix, Splunk
- Kibana, Logstash, Elasticsearch

**Messaging** (8+ probes):
- RabbitMQ (AMQP + Management API), Kafka
- MQTT/Mosquitto, NATS, ActiveMQ

**Proxies & Load Balancers** (8+ probes):
- HAProxy, Squid, Varnish, Traefik, Envoy

**Web Applications & CMS** (10+ probes):
- WordPress, Drupal, Joomla, Magento
- Nextcloud, ownCloud

**Enterprise Servers** (8+ probes):
- Tomcat, WebLogic, WebSphere, WildFly/JBoss

**IoT & Network Appliances** (8+ probes):
- Home Assistant, Node-RED, Pi-hole
- pfSense, OPNsense, UniFi Controller

**Network Services** (10+ probes):
- DNS, SNMP, NTP, SIP, RTSP, LDAP

**Storage** (6+ probes):
- MinIO, Ceph, GlusterFS, etcd, Consul

**Detection Workflow:**

```
Open Port Detected
    │
    ├─► 1. NULL Probe (passive banner grab)
    │   └─► Match against 7000+ signatures
    │
    ├─► 2. Service-Specific Probe (active)
    │   └─► Send targeted probe (HTTP GET, SSH version, etc.)
    │
    ├─► 3. Signature Matching
    │   └─► Regex match against 150+ service signatures
    │
    ├─► 4. Version Extraction
    │   └─► Apply 100+ version patterns
    │
    ├─► 5. CPE Mapping
    │   └─► Lookup in 200+ CPE dictionary
    │
    └─► 6. Result
        ├─► Service Name
        ├─► Version Number
        ├─► CPE Identifier
        └─► Confidence Score (0-100%)
```

**Combined Detection Power:**

| Database | Entries | Lines | Purpose |
|----------|---------|-------|---------|
| **CPE Dictionary** | 200+ | 719 | Product identification |
| **Service Signatures** | 150+ | 1,085 | Pattern matching |
| **Version Patterns** | 100+ | 526 | Version extraction |
| **Nmap Probes** | 100+ | 530 | Active probing |
| **TOTAL** | **550+** | **2,860** | **Comprehensive coverage** |

**Service Coverage:** 200+ unique services across web, database, container, DevOps, security, IoT, and enterprise categories.

**Accuracy:** 95-100% detection rate for common services, 80-95% for specialized/enterprise services.

**Performance:** Sub-second matching against entire signature database using optimized regex caching.

---

### 9. OSDetect Agent

**Responsibility:** Identify target operating system

**Input:**
- Target host
- Open TCP port (optional but improves accuracy)

**Output:**
- OSFingerprint with:
  - OS guess
  - Confidence level
  - TTL value
  - TCP window size

**API:**

```python
class OSDetector:
    def __init__(self, timeout: float)
    def detect_os(
        self, 
        host: str, 
        open_port: Optional[int]
    ) -> OSFingerprint
    def enhance_with_banner(
        self, 
        fingerprint: OSFingerprint, 
        banner: Optional[str]
    ) -> OSFingerprint
```

**Detection Methods:**

1. **TTL Analysis**
   - Linux/Unix: 64
   - Windows: 128
   - Network devices: 255

2. **TCP Window Size**
   - Different OS use different default values

3. **Banner Analysis**
   - Extract OS hints from service banners

**Limitations:**
- Requires elevated privileges for accurate TTL detection
- Heuristic-based (not 100% accurate)
- Can be fooled by modified stack parameters

---

### 10. ReportGenerator Agent

**Responsibility:** Generate reports in various formats

**Input:**
- List of ScanResult objects
- Scan summary statistics
- Host information

**Output:**
- Formatted reports in JSON/CSV/XML/HTML

**API:**

```python
def generate_json_report(
    results: List[ScanResult], 
    output_path: Path, 
    summary: Optional[Dict]
) -> None

def generate_csv_report(
    results: List[ScanResult], 
    output_path: Path
) -> None

def generate_xml_report(
    results: List[ScanResult], 
    output_path: Path, 
    summary: Optional[Dict]
) -> None

def generate_html_report(
    results: List[ScanResult], 
    output_path: Path, 
    summary: Optional[Dict], 
    host_info: Optional[Dict[str, HostInfo]]
) -> None
```

**Report Features:**

- **JSON**: Structured data for programmatic access
- **CSV**: Spreadsheet-compatible tabular data
- **XML**: Standardized markup format
- **HTML**: Professional branded reports with:
  - Summary statistics dashboard
  - Interactive tables
  - Host information
  - BitSpectreLabs branding
  - Responsive design

---

### 10a. PDFReportGenerator Agent

**Responsibility:** Generate professional PDF reports with charts

**Input:**
- List of ScanResult objects
- Scan summary statistics
- Host information
- Chart inclusion flag

**Output:**
- PDF report with charts and branding

**API:**

```python
def generate_pdf_report(
    results: List[ScanResult],
    output_path: Path,
    summary: Optional[Dict],
    host_info: Optional[Dict[str, HostInfo]],
    include_charts: bool = True
) -> None
```

**Features:**
- Executive summary section with statistics
- Port status pie charts (open/closed/filtered)
- Service distribution bar charts
- Host information tables
- Detailed scan results with banner info
- Professional BitSpectreLabs branding
- Print-ready layout

**Requirements:** ReportLab library (`pip install reportlab`)

---

### 10b. ComparisonReportGenerator Agent

**Responsibility:** Generate detailed scan comparison reports

**Input:**
- ScanComparison object
- Output file path
- Report format (text/html/json)

**Output:**
- Formatted comparison report

**API:**

```python
def generate_comparison_report(
    comparison: ScanComparison,
    output_path: Path,
    format: str = 'text'
) -> None
```

**Formats:**
- **Text**: Plain text with ASCII formatting
- **HTML**: Styled report with color-coded changes
- **JSON**: Structured data for automation

**Report Sections:**
- Scan metadata (IDs, timestamps, targets)
- Change summary statistics
- Newly opened ports with services
- Newly closed ports
- Newly filtered ports
- Service version changes

---

### 10c. ExecutiveSummaryGenerator Agent

**Responsibility:** Generate high-level security assessments with risk scoring

**Input:**
- List of ScanResult objects
- Scan summary statistics
- Host information

**Output:**
- Executive summary text with risk assessment

**API:**

```python
def generate_executive_summary(
    results: List[ScanResult],
    summary: Optional[Dict],
    host_info: Optional[Dict[str, HostInfo]],
    output_path: Optional[Path]
) -> str

def calculate_risk_score(
    results: List[ScanResult]
) -> tuple[int, str, List[str]]
```

**Features:**
- **Risk Scoring Algorithm** (0-100):
  - Attack surface analysis (port count)
  - High-risk service detection (FTP, Telnet, SMB, etc.)
  - Vulnerable port exposure
  - Database service exposure
  - Administrative interface exposure
  
- **Risk Levels**:
  - 🔴 CRITICAL (75-100): Immediate action required
  - 🟠 HIGH (50-74): Significant vulnerabilities
  - 🟡 MEDIUM (25-49): Moderate concerns
  - 🟢 LOW (0-24): Minimal risk

- **Critical Findings Identification**:
  - Unencrypted protocols (FTP, Telnet)
  - Known vulnerable services
  - Excessive port exposure
  - Web admin interfaces

- **Security Recommendations**:
  - Actionable remediation steps
  - Risk-based prioritization
  - Industry best practices

---

### 10d. ChartGenerator Agent

**Responsibility:** Generate visual charts and graphs

**Input:**
- List of ScanResult objects
- Chart type specification
- Dimensions (width/height)

**Output:**
- ReportLab Drawing objects or ASCII charts

**API:**

```python
def create_port_distribution_chart(
    results: List[ScanResult],
    width: int = 400,
    height: int = 300
) -> Optional[Drawing]

def create_service_distribution_chart(
    results: List[ScanResult],
    width: int = 500,
    height: int = 400,
    top_n: int = 10
) -> Optional[Drawing]

def create_port_range_distribution_chart(
    results: List[ScanResult],
    width: int = 500,
    height: int = 300
) -> Optional[Drawing]

def get_ascii_chart(
    results: List[ScanResult],
    chart_type: str = 'port_distribution'
) -> str
```

**Chart Types:**
- **Port Distribution**: Pie chart of open/closed/filtered ports
- **Service Distribution**: Bar chart of top services
- **Port Range Distribution**: Bar chart by port range (well-known, registered, dynamic)
- **ASCII Charts**: Terminal-friendly text visualizations

**Export Formats:**
- PDF (via ReportLab)
- PNG (requires Pillow)
- ASCII text

**Requirements:** ReportLab library (optional Pillow for PNG)

---

### 10e. TemplateManager Agent

**Responsibility:** Manage custom report templates

**Input:**
- Template name
- Template content
- Template context variables

**Output:**
- Rendered reports
- Template files
- Template list

**API:**

```python
class TemplateManager:
    def __init__(self, templates_dir: Optional[Path])
    def render_template(self, template_name: str, context: Dict[str, Any]) -> str
    def render_from_string(self, template_string: str, context: Dict[str, Any]) -> str
    def list_templates(self) -> List[str]
    def create_template(self, name: str, content: str, overwrite: bool) -> Path
    def delete_template(self, name: str) -> bool
    def get_template_path(self, name: str) -> Optional[Path]

def generate_custom_report(
    results: List[ScanResult],
    template_name: str,
    output_path: Path,
    summary: Optional[Dict],
    host_info: Optional[Dict[str, HostInfo]],
    custom_vars: Optional[Dict[str, Any]],
    templates_dir: Optional[Path]
) -> None

def create_default_templates(templates_dir: Optional[Path]) -> None
```

**Features:**
- **Jinja2 Template Engine**: Full Jinja2 syntax support with filters and control structures
- **Template Library**: Store templates in `~/.spectrescan/templates/`
- **Multiple Formats**: HTML, text, markdown, XML templates
- **Custom Variables**: Pass custom data to templates
- **Default Templates**: Pre-built template examples (simple text, markdown, XML)
- **Template Validation**: Syntax checking and error reporting

**Template Context:**
- `results`: Full scan results list
- `summary`: Scan summary statistics
- `host_info`: Host information dictionary
- `timestamp`: Current timestamp
- `tool`: "SpectreScan"
- `vendor`: "BitSpectreLabs"
- `open_ports`: Filtered open ports
- `closed_ports`: Filtered closed ports
- `filtered_ports`: Filtered filtered ports
- Custom variables via `custom_vars` parameter

**Default Templates:**
- `simple_text.txt`: Plain text report
- `markdown_report.md`: Markdown-formatted report
- `custom_xml.xml`: XML structured report

**Requirements:** Jinja2 library (`pip install jinja2`)

---

### 10f. InteractiveHTMLReport Agent

**Responsibility:** Generate interactive HTML reports with JavaScript

**Input:**
- List of ScanResult objects
- Scan summary statistics
- Host information

**Output:**
- Interactive HTML file with embedded JavaScript and CSS

**API:**

```python
def generate_interactive_html_report(
    results: List[ScanResult],
    output_path: Path,
    summary: Optional[Dict],
    host_info: Optional[Dict[str, HostInfo]]
) -> None
```

**Features:**
- **Live Search**: Real-time filtering across all fields (host, port, service, banner)
- **Sortable Columns**: Click-to-sort on any column (host, port, protocol, state, service)
- **State Filtering**: Filter buttons for all/open/closed/filtered ports
- **Dark Mode Toggle**: Light/dark theme with persistent preference (localStorage)
- **Expandable Details**: Click "Details" button to view banner information
- **Copy to Clipboard**: Quick copy of host:port combinations
- **Statistics Dashboard**: Visual cards showing scan metrics
- **Responsive Design**: Mobile-friendly layout
- **No Dependencies**: Pure JavaScript, no external libraries required
- **Offline**: Works without internet connection

**Interactive Elements:**
- Search box with instant filtering
- State filter buttons (visual badges)
- Sortable table headers
- Expandable port details rows
- Theme toggle button
- "No results" message when filters match nothing

**Styling:**
- CSS custom properties for theming
- Gradient header with branding
- Color-coded state badges (green/red/orange)
- Smooth transitions and hover effects
- Professional BitSpectreLabs branding

**JavaScript Functions:**
- `filterResults()`: Search and state filtering
- `toggleDetails()`: Show/hide port details
- `copyToClipboard()`: Copy text to clipboard
- Column sorting with direction toggle
- Theme persistence with localStorage

**Use Cases:**
- Shareable reports for stakeholders
- Interactive analysis in browser
- Offline report viewing
- Professional client deliverables
- Team collaboration on findings

---

### 11. TUIFrontend Agent

**Responsibility:** Provide terminal user interface

**Input:**
- User interactions (keyboard/mouse)
- Scan results from ScanEngine

**Output:**
- Real-time visual feedback
- Interactive controls

**API:**

```python
class SpectreScanTUI(App):
    def compose(self) -> ComposeResult
    def action_start_scan(self) -> None
    def action_stop_scan(self) -> None
    def action_clear(self) -> None
```

**Components:**

- **ResultsTable Widget**: Display scan results
- **ProgressWidget**: Show scan progress
- **LogsWidget**: Display log messages
- **Input Fields**: Target and port specification
- **Control Buttons**: Start/Stop/Clear

---

### 12. GUIFrontend Agent

**Responsibility:** Provide graphical user interface

**Input:**
- User interactions (clicks, input)
- Scan results from ScanEngine

**Output:**
- Visual interface
- Export functionality

**API:**

```python
class SpectreScanGUI:
    def __init__(self, root: tk.Tk)
    def _start_scan(self) -> None
    def _stop_scan(self) -> None
    def _export_results(self, format_type: str) -> None
```

**Features:**

- Configuration panel
- Results table with tabs
- Progress bar
- Real-time logs
- Export buttons
- Dark theme with branding

---

### 13. ProfileManager Agent

**Responsibility:** Manage scan configuration profiles

**Input:**
- Profile name
- ScanProfile object
- Import/export file paths

**Output:**
- Saved profiles
- Profile metadata
- Profile list

**API:**

```python
class ProfileManager:
    def __init__(self, profiles_dir: Optional[Path])
    def save_profile(self, profile: ScanProfile) -> None
    def load_profile(self, name: str) -> ScanProfile
    def delete_profile(self, name: str) -> None
    def list_profiles(self) -> List[str]
    def profile_exists(self, name: str) -> bool
    def export_profile(self, name: str, export_path: Path) -> None
    def import_profile(self, import_path: Path) -> ScanProfile
```

**Profile Structure:**

```python
@dataclass
class ScanProfile:
    name: str
    description: str
    ports: List[int]
    scan_types: List[str]
    threads: int
    timeout: float
    rate_limit: Optional[int]
    enable_service_detection: bool
    enable_os_detection: bool
    enable_banner_grabbing: bool
    randomize: bool
    timing_template: int
    created_at: Optional[str]
    modified_at: Optional[str]
```

**Features:**

- **Profile Storage**: Profiles saved as JSON in `~/.spectrescan/profiles/`
- **Profile Validation**: Ensures profile integrity on load
- **Filename Sanitization**: Handles special characters in profile names
- **Import/Export**: Share profiles between systems
- **Auto-Timestamps**: Tracks creation and modification times
- **Profile Overwrite**: Update existing profiles by name

**Use Cases:**

- Save frequently used scan configurations
- Share scan templates across teams
- Maintain different profiles for various scenarios
- Quick access to complex scan setups

---

### 14. HistoryManager Agent

**Responsibility:** Track and manage scan history

**Input:**
- Scan metadata (target, ports, type, duration)
- Scan results summary
- Filter/search criteria

**Output:**
- ScanHistoryEntry objects
- History statistics
- Search results

**API:**

```python
class HistoryManager:
    def __init__(self, history_dir: Optional[Path])
    def add_entry(
        self, target: str, ports: List[int], scan_type: str,
        duration: float, open_ports: int, closed_ports: int,
        filtered_ports: int, config: Dict[str, Any],
        results_file: Optional[str]
    ) -> ScanHistoryEntry
    def get_entry(self, scan_id: str) -> Optional[ScanHistoryEntry]
    def list_entries(
        self, limit: Optional[int], target_filter: Optional[str],
        scan_type_filter: Optional[str]
    ) -> List[ScanHistoryEntry]
    def delete_entry(self, scan_id: str) -> bool
    def clear_history(self) -> None
    def search_history(self, query: str) -> List[ScanHistoryEntry]
    def get_statistics(self) -> Dict[str, Any]
```

**History Entry Structure:**

```python
@dataclass
class ScanHistoryEntry:
    id: str
    target: str
    ports: List[int]
    scan_type: str
    timestamp: str
    duration: float
    open_ports: int
    closed_ports: int
    filtered_ports: int
    total_ports: int
    config: Dict[str, Any]
    results_file: Optional[str]
```

**Features:**

- **Persistent Storage**: History saved as JSON in `~/.spectrescan/history/`
- **Unique IDs**: MD5-based unique scan identifiers
- **Filtering**: Filter by target, scan type, time range
- **Search**: Full-text search across targets and configs
- **Statistics**: Aggregate data analysis
- **Chronological Order**: Most recent scans first
- **Linked Results**: Optional path to detailed scan results

**Statistics Provided:**

- Total scans performed
- Total ports scanned
- Total open ports found
- Total scan time
- Scan type distribution
- Most frequently scanned targets

**Use Cases:**

- Track scanning activity over time
- Review previous scan results
- Identify frequently scanned targets
- Audit scanning operations
- Performance analysis

---

### 15. ScanComparer Agent

**Responsibility:** Compare two scans to identify differences

**Input:**
- Two scan IDs or target name
- Optional scan results data
- History entries

**Output:**
- ScanComparison object
- Formatted comparison report
- Change statistics

**API:**

```python
class ScanComparer:
    def __init__(self)
    def compare_scans(
        self, scan1_id: str, scan2_id: str,
        results1: Optional[List[ScanResult]],
        results2: Optional[List[ScanResult]]
    ) -> ScanComparison
    def compare_by_target(
        self, target: str, limit: int
    ) -> Optional[ScanComparison]
    def format_comparison_text(
        self, comparison: ScanComparison
    ) -> str
```

**Comparison Structure:**

```python
@dataclass
class ScanComparison:
    scan1_id: str
    scan2_id: str
    scan1_target: str
    scan2_target: str
    scan1_timestamp: str
    scan2_timestamp: str
    newly_opened: List[PortDifference]
    newly_closed: List[PortDifference]
    newly_filtered: List[PortDifference]
    service_changed: List[PortDifference]
    total_changes: int
    scan1_open_count: int
    scan2_open_count: int
    open_diff: int

@dataclass
class PortDifference:
    port: int
    protocol: str
    old_state: str
    new_state: str
    service_old: Optional[str]
    service_new: Optional[str]
```

**Features:**

- **State Change Detection**: Identifies ports that changed state (open/closed/filtered)
- **Service Change Detection**: Detects when services change on open ports
- **Diff Statistics**: Calculates total changes and open port differences
- **Target Validation**: Ensures scans are for the same target
- **History Integration**: Automatically loads scans from history
- **Formatted Output**: Human-readable text report generation

**Change Categories:**

- Newly opened ports
- Newly closed ports
- Newly filtered ports
- Service version changes
- Open port count differences

**Use Cases:**

- Infrastructure change monitoring
- Security posture tracking
- Firewall rule verification
- Service deployment detection
- Compliance auditing

---

### 16. NSEEngine Agent

**Responsibility:** Execute Nmap-compatible Lua scripts for advanced service detection

**Input:**
- Script name or pattern
- Host information
- Port information (for portrule scripts)
- Script arguments

**Output:**
- NSEScriptResult objects with:
  - Script output (text)
  - Structured output (dict)
  - Execution time
  - Success/failure status

**API:**

```python
class NSEEngine:
    def __init__(self, scripts_dir: Optional[Path])
    def load_scripts(self, patterns: Optional[List[str]])
    def list_scripts(self) -> List[str]
    def get_script(self, name: str) -> Optional[NSEScriptInfo]
    def get_scripts_by_category(self, category: NSECategory) -> List[NSEScriptInfo]
    async def run_script(
        self,
        script_name: str,
        host: NSEHostInfo,
        port: Optional[NSEPortInfo],
        args: Optional[Dict[str, Any]]
    ) -> NSEScriptResult
    async def run_scripts(
        self,
        script_names: List[str],
        host: NSEHostInfo,
        ports: List[NSEPortInfo],
        args: Optional[Dict[str, Any]]
    ) -> List[NSEScriptResult]
```

**Script Categories:**

| Category | Description |
|----------|-------------|
| auth | Authentication testing |
| broadcast | Broadcast network discovery |
| brute | Brute-force password attacks |
| default | Default scripts run with -sC |
| discovery | Host and service discovery |
| dos | Denial of service testing |
| exploit | Exploitation scripts |
| external | External service queries |
| fuzzer | Fuzzing and input testing |
| intrusive | Potentially harmful scripts |
| malware | Malware detection |
| safe | Safe, non-intrusive scripts |
| version | Version detection enhancement |
| vuln | Vulnerability detection |

**Bundled Scripts:**

| Script | Description |
|--------|-------------|
| http-title | HTTP page title detection |
| ssl-cert | SSL certificate information |
| ssh-hostkey | SSH host key fingerprints |
| ftp-anon | FTP anonymous login check |
| smb-os-discovery | SMB OS discovery |
| http-headers | HTTP response headers |
| http-methods | HTTP allowed methods |
| mysql-info | MySQL server information |
| redis-info | Redis server information |
| smtp-commands | SMTP supported commands |

**Requirements:**
- Lupa library for Lua execution: `pip install lupa`
- Script parsing works without Lupa
- Script execution requires Lupa

**NSE Library Functions:**

The NSE library provides Nmap-compatible functions:
- `nmap.fetchurl(url)` - Fetch URL content
- `nmap.get_port_state(host, port)` - Get port state
- `nmap.log_write(category, text)` - Write to log
- `stdnse.sleep(seconds)` - Sleep function
- `stdnse.format_output(data)` - Format output
- `shortport.http`, `shortport.ssl` - Port matchers

---

### 17. SSLAnalyzer Agent

**Responsibility:** Analyze SSL/TLS certificates and cipher suites

**Input:**
- Target host
- Port (default 443)

**Output:**
- Certificate information
- Cipher suite analysis
- Vulnerability detection

---

### 18. CVEMatcher Agent

**Responsibility:** Match detected services against CVE database

**Input:**
- Service name
- Version number
- Product name

**Output:**
- List of matching CVEs
- Severity scores
- Descriptions

---

### 19. CheckpointManager Agent

**Responsibility:** Save and restore scan state for resume capability

**Input:**
- Scan ID
- Partial results
- Scan configuration

**Output:**
- Checkpoint file
- Restored scan state

---

### 20. DistributedMaster Agent

**Responsibility:** Coordinate distributed scanning across multiple worker nodes

**Input:**
- Target specification (large networks)
- Worker node list
- Scan configuration
- Task distribution strategy

**Output:**
- Aggregated scan results
- Worker status reports
- Task completion statistics

**API:**

```python
class DistributedMaster:
    def __init__(self, host: str, port: int, config: ClusterConfig)
    async def start(self) -> None
    async def stop(self) -> None
    async def register_worker(self, worker_id: str, address: str) -> bool
    async def unregister_worker(self, worker_id: str) -> bool
    async def distribute_scan(
        self,
        targets: List[str],
        ports: List[int],
        config: ScanConfig
    ) -> str  # Returns scan_id
    async def get_scan_status(self, scan_id: str) -> ScanStatus
    async def get_aggregated_results(self, scan_id: str) -> List[ScanResult]
    def get_worker_status(self) -> Dict[str, WorkerStatus]
```

**Data Structures:**

```python
@dataclass
class WorkerInfo:
    worker_id: str
    address: str
    status: WorkerStatus  # idle, busy, offline
    current_task: Optional[str]
    last_heartbeat: datetime
    tasks_completed: int
    tasks_failed: int

@dataclass
class TaskAssignment:
    task_id: str
    worker_id: str
    targets: List[str]
    ports: List[int]
    status: TaskStatus  # pending, running, completed, failed
    assigned_at: datetime
    completed_at: Optional[datetime]
    result_count: int
```

**Features:**
- Automatic worker discovery and registration
- Intelligent task distribution based on network size
- Load balancing across available workers
- Heartbeat-based health monitoring
- Automatic task reassignment on worker failure
- Result aggregation from all workers
- TLS encryption for secure communication
- Redis/RabbitMQ message queue support

**Task Distribution Strategy:**

```
Large Network (10.0.0.0/8)
         │
         ▼
    ┌────────────────┐
    │ Split by Subnet │
    └────────┬───────┘
             │
    ┌────────┼────────┬────────┐
    ▼        ▼        ▼        ▼
10.0.0.0/16 10.1.0.0/16 10.2.0.0/16 10.3.0.0/16
 (Worker1)   (Worker2)   (Worker3)   (Worker4)
```

---

### 21. DistributedWorker Agent

**Responsibility:** Execute scan tasks assigned by the master node

**Input:**
- Task assignment from master
- Target subset
- Port list
- Scan configuration

**Output:**
- Scan results for assigned targets
- Task completion status
- Health heartbeats

**API:**

```python
class DistributedWorker:
    def __init__(self, worker_id: str, master_address: str)
    async def start(self) -> None
    async def stop(self) -> None
    async def execute_task(self, task: TaskAssignment) -> TaskResult
    async def send_heartbeat(self) -> None
    async def report_results(self, results: List[ScanResult]) -> None
    def get_status(self) -> WorkerStatus
```

**Worker Lifecycle:**

```
┌─────────────┐
│   Start     │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Register with   │
│ Master Node     │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐     ┌─────────────┐
│ Wait for Task   │◄────┤  Heartbeat  │
└──────┬──────────┘     │   (every 5s)│
       │                └─────────────┘
       ▼
┌─────────────────┐
│ Execute Scan    │
│ on Assigned     │
│ Targets         │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Report Results  │
│ to Master       │
└──────┬──────────┘
       │
       └──────► (Loop back to Wait)
```

---

### 22. WebDashboard Agent

**Responsibility:** Provide web-based interface for scan management and monitoring

**Input:**
- HTTP requests (REST API)
- WebSocket connections
- User authentication

**Output:**
- HTML dashboard pages
- JSON API responses
- Real-time WebSocket updates

**API:**

```python
class WebDashboardApp:
    def __init__(self, host: str, port: int, debug: bool)
    def create_app(self) -> FastAPI
    async def start(self) -> None
    async def stop(self) -> None
```

**REST API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/login | User login |
| POST | /api/auth/logout | User logout |
| GET | /api/auth/me | Current user info |
| GET | /api/scans | List all scans |
| POST | /api/scans | Start new scan |
| GET | /api/scans/{id} | Get scan details |
| DELETE | /api/scans/{id} | Delete scan |
| POST | /api/scans/{id}/stop | Stop running scan |
| GET | /api/profiles | List profiles |
| POST | /api/profiles | Create profile |
| GET | /api/history | Scan history |
| GET | /api/dashboard | Dashboard stats |

**WebSocket Events:**

```python
# Server -> Client events
class WebSocketEvents:
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_RESULT = "scan_result"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    WORKER_STATUS = "worker_status"
    NOTIFICATION = "notification"
```

**Data Flow:**

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Browser   │◄───►│  FastAPI    │◄───►│ ScanEngine  │
│  (React/JS) │     │   Server    │     │   Agent     │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │  WebSocket  │
                    │   Manager   │
                    └─────────────┘
```

---

### 23. AuthManager Agent

**Responsibility:** Handle user authentication and authorization

**Input:**
- Login credentials
- Session tokens
- Permission requests

**Output:**
- Authentication status
- Session tokens
- Permission decisions

**API:**

```python
class UserManager:
    def __init__(self, users_file: Path)
    def create_user(self, username: str, password: str, role: UserRole) -> User
    def authenticate(self, username: str, password: str) -> Optional[User]
    def get_user(self, username: str) -> Optional[User]
    def update_user(self, username: str, **kwargs) -> bool
    def delete_user(self, username: str) -> bool

class SessionManager:
    def __init__(self, secret_key: str, session_timeout: int)
    def create_session(self, user: User) -> str  # Returns session_id
    def validate_session(self, session_id: str) -> Optional[User]
    def invalidate_session(self, session_id: str) -> None
    def cleanup_expired(self) -> int  # Returns count removed
```

**Role-Based Access Control (RBAC):**

| Role | Level | Permissions |
|------|-------|-------------|
| Viewer | 1 | view_scans, view_results, view_history |
| Operator | 2 | + start_scan, stop_scan, manage_own_profiles |
| Analyst | 3 | + export_data, compare_scans, view_all_profiles |
| Admin | 4 | + manage_users, manage_all_profiles, system_settings |
| Super Admin | 5 | + security_settings, audit_logs, full_access |

**Permission Matrix:**

```python
ROLE_PERMISSIONS = {
    UserRole.VIEWER: [
        "view_scans", "view_results", "view_history",
        "view_profiles", "view_dashboard"
    ],
    UserRole.OPERATOR: [
        # Includes Viewer permissions +
        "start_scan", "stop_scan", "pause_scan",
        "create_profile", "edit_own_profile", "delete_own_profile"
    ],
    UserRole.ANALYST: [
        # Includes Operator permissions +
        "export_json", "export_csv", "export_html", "export_pdf",
        "compare_scans", "view_all_profiles", "generate_reports"
    ],
    UserRole.ADMIN: [
        # Includes Analyst permissions +
        "manage_users", "manage_all_profiles", "view_audit_log",
        "system_settings", "manage_workers"
    ],
    UserRole.SUPER_ADMIN: [
        # All permissions
        "security_settings", "manage_roles", "manage_api_keys",
        "cluster_management", "full_access"
    ]
}
```

---

### 24. WebSocketManager Agent

**Responsibility:** Manage real-time WebSocket connections for live updates

**Input:**
- WebSocket connections
- Scan events
- System notifications

**Output:**
- Real-time updates to connected clients
- Connection status
- Broadcast messages

**API:**

```python
class WebSocketManager:
    def __init__(self)
    async def connect(self, websocket: WebSocket, client_id: str) -> None
    async def disconnect(self, client_id: str) -> None
    async def broadcast(self, message: Dict[str, Any]) -> None
    async def send_to_client(self, client_id: str, message: Dict) -> None
    async def send_scan_progress(
        self, scan_id: str, progress: float, 
        current_port: int, results_count: int
    ) -> None
    async def send_scan_result(self, scan_id: str, result: ScanResult) -> None
    async def send_scan_completed(self, scan_id: str, summary: Dict) -> None
    def get_connected_clients(self) -> List[str]
```

**Message Format:**

```json
{
    "event": "scan_progress",
    "data": {
        "scan_id": "abc123",
        "progress": 45.5,
        "current_port": 443,
        "results_count": 12,
        "eta_seconds": 120
    },
    "timestamp": "2025-01-15T14:30:00Z"
}
```

**Connection Lifecycle:**

```
Client                    Server
  │                          │
  │──── Connect ────────────►│
  │                          │ Register client
  │◄─── Welcome ─────────────│
  │                          │
  │◄─── scan_started ────────│
  │◄─── scan_progress ───────│
  │◄─── scan_result ─────────│
  │◄─── scan_progress ───────│
  │◄─── scan_result ─────────│
  │◄─── scan_completed ──────│
  │                          │
  │──── Disconnect ─────────►│
  │                          │ Cleanup
```

---

### 25. ScanScheduler Agent

**Responsibility:** Schedule and automate scan execution with cron-like timing

**Input:**
- Schedule configuration (cron expression, interval, datetime)
- Target specifications
- Scan configurations
- Pre/post scan hooks
- Execution conditions

**Output:**
- Scheduled scan objects
- Execution history
- Hook results
- Condition evaluation results

**API:**

```python
class ScanScheduler:
    def __init__(self, db_path: Optional[Path])
    def create_schedule(
        self,
        name: str,
        target: str,
        schedule_type: str,
        time_spec: Dict[str, Any],
        ports: Optional[str],
        scan_type: Optional[str],
        profile: Optional[str],
        hooks: Optional[List[ScanHook]],
        conditions: Optional[List[ExecutionCondition]],
        enabled: bool,
        chain_from: Optional[str]
    ) -> ScheduledScan
    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]
    def list_schedules(self, status: Optional[ScheduleStatus]) -> List[ScheduledScan]
    def update_schedule(self, schedule_id: str, **kwargs) -> bool
    def delete_schedule(self, schedule_id: str) -> bool
    def pause_schedule(self, schedule_id: str) -> bool
    def resume_schedule(self, schedule_id: str) -> bool
    def run_schedule_now(self, schedule_id: str) -> Optional[ScheduleRunResult]
    def get_schedule_history(self, schedule_id: str, limit: int) -> List[ScheduleRunResult]
    async def start_daemon(self) -> None
    async def stop_daemon(self) -> None
```

**Data Structures:**

```python
class ScheduleType(Enum):
    ONCE = "once"           # One-time execution
    CRON = "cron"           # Cron expression
    INTERVAL = "interval"   # Every N seconds/minutes/hours
    DAILY = "daily"         # Daily at specific time
    WEEKLY = "weekly"       # Weekly on specific days
    MONTHLY = "monthly"     # Monthly on specific day

class ScheduleStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class HookType(Enum):
    PRE_SCAN = "pre_scan"     # Before scan starts
    POST_SCAN = "post_scan"   # After scan completes
    ON_ERROR = "on_error"     # When scan fails
    ON_CHANGE = "on_change"   # When results differ from last run

class ConditionType(Enum):
    HOST_UP = "host_up"               # Target responds to ping
    PORT_CHANGED = "port_changed"     # Port state changed since last scan
    SERVICE_CHANGED = "service_changed"  # Service changed since last scan
    TIME_WINDOW = "time_window"       # Within specific time range
    PREVIOUS_SUCCESS = "previous_success"  # Last run succeeded
    CUSTOM = "custom"                 # Custom Python function

@dataclass
class ScheduledScan:
    id: str
    name: str
    target: str
    schedule_type: ScheduleType
    cron_expression: Optional[CronExpression]
    interval_seconds: Optional[int]
    scheduled_time: Optional[datetime]
    ports: Optional[str]
    scan_type: Optional[str]
    profile: Optional[str]
    hooks: List[ScanHook]
    conditions: List[ExecutionCondition]
    status: ScheduleStatus
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    run_count: int
    chain_from: Optional[str]
    created_at: datetime
    updated_at: datetime

@dataclass
class ScheduleRunResult:
    id: str
    schedule_id: str
    started_at: datetime
    completed_at: Optional[datetime]
    status: str  # "success", "failed", "skipped"
    results_count: int
    open_ports: int
    error_message: Optional[str]
    hook_results: Dict[str, Any]
    condition_results: Dict[str, bool]
```

**Cron Expression Support:**

```python
class CronExpression:
    """Parse and match cron expressions."""
    
    def __init__(self, expression: str)
    def matches(self, dt: datetime) -> bool
    def get_next_run(self, after: datetime) -> datetime
    
    # Supported patterns:
    # * - Any value
    # 5 - Specific value
    # 1-5 - Range
    # 1,3,5 - List
    # */15 - Step (every 15)
    # 1-10/2 - Range with step
    
    # Shorthand expressions:
    # @hourly, @daily, @weekly, @monthly
```

**Hook Execution:**

```python
class HookExecutor:
    async def execute_hook(self, hook: ScanHook, context: Dict[str, Any]) -> Dict[str, Any]
    
    # Hook types:
    # - Shell command: subprocess execution
    # - Python function: callable execution
    # - Webhook: HTTP POST notification

@dataclass
class ScanHook:
    type: HookType
    command: Optional[str]      # Shell command
    function: Optional[str]     # Python function path
    webhook_url: Optional[str]  # Webhook endpoint
    timeout: int = 60
```

**Condition Evaluation:**

```python
class ConditionEvaluator:
    async def evaluate(self, condition: ExecutionCondition, context: Dict[str, Any]) -> bool
    
    # Condition types:
    # HOST_UP - Ping target with timeout
    # PORT_CHANGED - Compare with previous scan
    # SERVICE_CHANGED - Compare service versions
    # TIME_WINDOW - Check if current time in range
    # PREVIOUS_SUCCESS - Check last run status
    # CUSTOM - Execute custom function

@dataclass
class ExecutionCondition:
    type: ConditionType
    parameters: Dict[str, Any]
```

**Features:**

- **Multiple Schedule Types**: One-time, cron, interval, daily, weekly, monthly
- **Full Cron Support**: Wildcards, ranges, lists, steps, shorthand expressions
- **Pre/Post Hooks**: Execute commands before/after scans
- **Conditional Execution**: Skip scans based on conditions
- **Scan Chaining**: Link scans for automated workflows
- **SQLite Persistence**: Reliable schedule storage
- **Background Daemon**: Async scheduler with asyncio
- **Execution History**: Track all run results
- **Error Recovery**: Retry logic with exponential backoff

**Scheduler Workflow:**

```
┌─────────────────────────────────────────────────────────────────┐
│                     Scheduler Daemon                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Check Active Schedules (every 60s)                              │
│   └─► For each schedule where next_run <= now                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Evaluate Conditions                                             │
│   ├─► HOST_UP: Ping target                                      │
│   ├─► TIME_WINDOW: Check time range                             │
│   ├─► PORT_CHANGED: Compare with last scan                      │
│   └─► If any condition fails → Skip scan                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Execute Pre-Scan Hooks                                          │
│   ├─► Shell commands                                            │
│   ├─► Python functions                                          │
│   └─► Webhooks                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Execute Scan                                                    │
│   ├─► Load profile (if specified)                               │
│   ├─► Configure PortScanner                                     │
│   └─► Run scan with configured options                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Execute Post-Scan Hooks                                         │
│   ├─► ON_CHANGE hooks (if results differ)                       │
│   └─► POST_SCAN hooks (always)                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Update Schedule                                                 │
│   ├─► Record run result                                         │
│   ├─► Calculate next_run                                        │
│   ├─► Trigger chained schedules                                 │
│   └─► Mark COMPLETED (if one-time)                              │
└─────────────────────────────────────────────────────────────────┘
```

**CLI Integration:**

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

**Use Cases:**

- Continuous infrastructure monitoring
- Compliance audit automation
- Change detection and alerting
- Multi-stage scan workflows
- Off-hours security scanning
- Automated vulnerability tracking

---

### 26. Proxy Agent

**Responsibility:** Manage proxy connections for anonymous and evasive scanning

**Input:**
- Proxy configuration (URL, credentials)
- Target host and port
- Proxy pool settings
- Rotation strategy

**Output:**
- Proxied connections (reader, writer)
- Connection status
- Health check results

**API:**

```python
class ProxyConnector:
    def __init__(
        self,
        proxy: Optional[ProxyConfig] = None,
        proxy_chain: Optional[ProxyChain] = None,
        proxy_pool: Optional[ProxyPool] = None
    )
    async def connect(
        self,
        host: str,
        port: int,
        timeout: float = 10.0
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]
    async def _socks4_handshake(...)
    async def _socks5_handshake(...)
    async def _http_connect_handshake(...)

class ProxyPool:
    def __init__(
        self,
        proxies: List[ProxyConfig],
        strategy: str = "round_robin"
    )
    def get_next(self) -> Optional[ProxyConfig]
    def mark_failed(self, proxy: ProxyConfig)
    def mark_success(self, proxy: ProxyConfig, response_time: float)
    def get_healthy_proxies(self) -> List[ProxyConfig]

class ProxyHealthChecker:
    def __init__(
        self,
        check_interval: int = 300,
        timeout: float = 10.0
    )
    async def check_proxy(self, proxy: ProxyConfig) -> bool
    async def check_all(self, proxies: List[ProxyConfig]) -> Dict[str, bool]
    async def start_background_checks(self, pool: ProxyPool)
```

**Data Structures:**

```python
class ProxyType(Enum):
    SOCKS4 = "socks4"
    SOCKS4A = "socks4a"
    SOCKS5 = "socks5"
    HTTP = "http"
    HTTPS = "https"

class ProxyStatus(Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    CHECKING = "checking"

@dataclass
class ProxyConfig:
    type: ProxyType
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    status: ProxyStatus = ProxyStatus.UNKNOWN
    last_check: Optional[datetime] = None
    response_time: Optional[float] = None
    fail_count: int = 0
    success_count: int = 0

class ProxyChain:
    """Chain multiple proxies for multi-hop routing."""
    proxies: List[ProxyConfig]
    
@dataclass
class RotationStrategy:
    ROUND_ROBIN = "round_robin"   # Sequential rotation
    RANDOM = "random"             # Random selection
    LEAST_USED = "least_used"     # Least connections
    FASTEST = "fastest"           # Lowest response time
```

**Proxy Connection Flow:**

```
┌─────────────────────────────────────────────────────────────────┐
│                     Proxy Connection Flow                       │
└─────────────────────────────────────────────────────────────────┘

Connection Request
      │
      ▼
┌─────────────────┐
│ Select Proxy    │
│ (Pool/Chain)    │
└────────┬────────┘
         │
    ┌────┴────┬───────────┬───────────┐
    ▼         ▼           ▼           ▼
┌───────┐ ┌───────┐ ┌─────────┐ ┌─────────┐
│SOCKS4 │ │SOCKS5 │ │  HTTP   │ │  Chain  │
│Connect│ │Connect│ │ CONNECT │ │ (Multi) │
└───┬───┘ └───┬───┘ └────┬────┘ └────┬────┘
    │         │          │           │
    └─────────┴──────────┴───────────┘
                   │
                   ▼
         ┌─────────────────┐
         │ Proxy Handshake │
         └────────┬────────┘
                  │
         ┌────────┴────────┐
         │  Success?       │
         └────────┬────────┘
              ┌───┴───┐
              │       │
         Yes  │       │  No
              ▼       ▼
    ┌──────────────┐ ┌──────────────┐
    │ Return Conn  │ │ Mark Failed  │
    │ (reader,     │ │ Try Next     │
    │  writer)     │ │ Proxy        │
    └──────────────┘ └──────────────┘
```

**SOCKS5 Handshake:**

```
Client                         SOCKS5 Proxy
   │                               │
   │─── Version/Auth Methods ────►│
   │    (0x05, n_methods, ...)    │
   │                               │
   │◄── Auth Method Response ─────│
   │    (0x05, method)            │
   │                               │
   │─── Auth (if required) ──────►│
   │    (user, pass)              │
   │                               │
   │◄── Auth Response ────────────│
   │    (0x01, 0x00 = success)    │
   │                               │
   │─── Connect Request ─────────►│
   │    (0x05, 0x01, 0x00,        │
   │     addr_type, addr, port)   │
   │                               │
   │◄── Connect Response ─────────│
   │    (0x05, 0x00 = success)    │
   │                               │
   │═══ Proxied Connection ═══════│
```

**HTTP CONNECT Handshake:**

```
Client                          HTTP Proxy
   │                               │
   │─── CONNECT host:port ───────►│
   │    HTTP/1.1                  │
   │    Host: host:port           │
   │    [Proxy-Authorization]     │
   │                               │
   │◄── 200 Connection ───────────│
   │    Established               │
   │                               │
   │═══ Tunneled Connection ══════│
```

**Rotation Strategies:**

| Strategy | Description | Use Case |
|----------|-------------|----------|
| round_robin | Sequential proxy rotation | Even load distribution |
| random | Random proxy selection | Unpredictable patterns |
| least_used | Lowest connection count | Load balancing |
| fastest | Lowest response time | Performance optimization |

**Features:**

- **Full SOCKS Support**: SOCKS4, SOCKS4a, SOCKS5 with authentication
- **HTTP/HTTPS Proxy**: HTTP CONNECT method with Basic/NTLM auth
- **Proxy Chaining**: Route through multiple proxies (multi-hop)
- **Proxy Pool**: Manage multiple proxies with rotation
- **Health Checking**: Automatic proxy health monitoring
- **Tor Integration**: Built-in Tor network support
- **Automatic Failover**: Switch to healthy proxy on failure
- **Response Time Tracking**: Track proxy performance metrics

**CLI Integration:**

```bash
# Single proxy
spectrescan scan 192.168.1.1 --proxy socks5://127.0.0.1:9050
spectrescan scan 192.168.1.1 --proxy http://user:pass@proxy.example.com:8080

# Proxy file (one per line)
spectrescan scan 192.168.1.1 --proxy-file proxies.txt

# Proxy rotation
spectrescan scan 192.168.1.1 --proxy-file proxies.txt --proxy-rotate
spectrescan scan 192.168.1.1 --proxy-file proxies.txt --proxy-strategy fastest

# Tor network
spectrescan scan 192.168.1.1 --tor

# Health check before scan
spectrescan scan 192.168.1.1 --proxy-file proxies.txt --proxy-check
```

**Proxy File Format:**

```text
# Comments start with #
socks5://127.0.0.1:9050
socks5://user:password@proxy1.example.com:1080
http://proxy2.example.com:8080
https://user:pass@secure-proxy.example.com:443
socks4://legacy-proxy.example.com:1080
```

**Use Cases:**

- Anonymous scanning through Tor network
- Evasion through proxy rotation
- Geographic distribution of scan sources
- Bypassing IP-based rate limiting
- Corporate network egress through proxies
- Multi-hop routing for enhanced privacy

---

### 27. Evasion Agent

**Responsibility:** Implement IDS/IPS evasion techniques for stealthy scanning

**Input:**
- Evasion configuration (profile, techniques)
- Target host and port
- Scan type (TCP, SYN, UDP)

**Output:**
- Crafted packets with evasion techniques applied
- Scan results with evasion metadata
- Evasion statistics

**API:**

```python
class EvasionManager:
    def __init__(self, config: EvasionConfig)
    def get_scanner(self) -> EvasionScanner
    def get_packet_crafter(self) -> PacketCrafter
    def get_active_techniques(self) -> List[EvasionTechnique]
    def get_evasion_summary(self) -> Dict[str, Any]

class EvasionScanner:
    def __init__(self, config: EvasionConfig)
    def scan_with_evasion(
        self,
        host: str,
        port: int,
        timeout: float
    ) -> Tuple[str, Optional[str]]
    async def async_scan_with_evasion(
        self,
        host: str,
        port: int,
        timeout: float
    ) -> Tuple[str, Optional[str]]

class PacketCrafter:
    def __init__(self, config: EvasionConfig)
    def craft_syn_packet(
        self,
        target_ip: str,
        target_port: int,
        source_port: Optional[int]
    ) -> Optional[Any]
    def craft_fragmented_packet(
        self,
        target_ip: str,
        target_port: int
    ) -> Optional[List[Any]]
```

**Data Structures:**

```python
class EvasionTechnique(Enum):
    FRAGMENTATION = "fragmentation"
    DECOY = "decoy"
    SOURCE_PORT = "source_port"
    TTL_MANIPULATION = "ttl_manipulation"
    BAD_CHECKSUM = "bad_checksum"
    IDLE_SCAN = "idle_scan"
    TIMING_EVASION = "timing_evasion"
    RANDOMIZE_HOSTS = "randomize_hosts"
    DATA_LENGTH = "data_length"

class EvasionProfile(Enum):
    NONE = "none"
    STEALTH = "stealth"
    PARANOID = "paranoid"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"

class TimingLevel(Enum):
    PARANOID = 0    # 5 minute delay
    SNEAKY = 1      # 15 second delay
    POLITE = 2      # 0.4 second delay
    NORMAL = 3      # No delay
    AGGRESSIVE = 4  # No delay, parallel
    INSANE = 5      # Maximum speed

@dataclass
class DecoyConfig:
    enabled: bool = False
    decoy_ips: List[str] = field(default_factory=list)
    random_count: int = 0
    include_real_ip: bool = True
    real_ip_position: Optional[int] = None

@dataclass
class FragmentConfig:
    enabled: bool = False
    mtu: int = 8
    overlap: bool = False
    random_offset: bool = False

@dataclass
class TimingConfig:
    level: TimingLevel = TimingLevel.NORMAL
    scan_delay: float = 0.0
    max_parallelism: int = 100
    randomize_delay: bool = False

@dataclass
class IdleScanConfig:
    enabled: bool = False
    zombie_host: str = ""
    zombie_port: int = 80
    probe_port: int = 80

@dataclass
class EvasionConfig:
    profile: EvasionProfile = EvasionProfile.NONE
    techniques: List[EvasionTechnique] = field(default_factory=list)
    decoys: DecoyConfig = field(default_factory=DecoyConfig)
    fragmentation: FragmentConfig = field(default_factory=FragmentConfig)
    timing: TimingConfig = field(default_factory=TimingConfig)
    idle_scan: IdleScanConfig = field(default_factory=IdleScanConfig)
    source_port: Optional[int] = None
    random_source_port: bool = False
    common_source_port: bool = False
    ttl: Optional[int] = None
    ttl_style: str = "fixed"
    bad_checksum: bool = False
    randomize_hosts: bool = False
    data_length: int = 0
```

**Evasion Profiles:**

| Profile | Description | Techniques Enabled |
|---------|-------------|-------------------|
| NONE | No evasion | None |
| STEALTH | Balanced stealth | TTL manipulation, timing (SNEAKY), random source port |
| PARANOID | Maximum stealth | Fragmentation, decoys, timing (PARANOID), random everything |
| AGGRESSIVE | Fast with basic evasion | TTL manipulation, timing (AGGRESSIVE), common source port |

**Evasion Workflow:**

```
┌─────────────────────────────────────────────────────────────────┐
│                     Evasion Workflow                            │
└─────────────────────────────────────────────────────────────────┘

Scan Request with Evasion
         │
         ▼
┌─────────────────┐
│ Load Evasion    │
│ Configuration   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Select Active Techniques (based on profile or custom config)    │
│   - Fragmentation    - Decoy Scanning    - Source Port          │
│   - TTL Manipulation - Bad Checksum      - Timing Evasion       │
└────────────────────────────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────┐        ┌─────────────────┐
│ Scapy Available │───Yes─►│ Raw Packet Mode │
└────────┬────────┘        │ - Fragmentation │
         │                 │ - Custom TTL    │
         No                │ - Bad Checksum  │
         │                 │ - Decoys        │
         ▼                 └────────┬────────┘
┌─────────────────┐                 │
│ Fallback Mode   │                 │
│ - Timing Only   │                 │
│ - Host Ordering │                 │
└────────┬────────┘                 │
         │                          │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌─────────────────┐
         │ Apply Timing    │
         │ Delays (if any) │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ Execute Scan    │
         │ with Evasion    │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ Return Results  │
         │ + Evasion Stats │
         └─────────────────┘
```

**Decoy Scanning:**

```
Real Scanner                Target                    IDS
     │                         │                        │
     │─── SYN from Decoy1 ────►│◄──────────────────────│
     │                         │     Log: Decoy1       │
     │─── SYN from Decoy2 ────►│◄──────────────────────│
     │                         │     Log: Decoy2       │
     │─── SYN from Real IP ───►│◄──────────────────────│
     │                         │     Log: Real IP      │
     │─── SYN from Decoy3 ────►│◄──────────────────────│
     │                         │     Log: Decoy3       │
     │                         │                        │
     │   (Real IP hidden among│     IDS sees multiple │
     │    many decoy sources) │     source IPs        │
```

**Fragmentation:**

```
Original Packet               Fragmented Packets
┌────────────────────┐       ┌────────┐ ┌────────┐ ┌────────┐
│ IP Header          │   ──► │ Frag 1 │ │ Frag 2 │ │ Frag 3 │
│ TCP Header         │       │ IP+TCP │ │ Data 1 │ │ Data 2 │
│ Data               │       │ Part 1 │ │        │ │        │
└────────────────────┘       └────────┘ └────────┘ └────────┘
                                 │           │           │
                                 └───────────┴───────────┘
                                 IDS may fail to reassemble
                                 or miss signature patterns
```

**Features:**

- **Packet Fragmentation**: Split packets to evade signature detection (requires scapy)
- **Decoy Scanning**: Send packets from spoofed source IPs
- **Source Port Manipulation**: Use trusted ports (53, 80, 443) as source
- **TTL Manipulation**: Control TTL values with multiple styles
- **Bad Checksum**: Send malformed packets IDS may ignore
- **Idle/Zombie Scanning**: Use third-party hosts for stealth
- **Timing Evasion**: Slow scans with configurable delays
- **Host Randomization**: Randomize target order to avoid patterns

**CLI Integration:**

```bash
# Evasion profiles
spectrescan scan 192.168.1.1 --evasion stealth
spectrescan scan 192.168.1.1 --evasion paranoid

# Decoy scanning
spectrescan scan 192.168.1.1 -D RND:5
spectrescan scan 192.168.1.1 -D 10.0.0.1,10.0.0.2,ME

# Fragmentation
spectrescan scan 192.168.1.1 -f --mtu 8

# Source port
spectrescan scan 192.168.1.1 -g 53
spectrescan scan 192.168.1.1 --common-source-port

# TTL manipulation
spectrescan scan 192.168.1.1 --ttl 64 --ttl-style random

# Timing evasion
spectrescan scan 192.168.1.1 --scan-delay 5.0 --max-parallelism 1

# Idle scan
spectrescan scan 192.168.1.1 -sI 10.0.0.100 --zombie-port 443
```

**Requirements:**

- **Scapy** (optional): Required for advanced packet crafting
- **Root/Admin**: Required for raw socket access (fragmentation, decoys)
- Without scapy: Basic timing and ordering evasion available

**Use Cases:**

- Penetration testing against IDS/IPS-protected networks
- Stealthy reconnaissance during red team engagements
- Bypassing rate-based detection systems
- Evading signature-based intrusion detection
- Testing IDS/IPS effectiveness

---

## Data Flow

### Complete Scan Workflow

```
┌──────────────┐
│ User Request │
└──────┬───────┘
       │
       ▼
┌──────────────────────┐
│ Interface Agent      │ (CLI/TUI/GUI)
│ - Parse arguments    │
│ - Validate input     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ ScanEngine Agent     │
│ - Load configuration │
│ - Parse targets      │
│ - Parse ports        │
└──────┬───────────────┘
       │
       ├────────────────────────┐
       ▼                        ▼
┌──────────────────┐   ┌──────────────────┐
│ HostDiscovery    │   │ Direct Scan      │
│ Agent (optional) │   │ (single target)  │
│ - Ping sweep     │   └──────┬───────────┘
│ - Filter live    │          │
└──────┬───────────┘          │
       │                       │
       └───────────┬───────────┘
                   │
                   ▼
       ┌───────────────────────┐
       │ Scan Method Selection │
       └───────────┬───────────┘
                   │
       ┌───────────┼───────────┬───────────┐
       ▼           ▼           ▼           ▼
  ┌────────┐ ┌────────┐ ┌────────┐ ┌─────────┐
  │ TCP    │ │ SYN    │ │ UDP    │ │ Async   │
  │ Agent  │ │ Agent  │ │ Agent  │ │ Agent   │
  └───┬────┘ └───┬────┘ └───┬────┘ └────┬────┘
      │          │          │           │
      └──────────┴──────────┴───────────┘
                   │
                   ▼
          ┌────────────────┐
          │ Collect Results│
          └────────┬───────┘
                   │
       ┌───────────┼───────────┬───────────┐
       ▼           ▼           ▼           ▼
  ┌─────────┐ ┌──────────┐ ┌─────────┐ Results
  │ Banner  │ │ Service  │ │ OS      │    │
  │ Grab    │ │ Detect   │ │ Detect  │    │
  └────┬────┘ └────┬─────┘ └────┬────┘    │
       │           │            │          │
       └───────────┴────────────┴──────────┘
                   │
                   ▼
          ┌────────────────┐
          │ Format Results │
          └────────┬───────┘
                   │
       ┌───────────┼───────────┬───────────┐
       ▼           ▼           ▼           ▼
  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
  │ JSON   │ │ CSV    │ │ XML    │ │ HTML   │
  │ Report │ │ Report │ │ Report │ │ Report │
  └────────┘ └────────┘ └────────┘ └────────┘
```

---

## Agent Communication

### Message Passing

Agents communicate through:

1. **Direct Function Calls**: For synchronous operations
2. **Callbacks**: For asynchronous progress updates
3. **Shared Data Structures**: ScanResult, HostInfo, etc.

### Callback Interface

```python
def progress_callback(result: ScanResult) -> None:
    """
    Called for each completed port scan.
    
    Args:
        result: ScanResult with port state and details
    """
    pass
```

### Data Structures

**ScanResult:**
```python
@dataclass
class ScanResult:
    host: str
    port: int
    state: str  # "open", "closed", "filtered"
    service: Optional[str]
    banner: Optional[str]
    protocol: str
    timestamp: datetime
```

**HostInfo:**
```python
@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str]
    mac_address: Optional[str]
    os_guess: Optional[str]
    ttl: Optional[int]
    latency_ms: Optional[float]
    is_up: bool
```

**ScanConfig:**
```python
@dataclass
class ScanConfig:
    name: str
    description: str
    ports: List[int]
    scan_types: List[str]
    threads: int
    timeout: float
    rate_limit: Optional[int]
    enable_service_detection: bool
    enable_os_detection: bool
    enable_banner_grabbing: bool
    randomize: bool
    timing_template: int
```

---

## API Reference

### Core Classes

- `PortScanner`: Main scanning orchestrator
- `SynScanner`: SYN scan implementation
- `UdpScanner`: UDP scan implementation
- `AsyncScanner`: Async high-speed scanner
- `BannerGrabber`: Banner grabbing service
- `OSDetector`: Operating system detection
- `HostDiscovery`: Host discovery service
- `ProfileManager`: Scan profile management
- `HistoryManager`: Scan history tracking
- `ScanComparer`: Scan comparison and diff analysis

### Utility Functions

- `parse_target()`: Parse target specifications
- `parse_ports()`: Parse port specifications
- `get_service_name()`: Get service name for port
- `calculate_scan_time()`: Format scan duration
- `get_common_ports()`: Get list of common ports

### Report Generators

**Basic Formats:**
- `generate_json_report()`: Create JSON report
- `generate_csv_report()`: Create CSV report
- `generate_xml_report()`: Create XML report
- `generate_html_report()`: Create HTML report

**Enhanced Reporting:**
- `generate_pdf_report()`: Create PDF report with charts (requires reportlab)
- `generate_comparison_report()`: Create scan comparison reports (text/html/json)
- `generate_executive_summary()`: Create executive summary with risk scoring
- `calculate_risk_score()`: Calculate security risk score (0-100)
- `identify_critical_findings()`: Identify critical security issues

**Chart Generation:**
- `create_port_distribution_chart()`: Pie chart of port states
- `create_service_distribution_chart()`: Bar chart of top services
- `create_port_range_distribution_chart()`: Port range distribution
- `get_ascii_chart()`: Terminal-friendly ASCII charts
- `generate_all_charts()`: Generate all available charts

**Custom Templates:**
- `TemplateManager`: Manage custom report templates
- `generate_custom_report()`: Generate report from custom template
- `create_default_templates()`: Create default template examples

**Interactive Reports:**
- `generate_interactive_html_report()`: Create interactive HTML with JavaScript features

---

## Extensibility

### Adding New Scan Methods

1. Create new agent class in `core/`
2. Implement scan interface:
   ```python
   def scan_port(self, host: str, port: int) -> ScanResult
   def scan_ports(self, host: str, ports: List[int]) -> List[ScanResult]
   ```
3. Register in `PortScanner._scan()` method
4. Add CLI option
5. Update documentation

### Adding New Detection Methods

1. Create new detector in `core/`
2. Implement detection interface
3. Integrate in `PortScanner._detect_*()` methods
4. Add configuration option
5. Update reports

---

## Performance Considerations

### Threading

- **TCP Connect**: Uses ThreadPoolExecutor for concurrent connections
- **Async Scan**: Uses asyncio for maximum concurrency
- **Thread Limits**: Configurable (default 100, max 2000)

### Memory Management

- Results are accumulated in memory
- Large scans (65535 ports × multiple hosts) may use significant RAM
- Consider streaming results for very large scans

### Network Considerations

- Rate limiting prevents network congestion
- Timeout values balance speed vs accuracy
- Randomization reduces detection likelihood

---

## Conclusion

The SpectreScan agent architecture provides a **modular, scalable, and maintainable** foundation for professional port scanning. Each agent focuses on a single responsibility while communicating through well-defined interfaces, enabling:

- **Parallel execution** for maximum performance
- **Easy testing** of individual components
- **Simple extension** with new scan methods
- **Clear separation** of concerns

For more information, see the main [README.md](README.md) documentation.

---

**SpectreScan Agent Architecture**  
© 2025 BitSpectreLabs | Professional Security Tools
