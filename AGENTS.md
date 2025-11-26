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
│                     SpectreScan Agent System                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────┐                                            │
│  │ Interface Agent │ ◄──── User Input (CLI/TUI/GUI)            │
│  └────────┬────────┘                                            │
│           │                                                       │
│           ▼                                                       │
│  ┌─────────────────┐                                            │
│  │ ScanEngine      │ ◄──── Orchestrates scanning workflow      │
│  │ Agent           │                                            │
│  └────────┬────────┘                                            │
│           │                                                       │
│           ├─────────┬──────────┬─────────────┬─────────────┐   │
│           ▼         ▼          ▼             ▼             ▼   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐│
│  │HostDisc  │ │TCPScan   │ │SYNScan   │ │UDPScan   │ │AsyncScan││
│  │Agent     │ │Agent     │ │Agent     │ │Agent     │ │Agent    ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘│
│       │            │            │            │            │     │
│       └────────────┴────────────┴────────────┴────────────┘     │
│                                 │                                │
│                                 ▼                                │
│                    ┌─────────────────────┐                      │
│                    │ Detection Agents    │                      │
│                    ├─────────────────────┤                      │
│           ┌────────┤ BannerGrab Agent    │                      │
│           │        │ ServiceDetect Agent │                      │
│           │        │ OSDetect Agent      │                      │
│           │        └──────────┬──────────┘                      │
│           │                   │                                  │
│           ▼                   ▼                                  │
│  ┌─────────────────┐ ┌─────────────────┐                       │
│  │ ReportGenerator │ │ OutputFormatter │                       │
│  │ Agent           │ │ Agent           │                       │
│  └─────────────────┘ └─────────────────┘                       │
│                                                                   │
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

**Responsibility:** Identify services running on open ports

**Input:**
- ScanResult objects with open ports

**Output:**
- Updated ScanResults with service names

**API:**

```python
def get_service_name(port: int, protocol: str) -> Optional[str]
def detect_service_version(banner: Optional[str]) -> Optional[str]
```

**Process:**

```
1. Check port number against known services database
2. Analyze banner for service signatures
3. Extract version information if available
4. Return service name and version
```

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
