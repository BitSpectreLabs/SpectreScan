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

### Utility Functions

- `parse_target()`: Parse target specifications
- `parse_ports()`: Parse port specifications
- `get_service_name()`: Get service name for port
- `calculate_scan_time()`: Format scan duration
- `get_common_ports()`: Get list of common ports

### Report Generators

- `generate_json_report()`: Create JSON report
- `generate_csv_report()`: Create CSV report
- `generate_xml_report()`: Create XML report
- `generate_html_report()`: Create HTML report

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
