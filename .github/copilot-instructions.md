# SpectreScan - GitHub Copilot Instructions

<p align="center">
  <img src="https://skillicons.dev/icons?i=python,linux,windows,apple" alt="Platform Support" height="30"/>
</p>

## Project Overview

**SpectreScan** is a professional-grade port scanning toolkit developed by **BitSpectreLabs**. It provides multiple interfaces (CLI, TUI, GUI) for network security assessment with features including TCP/SYN/UDP scanning, service detection, OS fingerprinting, and comprehensive reporting.

---

## <img src="https://cdn.simpleicons.org/files/4285F4" width="16" height="16"/> Complete Project Structure

```
spectrescan/
|-- __init__.py              # Package init, exports PortScanner, ScanPreset
|-- __main__.py              # Entry point for `python -m spectrescan`
|
|-- cli/                     # Command-line interface
|   |-- __init__.py
|   |-- main.py              # Typer-based CLI with all commands (2300+ lines)
|   +-- completions.py       # Shell completion generator (250 lines)
|
|-- core/                    # Core scanning functionality (40+ modules)
|   |-- __init__.py
|   |-- scanner.py           # Main PortScanner class (505 lines)
|   |-- async_scan.py        # AsyncScanner with timing templates (515 lines)
|   |-- syn_scan.py          # SynScanner using scapy (252 lines)
|   |-- udp_scan.py          # UdpScanner with service probes (197 lines)
|   |-- banners.py           # BannerGrabber for service ID (322 lines)
|   |-- os_detect.py         # OSDetector TTL/window fingerprint (331 lines)
|   |-- host_discovery.py    # HostDiscovery ping/TCP/ARP sweep (308 lines)
|   |-- profiles.py          # ScanProfile, ProfileManager (229 lines)
|   |-- history.py           # ScanHistoryEntry, HistoryManager (304 lines)
|   |-- comparison.py        # ScanComparer, PortDifference (325 lines)
|   |-- presets.py           # ScanPreset enum, ScanConfig (293 lines)
|   |-- utils.py             # ScanResult, HostInfo, parse functions (484 lines)
|   |-- service_detection.py # ServiceDetector with probes (455 lines)
|   |-- timing_engine.py     # TimingTemplate T0-T5 levels (291 lines)
|   |-- connection_pool.py   # Async connection pooling (331 lines)
|   |-- signature_cache.py   # Lazy-loaded signature DB cache (269 lines)
|   |-- probe_parser.py      # Nmap service probes parser (480 lines)
|   |-- error_recovery.py    # Retry logic, graceful degradation (456 lines)
|   |-- memory_optimizer.py  # Stream results, GC management (376 lines)
|   |-- network_monitor.py   # Latency/packet loss detection (521 lines)
|   |-- nmap_output.py       # Nmap-compatible output formats (320 lines)
|   |-- version_detection.py # Version extraction engine (375 lines)
|   |-- app_fingerprinting.py# Web app/CMS detection (499 lines)
|   |-- banner_parser.py     # Tech stack detection (480 lines)
|   |-- database_updater.py  # Auto-update signatures from GitHub (301 lines)
|   |-- detailed_reports.py  # Security findings reports (389 lines)
|   |-- os_detection_enhanced.py # Advanced TCP/IP fingerprinting (441 lines)
|   |-- progress_tracker.py  # Real-time ETA/throughput (310 lines)
|   |-- resource_limiter.py  # CPU/memory/network limits (433 lines)
|   |-- scripting_engine.py  # Python scripting (NSE alternative) (453 lines)
|   |-- script_manager.py    # -sC/--script flags handler (277 lines)
|   |-- version_mode.py      # -sV version detection mode (360 lines)
|   |-- ssl_analyzer.py      # SSL/TLS certificate and cipher analysis (600 lines)
|   |-- cve_matcher.py       # CVE vulnerability matching (450 lines)
|   |-- checkpoint.py        # Scan resume/checkpoint support (400 lines)
|   |-- config.py            # TOML configuration management (500 lines)
|   |-- dns_enum.py          # DNS enumeration and subdomain discovery (450 lines)
|   +-- nse_engine.py        # NSE Lua script engine (920 lines)
|
|-- nse_scripts/             # Bundled NSE Lua scripts
|   |-- __init__.py
|   |-- http-title.nse       # HTTP page title detection
|   |-- ssl-cert.nse         # SSL certificate information
|   |-- ssh-hostkey.nse      # SSH host key fingerprints
|   |-- ftp-anon.nse         # FTP anonymous login check
|   |-- smb-os-discovery.nse # SMB OS discovery
|   |-- http-headers.nse     # HTTP response headers
|   |-- http-methods.nse     # HTTP allowed methods
|   |-- mysql-info.nse       # MySQL server information
|   |-- redis-info.nse       # Redis server information
|   +-- smtp-commands.nse    # SMTP supported commands
|
|-- api/                     # REST API server (FastAPI)
|   |-- __init__.py
|   |-- main.py              # FastAPI application (400 lines)
|   |-- auth.py              # JWT authentication (300 lines)
|   |-- routes/              # API route handlers
|   +-- websocket.py         # WebSocket support (200 lines)
|
|-- data/                    # Service signature databases
|   |-- cpe-dictionary.json       # 200+ CPE entries (719 lines)
|   |-- service-signatures.json   # 150+ service signatures (1,085 lines)
|   |-- version-patterns.json     # 100+ version patterns (526 lines)
|   +-- nmap-service-probes       # Nmap-compatible probes (530 lines)
|
|-- reports/                 # Report generation (9 modules)
|   |-- __init__.py          # JSON/CSV/XML generators
|   |-- html_report.py       # Static HTML reports (514 lines)
|   |-- interactive_html.py  # Interactive HTML with JS (492 lines)
|   |-- pdf_report.py        # PDF with charts (281 lines)
|   |-- charts.py            # ReportLab chart generation (395 lines)
|   |-- comparison_report.py # Scan diff reports (500 lines)
|   |-- executive_summary.py # Risk scoring reports (363 lines)
|   |-- templates.py         # Jinja2 template manager (342 lines)
|   +-- markdown_report.py   # Markdown report generator (250 lines)
|
|-- tui/                     # Terminal UI (Textual-based)
|   |-- __init__.py
|   |-- app.py               # Main SpectreScanTUI class (473 lines)
|   |-- screens/
|   |   +-- __init__.py      # ProfileSelectionScreen, HistorySelectionScreen
|   +-- widgets/
|       |-- __init__.py
|       |-- results_table.py # DataTable for scan results
|       |-- progress.py      # Progress bar widget
|       +-- logs.py          # Log display widget
|
|-- gui/                     # Graphical UI (Tkinter-based)
|   |-- __init__.py
|   +-- app.py               # SpectreScanGUI class (915 lines)
|
+-- tests/                   # Unit tests (pytest) - 50+ test files, 1650+ tests
    |-- __init__.py
    |-- test_scanner.py
    |-- test_profiles.py
    |-- test_history.py
    |-- test_comparison.py
    |-- test_ssl_analyzer.py     # SSL/TLS analysis tests
    |-- test_cve_matcher.py      # CVE matching tests
    |-- test_checkpoint.py       # Scan resume tests
    |-- test_config.py           # Configuration tests
    |-- test_dns_enum.py         # DNS enumeration tests
    |-- test_shell_completion.py # Shell completion tests
    |-- test_nse_engine.py       # NSE engine tests (63 tests)
    |-- test_nse_cli.py          # NSE CLI tests (20 tests)
    +-- ... (50+ test files total)
```

---

## <img src="https://cdn.simpleicons.org/task/4CAF50" width="16" height="16"/> Critical Development Rules

### 1. Every Feature Must Have Tests
- **MANDATORY**: Every new feature, bug fix, or enhancement MUST include corresponding unit tests
- Tests go in `spectrescan/tests/` directory
- Follow naming convention: `test_<feature_name>.py`
- Minimum coverage target: 80% for new code

### 2. No New Markdown Files
- **NEVER** create new `.md` files for fixes, feature completion, or documentation updates
- Update existing files: `README.md`, `AGENTS.md`, or this `copilot-instructions.md`
- Keep documentation consolidated

### 3. Version Management
- **Current Version**: v2.0.0
- **ALWAYS** update `pyproject.toml` when starting a new version
- Follow semantic versioning: `MAJOR.MINOR.PATCH`
- Update version in:
  - `pyproject.toml` (primary source)
  - `spectrescan/__init__.py`

### 4. No Emojis in Code or Documentation
- Use GitHub README icon packs instead
- Example: `<img src="https://cdn.simpleicons.org/python/3776AB" width="16" height="16"/>`
- Or use Skill Icons: `<img src="https://skillicons.dev/icons?i=python" height="20"/>`

### 5. No Em Dashes
- Use regular dashes `-` or colons `:` instead of em dashes
- Wrong: `feature — description`
- Correct: `feature - description` or `feature: description`

---

## <img src="https://cdn.simpleicons.org/python/3776AB" width="16" height="16"/> Key Data Structures

### ScanResult (spectrescan/core/utils.py)
```python
@dataclass
class ScanResult:
    host: str
    port: int
    state: str  # "open", "closed", "filtered"
    service: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "tcp"
    timestamp: Optional[datetime] = None
```

### HostInfo (spectrescan/core/utils.py)
```python
@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None
    is_up: bool = True
```

### ScanProfile (spectrescan/core/profiles.py)
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

---

## <img src="https://cdn.simpleicons.org/eslint/4B32C3" width="16" height="16"/> Coding Conventions

### General
- Python 3.8+ compatibility required
- Type hints on all function signatures
- Docstrings for all public functions/classes (Google style)
- Author attribution: `by BitSpectreLabs` in module docstrings

### Imports Order
```python
# Standard library first
import asyncio
from typing import List, Optional, Dict

# Third-party
from textual.app import App
from rich.text import Text

# Local
from spectrescan.core.utils import ScanResult
from spectrescan.core.scanner import PortScanner
```

### Error Handling
- Use specific exceptions where possible
- Log errors before raising
- Provide user-friendly error messages in UI

---

## <img src="https://cdn.simpleicons.org/gnometerminal/241F31" width="16" height="16"/> TUI Development (Textual)

### Key Patterns

1. **Thread-safe UI updates**: Always use `self.call_from_thread()` when updating UI from background threads:
```python
self.call_from_thread(self.results_table.add_result, result)
```

2. **DataTable RowKey handling**: When accessing row keys from DataTable, the key is a `RowKey` object:
```python
row_key = list(table.rows.keys())[table.cursor_row]
entry_id = row_key.value if hasattr(row_key, 'value') else str(row_key)
```

3. **Rich Text in DataTable**: Use `rich.text.Text` objects for colored text in DataTable cells:
```python
from rich.text import Text
state_text = Text("open", style="green bold")
self.add_row(host, port, state_text)
```

4. **Widget refresh**: Call `self.refresh()` after modifying widget content to ensure visibility.

5. **Thread-safe UI updates with Messages**: Use custom Message classes and `post_message()` for thread-safe UI updates from background workers:
```python
from textual.message import Message

class ScanResultMessage(Message):
    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__()

# In worker thread:
self.post_message(ScanResultMessage(result))

# Message handler (runs in main thread):
def on_scan_result_message(self, message: ScanResultMessage) -> None:
    self.results_table.add_result(message.result)
```

6. **CSS Layout for TabbedContent**: Use `height: 1fr` (fractional units) instead of `height: 100%` for proper space distribution in nested containers:
```css
TabbedContent {
    height: 1fr;
}

TabPane {
    height: 1fr;
}

ResultsTable {
    height: 1fr;
    width: 100%;
}
```

### Common TUI Issues

| Issue | Solution |
|-------|----------|
| RowKey not subscriptable | Access `.value` property |
| Results not visible | Use `height: 1fr` in CSS, remove large logos |
| UI not updating from thread | Use `post_message()` with custom Message classes |
| DataTable empty | Ensure columns added in `on_mount()` |
| Progress works but results don't | Use Message-based pattern instead of `call_from_thread` for complex widgets |

---

## <img src="https://cdn.simpleicons.org/pytest/0A9EDC" width="16" height="16"/> Testing Requirements

### Running Tests
```bash
# All tests
pytest spectrescan/tests/

# Specific test file
pytest spectrescan/tests/test_scanner.py

# With coverage
pytest --cov=spectrescan --cov-report=html
```

### Test File Naming
- `test_scanner.py` - Scanner functionality tests
- `test_profiles.py` - Profile management tests
- `test_history.py` - History tracking tests
- `test_tui_*.py` - TUI component tests

### Test Template
```python
"""
Tests for <feature_name>
by BitSpectreLabs
"""

import pytest
from spectrescan.core.<module> import <Class>


class Test<FeatureName>:
    """Test suite for <feature_name>."""
    
    def test_basic_functionality(self):
        """Test basic <feature> operation."""
        # Arrange
        instance = <Class>(config)
        
        # Act
        result = instance.method()
        
        # Assert
        assert result is not None
        assert len(result) > 0
    
    def test_edge_case(self):
        """Test <feature> with edge case."""
        pass
    
    def test_error_handling(self):
        """Test <feature> error handling."""
        with pytest.raises(ValueError):
            instance.method(invalid_input)
```

---

## <img src="https://cdn.simpleicons.org/windowsterminal/4D4D4D" width="16" height="16"/> CLI Commands

```bash
# Basic scan
spectrescan 192.168.1.1

# With ports
spectrescan 192.168.1.1 -p 1-1000

# TUI mode
spectrescan --tui

# GUI mode
spectrescan --gui

# Profile management
spectrescan profile list
spectrescan profile create

# History
spectrescan history list
spectrescan history compare <scan1> <scan2>

# Output formats
spectrescan 192.168.1.1 -o results.json --format json
spectrescan 192.168.1.1 -o results.html --format html

# v2.0.0 Commands
spectrescan ssl example.com                    # SSL/TLS analysis
spectrescan cve search apache 2.4.49           # CVE lookup
spectrescan dns example.com                    # DNS enumeration
spectrescan api --port 8000                    # Start REST API server
spectrescan resume <checkpoint-id>             # Resume interrupted scan
spectrescan config show                        # Show configuration
spectrescan completion install bash            # Install shell completion

# v2.1.0 NSE Commands
spectrescan script list                        # List available scripts
spectrescan script categories                  # Show script categories
spectrescan script info http-title             # Script information
spectrescan script run http-title -t 192.168.1.1 -p 80  # Run script

# v2.1.0 Distributed Scanning Commands
spectrescan cluster init                       # Initialize master node
spectrescan cluster status                     # Show cluster status
spectrescan cluster workers                    # List registered workers
spectrescan cluster worker --master 192.168.1.100:5000  # Start worker
spectrescan cluster scan 10.0.0.0/8            # Distributed scan

# v2.1.0 Web Dashboard Commands
spectrescan web                                # Start dashboard (port 8080)
spectrescan web --port 9000                    # Custom port
spectrescan web --no-browser                   # Don't auto-open browser
spectrescan web --debug                        # Enable debug mode
```

---

## <img src="https://cdn.simpleicons.org/pypi/3775A9" width="16" height="16"/> Dependencies

### Core
- Python 3.11+
- Standard library: socket, asyncio, ipaddress, dataclasses

### Optional
| Package | Purpose |
|---------|---------|
| Scapy | SYN scanning (requires root) |
| Textual | TUI interface |
| Tkinter | GUI interface |
| ReportLab | PDF reports |
| Jinja2 | Custom templates |
| Typer | CLI framework |
| FastAPI | REST API server |
| dnspython | DNS enumeration |
| Lupa | NSE Lua script execution |
| Redis | Distributed scanning message queue |
| Celery | Distributed task queue |
| uvicorn | ASGI server for web dashboard |

---

## <img src="https://cdn.simpleicons.org/folders/F9A825" width="16" height="16"/> Configuration Files

- `~/.spectrescan/config.toml` - Main configuration file
- `~/.spectrescan/profiles/` - Saved scan profiles (JSON)
- `~/.spectrescan/history/` - Scan history entries (JSON)
- `~/.spectrescan/templates/` - Custom report templates
- `~/.spectrescan/checkpoints/` - Scan checkpoints for resume

---

## <img src="https://cdn.simpleicons.org/git/F05032" width="16" height="16"/> Version History

| Version | Status | Notes |
|---------|--------|-------|
| v2.1.0 | In Progress | NSE Lua script engine, distributed scanning, web dashboard |
| v2.0.0 | Current | SSL/TLS, CVE matching, REST API, DNS enum, checkpoints |
| v1.2.0 | Stable | Service detection, profiles, history |
| v1.1.0 | Stable | TUI/GUI interfaces |
| v1.0.0 | Stable | Initial release |

---

## <img src="https://cdn.simpleicons.org/addthis/FF6550" width="16" height="16"/> Adding New Features

### Adding a New Scan Type
1. Create scanner class in `spectrescan/core/`
2. Implement `scan_port()` and `scan_ports()` methods
3. Register in `PortScanner._scan()` method
4. Add CLI option in `spectrescan/cli/main.py`
5. Update presets in `spectrescan/core/presets.py`
6. **Add tests in `spectrescan/tests/test_<scan_type>.py`**

### Adding a New Report Format
1. Create generator in `spectrescan/reports/`
2. Implement `generate_X_report(results, output_path, summary)` function
3. Add CLI option and format handler
4. Update `__init__.py` exports
5. **Add tests for the new report format**

### Adding a New TUI Widget
1. Create widget class in `spectrescan/tui/widgets/`
2. Inherit from appropriate Textual widget
3. Implement `compose()` for layout
4. Register in `spectrescan/tui/app.py`
5. **Add tests for widget behavior**

---

## <img src="https://cdn.simpleicons.org/files/4285F4" width="16" height="16"/> Complete Module Documentation

### Core Modules (spectrescan/core/)

#### scanner.py - Main Port Scanner (505 lines)
**Purpose:** Primary scanning orchestrator that coordinates all scan types
**Key Classes:**
- `PortScanner`: Main class for port scanning operations
**Key Methods:**
- `scan(target, ports, callback)`: Execute scan on target
- `_tcp_scan()`: TCP connect scan implementation
- `_syn_scan()`: SYN scan wrapper (requires scapy)
- `_udp_scan()`: UDP scan wrapper
- `get_open_ports()`: Retrieve open ports after scan
- `get_scan_summary()`: Get scan statistics

#### async_scan.py - Async High-Speed Scanner (515 lines)
**Purpose:** Concurrent TCP scanning using asyncio for maximum speed
**Key Classes:**
- `AsyncScanner`: High-performance async port scanner
**Key Features:**
- Supports 2000+ concurrent connections
- Rate limiting support
- Timing templates (T0-T5 like nmap)
- Connection pooling integration

#### syn_scan.py - SYN Scanner (252 lines)
**Purpose:** TCP SYN (half-open) scanning using raw packets
**Key Classes:**
- `SynScanner`: Stealth scanning with scapy
**Requirements:**
- Scapy library
- Root/Administrator privileges
- Raw socket support
**Response Analysis:**
- SYN-ACK (0x12) = Open
- RST-ACK (0x14) = Closed
- No response = Filtered

#### udp_scan.py - UDP Scanner (197 lines)
**Purpose:** UDP port scanning with service-specific probes
**Key Classes:**
- `UdpScanner`: UDP port detection
**Key Features:**
- Service-specific probe packets
- ICMP unreachable detection for closed ports
- Handles open|filtered ambiguity

#### banners.py - Banner Grabber (322 lines)
**Purpose:** Capture service banners for fingerprinting
**Key Classes:**
- `BannerGrabber`: Banner capture and service identification
**Supported Services:**
- HTTP/HTTPS, FTP, SSH, SMTP, POP3, IMAP
- MySQL, PostgreSQL, Redis, MongoDB
- And many more...

#### os_detect.py - OS Detection (331 lines)
**Purpose:** Operating system fingerprinting
**Key Classes:**
- `OSDetector`: TTL and TCP window fingerprinting
**Detection Methods:**
- TTL analysis (64=Linux, 128=Windows, 255=Network)
- TCP window size analysis
- Banner hint extraction

#### host_discovery.py - Host Discovery (308 lines)
**Purpose:** Identify live hosts before port scanning
**Key Classes:**
- `HostDiscovery`: Network host detection
**Methods:**
- ICMP ping sweep
- TCP ping (common ports)
- ARP sweep (local network)

#### profiles.py - Profile Manager (229 lines)
**Purpose:** Save and reuse scan configurations
**Key Classes:**
- `ScanProfile`: Profile data structure
- `ProfileManager`: CRUD operations for profiles
**Storage:** `~/.spectrescan/profiles/` (JSON)

#### history.py - History Manager (304 lines)
**Purpose:** Track and review previous scans
**Key Classes:**
- `ScanHistoryEntry`: History record data structure
- `HistoryManager`: History CRUD and search
**Features:**
- Unique scan IDs (MD5-based)
- Filter by target/type
- Full-text search
- Aggregate statistics

#### comparison.py - Scan Comparison (325 lines)
**Purpose:** Compare scans to identify changes
**Key Classes:**
- `PortDifference`: Single port change record
- `ScanComparison`: Full comparison result
- `ScanComparer`: Comparison logic
**Change Categories:**
- Newly opened ports
- Newly closed ports
- Newly filtered ports
- Service version changes

#### presets.py - Scan Presets (293 lines)
**Purpose:** Predefined scan configurations
**Key Classes:**
- `ScanPreset`: Enum of preset names
- `ScanConfig`: Configuration data structure
**Available Presets:**
- QUICK: Top 100 ports
- TOP_PORTS: Top 1000 ports
- FULL: All 65535 ports
- STEALTH: SYN scan with rate limiting
- SAFE: Non-intrusive conservative scan
- AGGRESSIVE: All features enabled

#### utils.py - Utilities (484 lines)
**Purpose:** Common data structures and helper functions
**Key Classes:**
- `ScanResult`: Port scan result dataclass
- `HostInfo`: Host information dataclass
**Key Functions:**
- `parse_ports()`: Parse port specifications
- `parse_target()`: Parse IP/CIDR/hostname
- `parse_targets_from_file()`: Load targets from file
- `get_common_ports()`: Return common port list
- `get_timestamp()`: Formatted timestamp

#### service_detection.py - Service Detection (455 lines)
**Purpose:** Identify services using probe-based detection
**Key Classes:**
- `ServiceInfo`: Detection result dataclass
- `ServiceDetector`: Probe-based service identification
**Features:**
- Nmap-style probes
- Confidence scoring (0-100%)
- CPE mapping
- Version extraction

#### timing_engine.py - Timing Templates (291 lines)
**Purpose:** Nmap-style timing configuration
**Key Classes:**
- `TimingLevel`: Enum (T0-T5)
- `TimingTemplate`: Template configuration
**Levels:**
- T0 PARANOID: 1 concurrent, 300s timeout
- T1 SNEAKY: 5 concurrent, 60s timeout
- T2 POLITE: 10 concurrent, 30s timeout
- T3 NORMAL: 100 concurrent, 10s timeout
- T4 AGGRESSIVE: 500 concurrent, 5s timeout
- T5 INSANE: 2000 concurrent, 0.5s timeout

#### connection_pool.py - Connection Pooling (331 lines)
**Purpose:** Reusable TCP connection management
**Key Classes:**
- `PooledConnection`: Connection wrapper
- `ConnectionPool`: Async connection pool
**Features:**
- Connection reuse to reduce overhead
- Max connections per host
- Connection expiration
- Health checking

#### signature_cache.py - Signature Cache (269 lines)
**Purpose:** Lazy loading of signature databases
**Key Classes:**
- `SignatureCache`: Singleton pattern cache
**Benefits:**
- Improves startup time
- Only loads when needed
- LRU caching for regex compilation

#### probe_parser.py - Probe Parser (480 lines)
**Purpose:** Parse nmap-service-probes format
**Key Classes:**
- `ServiceMatch`: Match signature data
- `ServiceProbe`: Probe definition
- `ProbeParser`: File parser
**Parses:**
- Probe directives
- Match/softmatch patterns
- Ports and rarity

#### error_recovery.py - Error Recovery (456 lines)
**Purpose:** Graceful error handling and retry logic
**Key Classes:**
- `ErrorSeverity`: Enum (recoverable/degraded/fatal)
- `ErrorContext`: Error information
- `RetryStrategy`: Exponential backoff
**Features:**
- Configurable retry attempts
- Exponential backoff with jitter
- Partial result preservation

#### memory_optimizer.py - Memory Management (376 lines)
**Purpose:** Handle large scans efficiently
**Key Classes:**
- `MemoryStats`: Usage statistics
- `MemoryMonitor`: Usage tracking
- `StreamingResultWriter`: Disk streaming
**Features:**
- Memory limit enforcement
- Forced garbage collection
- Streaming results to disk
- Large scan support (100K+ ports)

#### network_monitor.py - Network Monitoring (521 lines)
**Purpose:** Detect network conditions
**Key Classes:**
- `NetworkMetrics`: Performance data
- `LatencyMonitor`: Latency tracking
- `PacketLossDetector`: Loss detection
**Features:**
- Latency sliding window
- Packet loss percentage
- Jitter calculation
- High latency alerts

#### nmap_output.py - Nmap Output (320 lines)
**Purpose:** Nmap-compatible output formats
**Key Classes:**
- `NmapOutputFormatter`: Format generator
**Formats:**
- Greppable (.gnmap)
- XML (.xml)
- Normal (.nmap)

#### version_detection.py - Version Extraction (375 lines)
**Purpose:** Extract version info from banners
**Key Classes:**
- `VersionInfo`: Version data structure
- `VersionExtractor`: Pattern matching
**Patterns:**
- HTTP headers (Server, X-Powered-By)
- Service banners
- Protocol handshakes

#### app_fingerprinting.py - App Detection (499 lines)
**Purpose:** Web application fingerprinting
**Key Classes:**
- `ApplicationInfo`: App metadata
- `ApplicationFingerprinter`: Detection engine
**Detects:**
- CMS: WordPress, Drupal, Joomla
- E-commerce: Magento, Shopify, WooCommerce
- Frameworks: Laravel, Django, Express
- Admin panels: phpMyAdmin, Adminer

#### banner_parser.py - Technology Stack (480 lines)
**Purpose:** Parse banners for tech stack
**Key Classes:**
- `TechnologyStack`: Detected stack
- `ParsedBanner`: Comprehensive result
- `BannerParser`: Detection engine
**Detects:**
- Web servers, frameworks, languages
- Databases, CMS, WAF, CDN
- Load balancers, OS hints

#### database_updater.py - Auto Updates (301 lines)
**Purpose:** Update signature databases
**Key Classes:**
- `DatabaseUpdater`: Update manager
**Features:**
- Download from GitHub
- Hash-based change detection
- Automatic backups
- Fallback support

#### detailed_reports.py - Security Reports (389 lines)
**Purpose:** Comprehensive scan reports
**Key Classes:**
- `SecurityFinding`: Finding record
- `TechnologyReport`: Tech stack summary
- `DetailedReportGenerator`: Report generator
**Includes:**
- Vulnerability patterns
- Security recommendations
- Risk assessment

#### os_detection_enhanced.py - Advanced OS Detection (441 lines)
**Purpose:** Enhanced TCP/IP fingerprinting
**Key Classes:**
- `OSFamily`: Enum (Linux/Windows/Unix/macOS)
- `OSFingerprint`: Detailed fingerprint
- `EnhancedOSDetector`: Multi-technique detector
**Techniques:**
- TTL analysis
- Window size signatures
- TCP options fingerprinting
- IP ID sequence analysis

#### progress_tracker.py - Progress Tracking (310 lines)
**Purpose:** Real-time scan progress
**Key Classes:**
- `ProgressStats`: Statistics dataclass
- `ProgressTracker`: Tracker implementation
**Features:**
- ETA calculation
- Throughput stats
- Progress bar generation
- Callback support

#### resource_limiter.py - Resource Limits (433 lines)
**Purpose:** CPU/memory/network limiting
**Key Classes:**
- `ResourceLimits`: Configuration
- `CPULimiter`: CPU throttling
- `NetworkThrottler`: Bandwidth limiting
- `FileDescriptorManager`: FD management
**Features:**
- Configurable limits
- Automatic throttling
- Usage statistics

#### scripting_engine.py - Script Engine (453 lines)
**Purpose:** Python-based scripting (NSE alternative)
**Key Classes:**
- `ScriptCategory`: Enum (discovery/vuln/exploit...)
- `ScriptInfo`: Script metadata
- `ScriptResult`: Execution result
- `Script`: Base script class
- `ScriptEngine`: Script loader/executor
**Categories:**
- discovery, version, vuln
- exploit, auth, brute
- default, safe, intrusive

#### script_manager.py - Script Manager (277 lines)
**Purpose:** Handle -sC and --script flags
**Key Classes:**
- `ScriptOptions`: Parsed options
- `ScriptManager`: Execution manager
**Supports:**
- Single script: `--script http-title`
- Wildcards: `--script "http-*"`
- Categories: `--script discovery`
- All: `--script all`

#### version_mode.py - Version Mode (360 lines)
**Purpose:** Nmap-style -sV version detection
**Key Classes:**
- `VersionScanResult`: Detection result
- `VersionScanner`: Intensity-based scanner
**Intensity Levels (0-9):**
- 0: No version detection
- 1: NULL probe only
- 7: All probes (default)
- 9: Aggressive mode

---

### CLI Module (spectrescan/cli/)

#### main.py - CLI Application (736 lines)
**Purpose:** Typer-based command line interface
**Framework:** Typer with Rich console
**Commands:**
- `scan`: Main scanning command
- `profile`: Profile management subcommands
- `history`: History subcommands
- `compare`: Scan comparison
- `presets`: List available presets
- `version`: Show version
- `tui`: Launch TUI
- `gui`: Launch GUI
**Options:**
- Target specification (IP/CIDR/hostname)
- Port ranges (-p)
- Scan types (--tcp, --syn, --udp, --async)
- Presets (--quick, --top-ports, --full, --stealth)
- Detection (--service-detection, --os-detection, --banner-grab)
- Output formats (--json, --csv, --xml, --html, --pdf)
- Timing templates (-T0 to -T5)

---

### Reports Module (spectrescan/reports/)

#### html_report.py - HTML Reports (514 lines)
**Purpose:** Professional branded HTML reports
**Features:**
- Dark theme with BitSpectreLabs branding
- Summary statistics dashboard
- Interactive tables
- Host information section
- Responsive design

#### interactive_html.py - Interactive HTML (492 lines)
**Purpose:** HTML with JavaScript features
**Features:**
- Live search/filter
- Sortable columns
- State filtering (open/closed/filtered)
- Dark mode toggle
- Copy to clipboard
- Expandable details
- No external dependencies

#### pdf_report.py - PDF Reports (281 lines)
**Purpose:** Professional PDF with charts
**Requirements:** ReportLab
**Features:**
- Executive summary
- Port status charts
- Service distribution graphs
- Host information tables

#### charts.py - Chart Generation (395 lines)
**Purpose:** Visual chart creation
**Requirements:** ReportLab
**Chart Types:**
- Pie: Port state distribution
- Horizontal Bar: Service distribution
- Bar: Port range distribution
- ASCII: Terminal-friendly charts

#### comparison_report.py - Diff Reports (500 lines)
**Purpose:** Scan comparison reports
**Formats:**
- Text: Terminal-friendly ASCII
- HTML: Styled with color coding
- JSON: Machine-readable

#### executive_summary.py - Risk Scoring (363 lines)
**Purpose:** High-level security assessment
**Features:**
- Risk scoring (0-100)
- Risk levels (Critical/High/Medium/Low)
- Critical findings identification
- Security recommendations
**Scoring Factors:**
- Attack surface (open port count)
- High-risk services
- Vulnerable ports
- Database exposure

#### templates.py - Template Manager (342 lines)
**Purpose:** Custom report templates
**Requirements:** Jinja2
**Features:**
- Jinja2 template engine
- Template library management
- Multiple format support
- Custom variables
- Default templates

---

### TUI Module (spectrescan/tui/)

#### app.py - TUI Application (473 lines)
**Purpose:** Textual-based terminal interface
**Key Classes:**
- `SpectreScanTUI`: Main application
**Bindings:**
- q: Quit
- s: Start scan
- x: Stop scan
- c: Clear results
- d: Toggle dark mode
- p: Open profiles
- h: Open history
**Features:**
- Real-time results table
- Progress bar
- Logs panel
- Multi-target support
- Profile integration

#### screens/__init__.py - Modal Screens
**Classes:**
- `ProfileSelectionScreen`: Profile picker
- `HistorySelectionScreen`: History browser
**Key Pattern:** Access RowKey.value for IDs

#### widgets/results_table.py - Results Table
**Purpose:** DataTable for scan results
**Features:**
- Color-coded states
- Rich Text formatting
- Auto-refresh

#### widgets/progress.py - Progress Widget
**Purpose:** Scan progress display

#### widgets/logs.py - Logs Widget
**Purpose:** Log message display

---

### GUI Module (spectrescan/gui/)

#### app.py - GUI Application (915 lines)
**Purpose:** Tkinter-based graphical interface
**Key Classes:**
- `SpectreScanGUI`: Main application
**Features:**
- Vercel-inspired dark theme
- Scrollable configuration panel
- Tabbed results area
- Export buttons
- Profile manager dialog
- History browser dialog
- Multi-target file import

---

### Data Files (spectrescan/data/)

#### cpe-dictionary.json (719 lines)
**Purpose:** CPE identifier mapping
**Content:** 200+ CPE entries across 10 categories
**Categories:**
- web_servers, databases, app_servers
- network_services, dev_tools, containers
- monitoring, messaging, storage, security

#### service-signatures.json (1,085 lines)
**Purpose:** Service detection signatures
**Content:** 150+ service signatures
**Fields:**
- name, ports, protocol
- patterns (regex), version_pattern
- cpe, confidence, category

#### version-patterns.json (526 lines)
**Purpose:** Version extraction patterns
**Content:** 100+ service patterns
**Includes:**
- Generic fallback patterns
- OS version patterns
- Service-specific extractors

#### nmap-service-probes (530 lines)
**Purpose:** Active service probing
**Format:** Nmap probe syntax
**Content:** 100+ probes covering:
- Web, databases, mail
- Containers, DevOps, monitoring
- Remote access, file transfer
- Security, IoT, network services

---

### Test Files (spectrescan/tests/)

| File | Purpose |
|------|---------|
| test_scanner.py | Core scanner functionality |
| test_profiles.py | Profile management |
| test_history.py | History tracking |
| test_comparison.py | Scan comparison |
| test_enhanced_features.py | Advanced features |
| test_error_recovery.py | Error handling |
| test_memory_optimizer.py | Memory management |
| test_multi_target.py | Multi-target scanning |
| test_network_monitor.py | Network monitoring |
| test_reporting.py | Report generation |
| test_resource_limiter.py | Resource limits |
| test_service_detection.py | Service detection |
| test_version_mode.py | Version detection |
| test_ssl_analyzer.py | SSL/TLS analysis |
| test_cve_matcher.py | CVE matching |
| test_checkpoint.py | Scan resume |
| test_config.py | Configuration |
| test_dns_enum.py | DNS enumeration |
| test_nse_engine.py | NSE Lua engine |
| test_nse_cli.py | NSE CLI commands |

---

## <img src="https://cdn.simpleicons.org/readme/018EF5" width="16" height="16"/> Related Documentation

- [AGENTS.md](../AGENTS.md) - Detailed agent architecture documentation
- [README.md](../README.md) - User documentation

---

**SpectreScan** - Professional Port Scanner by BitSpectreLabs  
License: MIT | Current Version: v2.0.0
