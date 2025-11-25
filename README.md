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

- **Host Discovery** - ICMP ping, TCP ping, ARP scanning
- **Service Detection** - Automatic service/version identification
- **Banner Grabbing** - Capture service banners for fingerprinting
- **OS Detection** - TTL-based and TCP fingerprinting
- **Rate Limiting** - Control scan speed to avoid detection
- **Timing Templates** - Paranoid to Insane (0-5)
- **Randomized Scanning** - Randomize target and port order
- **Graceful Error Handling** - Robust exception management

### Multiple Interfaces

- **CLI** - Powerful command-line interface with Typer
- **TUI** - Beautiful terminal UI with Textual framework
- **GUI** - User-friendly tkinter graphical interface

### Professional Reporting

- **JSON** - Structured data export
- **CSV** - Spreadsheet-compatible format
- **XML** - Standardized markup format
- **HTML** - Professional branded reports with logo and summary

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

#### Complete Example

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
- Keyboard shortcuts (`s` = start, `x` = stop, `c` = clear, `q` = quit)
- Dark/light theme toggle (`d`)
- Statistics dashboard

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
