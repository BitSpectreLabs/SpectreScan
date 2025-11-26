"""
Utility functions for SpectreScan
by BitSpectreLabs
"""

import ipaddress
import socket
import re
from typing import List, Tuple, Optional, Union
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class ScanResult:
    """Result of a single port scan."""
    host: str
    port: int
    state: str  # "open", "closed", "filtered"
    service: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "tcp"
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None
    is_up: bool = True


def parse_target(target: Union[str, List[str]]) -> List[str]:
    """
    Parse target specification into list of IP addresses.
    
    Supports multiple input formats:
    - Single IP: "192.168.1.1"
    - CIDR notation: "192.168.1.0/24"
    - IP range: "192.168.1.1-254"
    - Hostname: "example.com"
    - Comma-separated: "192.168.1.1,192.168.1.2,example.com"
    - List of targets: ["192.168.1.1", "example.com"]
    
    Args:
        target: Target specification (string or list of strings)
        
    Returns:
        List of IP addresses/hostnames
        
    Raises:
        ValueError: If target specification is invalid
        
    Examples:
        >>> parse_target("192.168.1.1")
        ['192.168.1.1']
        >>> parse_target("192.168.1.0/30")
        ['192.168.1.1', '192.168.1.2']
        >>> parse_target("192.168.1.1,example.com")
        ['192.168.1.1', '93.184.216.34']
        >>> parse_target(["192.168.1.1", "192.168.1.2"])
        ['192.168.1.1', '192.168.1.2']
    """
    all_targets = []
    
    # Handle list input
    if isinstance(target, list):
        for t in target:
            all_targets.extend(parse_target(t))
        return all_targets
    
    # Handle comma-separated targets
    if ',' in target:
        for t in target.split(','):
            t = t.strip()
            if t:
                all_targets.extend(parse_target(t))
        return all_targets
    
    # Check if it's a CIDR notation
    if '/' in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass
    
    # Check if it's a range (192.168.1.1-254)
    if '-' in target and '.' in target:
        parts = target.split('.')
        if len(parts) == 4 and '-' in parts[3]:
            base = '.'.join(parts[:3])
            range_part = parts[3].split('-')
            if len(range_part) == 2:
                try:
                    start_num = int(range_part[0])
                    end_num = int(range_part[1])
                    if start_num < 0 or end_num > 255 or start_num > end_num:
                        raise ValueError(f"Invalid IP range: {target}")
                    return [f"{base}.{i}" for i in range(start_num, end_num + 1)]
                except ValueError as e:
                    raise ValueError(f"Invalid IP range: {target}") from e
    
    # Try as hostname or single IP
    try:
        # Try to resolve as hostname
        ip = socket.gethostbyname(target)
        return [ip]
    except socket.gaierror:
        # If resolution fails, try as IP
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            raise ValueError(f"Invalid target specification: {target}")


def parse_targets_from_file(filepath: Union[str, Path]) -> List[str]:
    """
    Parse targets from a file.
    
    Supports:
    - Plain text files with one target per line
    - CSV files with targets in first column
    - Comments (lines starting with #)
    - Empty lines (ignored)
    - All target formats supported by parse_target()
    
    Args:
        filepath: Path to file containing targets
        
    Returns:
        List of IP addresses/hostnames
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file format is invalid
        
    Examples:
        File content (targets.txt):
        ```
        # Web servers
        192.168.1.1
        192.168.1.10-20
        webserver.example.com
        
        # Database subnet
        10.0.0.0/28
        ```
    """
    filepath = Path(filepath)
    
    if not filepath.exists():
        raise FileNotFoundError(f"Target file not found: {filepath}")
    
    if not filepath.is_file():
        raise ValueError(f"Not a file: {filepath}")
    
    all_targets = []
    line_number = 0
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line_number += 1
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Handle CSV format (take first column)
                if ',' in line and not _looks_like_target_list(line):
                    line = line.split(',')[0].strip()
                
                # Parse target
                try:
                    targets = parse_target(line)
                    all_targets.extend(targets)
                except ValueError as e:
                    # Add line context to error
                    raise ValueError(f"Line {line_number}: {e}") from e
    
    except UnicodeDecodeError:
        raise ValueError(f"File encoding error: {filepath}. Use UTF-8 encoding.")
    
    if not all_targets:
        raise ValueError(f"No valid targets found in file: {filepath}")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in all_targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
    
    return unique_targets


def _looks_like_target_list(line: str) -> bool:
    """
    Check if line looks like comma-separated targets vs CSV data.
    
    Args:
        line: Line to check
        
    Returns:
        True if looks like target list, False if CSV with other data
    """
    # If all comma-separated parts look like IP/hostname, it's a target list
    parts = [p.strip() for p in line.split(',')]
    
    # Check if most parts look like valid targets
    target_like = 0
    for part in parts[:5]:  # Check first 5 parts
        if not part:
            continue
        # Simple heuristic: contains dots or looks like hostname
        if '.' in part or re.match(r'^[a-zA-Z0-9\-]+$', part):
            target_like += 1
    
    # If more than half look like targets, treat as target list
    return target_like > len(parts[:5]) // 2


def parse_ports(port_spec: str) -> List[int]:
    """
    Parse port specification into list of ports.
    
    Supports:
    - Single port: 80
    - Range: 1-1024
    - Comma-separated: 80,443,8080
    - Mixed: 22,80-100,443
    
    Args:
        port_spec: Port specification string
        
    Returns:
        List of port numbers
    """
    ports = set()
    
    for part in port_spec.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            try:
                start_port = int(start)
                end_port = int(end)
                if start_port < 1 or end_port > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                ports.update(range(start_port, end_port + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range: {part}") from e
        else:
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                ports.add(port)
            except ValueError as e:
                raise ValueError(f"Invalid port: {part}") from e
    
    return sorted(list(ports))


def get_service_name(port: int, protocol: str = "tcp") -> Optional[str]:
    """
    Get service name for a given port.
    
    Args:
        port: Port number
        protocol: Protocol (tcp/udp)
        
    Returns:
        Service name or None
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return None


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """
    Check if string is a valid hostname.
    
    Args:
        hostname: Hostname to validate
        
    Returns:
        True if valid hostname, False otherwise
    """
    if not hostname or len(hostname) > 255:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith("."):
        hostname = hostname[:-1]
    
    # Check for empty string after removing dot
    if not hostname:
        return False
    
    # Check for consecutive dots
    if ".." in hostname:
        return False
    
    # Hostname pattern: alphanumeric, hyphens, dots
    # Each label must start and end with alphanumeric
    pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(pattern.match(hostname))


def format_banner(banner: bytes) -> str:
    """
    Format banner for display.
    
    Args:
        banner: Raw banner bytes
        
    Returns:
        Formatted banner string
    """
    try:
        # Try UTF-8 first
        text = banner.decode('utf-8', errors='ignore')
    except Exception:
        # Fallback to latin-1
        text = banner.decode('latin-1', errors='ignore')
    
    # Remove non-printable characters
    text = ''.join(char for char in text if char.isprintable() or char in '\n\r\t')
    
    # Truncate if too long
    if len(text) > 500:
        text = text[:500] + "..."
    
    return text.strip()


def calculate_scan_time(start_time, end_time=None) -> str:
    """
    Calculate and format scan duration.
    
    Can be called with:
    - Two datetime objects: calculate_scan_time(start_dt, end_dt)
    - Single float (seconds): calculate_scan_time(65.5)
    
    Args:
        start_time: Scan start time (datetime) or duration in seconds (float)
        end_time: Scan end time (datetime), optional
        
    Returns:
        Formatted duration string
    """
    # Handle float input (seconds)
    if isinstance(start_time, (int, float)):
        total_seconds = float(start_time)
    # Handle datetime input
    elif isinstance(start_time, datetime) and end_time is not None:
        duration = end_time - start_time
        total_seconds = duration.total_seconds()
    else:
        raise ValueError("Invalid arguments: provide either float seconds or two datetime objects")
    
    if total_seconds < 60:
        return f"{total_seconds:.2f} seconds"
    elif total_seconds < 3600:
        minutes = int(total_seconds // 60)
        seconds = int(total_seconds % 60)
        return f"{minutes}m {seconds}s"
    else:
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def get_common_ports(count: int = 100) -> List[int]:
    """
    Get list of most common ports.
    
    Args:
        count: Number of ports to return (100 or 1000)
        
    Returns:
        List of port numbers
    """
    # Top 100 most common ports
    top_100 = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        20, 69, 161, 162, 389, 636, 1433, 1521, 2049, 3690,
        5432, 5800, 5900, 6379, 8000, 8443, 8888, 9090, 9200, 9300,
        137, 138, 445, 514, 587, 1080, 1194, 2082, 2083, 2086,
        2087, 2095, 2096, 2222, 3128, 3333, 4443, 4444, 4567, 5000,
        5001, 5060, 5061, 5222, 5269, 5353, 5555, 5601, 5672, 5900,
        6000, 6001, 6379, 6660, 6661, 6662, 6663, 6664, 6665, 6666,
        6667, 6668, 6669, 7000, 7001, 7777, 8008, 8009, 8081, 8082,
        8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092
    ]
    
    if count <= 100:
        return top_100[:count]
    
    # Extend to top 1000 if needed
    top_1000 = top_100 + [i for i in range(1, 1024) if i not in top_100]
    remaining = 1000 - len(top_1000)
    top_1000.extend([i for i in range(1024, 10000) if i not in top_1000][:remaining])
    
    return sorted(top_1000[:count])


def validate_target(target: str) -> bool:
    """
    Validate target specification.
    
    Args:
        target: Target specification
        
    Returns:
        True if valid, False otherwise
    """
    try:
        parse_target(target)
        return True
    except (ValueError, socket.gaierror):
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file writing.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    return filename


def get_timestamp() -> str:
    """Get formatted timestamp for reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_timestamp_filename() -> str:
    """Get formatted timestamp for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")
