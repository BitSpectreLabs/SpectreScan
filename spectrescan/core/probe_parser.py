"""
Nmap Service Probes Parser

Parses nmap-service-probes format and extracts probe definitions and match signatures.
Based on Nmap's service detection database format.

File: spectrescan/core/probe_parser.py
Author: BitSpectreLabs
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class ServiceMatch:
    """A service match signature from nmap-service-probes."""
    
    service: str
    pattern: str
    compiled_pattern: Optional[re.Pattern] = None
    version_info: Optional[str] = None
    info: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    device_type: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Compile the regex pattern."""
        if self.pattern and not self.compiled_pattern:
            try:
                # Remove the pattern delimiters and flags
                pattern_str = self.pattern
                flags = 0
                
                # Parse flags (i for case-insensitive, s for dotall, m for multiline)
                if pattern_str.endswith('i'):
                    flags |= re.IGNORECASE
                    pattern_str = pattern_str[:-1]
                if pattern_str.endswith('s'):
                    flags |= re.DOTALL
                    pattern_str = pattern_str[:-1]
                if pattern_str.endswith('m'):
                    flags |= re.MULTILINE
                    pattern_str = pattern_str[:-1]
                
                self.compiled_pattern = re.compile(pattern_str, flags)
            except re.error as e:
                logger.warning(f"Failed to compile pattern for {self.service}: {e}")
                self.compiled_pattern = None


@dataclass
class ServiceProbe:
    """A probe definition from nmap-service-probes."""
    
    protocol: str  # TCP or UDP
    name: str
    probe_string: bytes
    ports: List[int] = field(default_factory=list)
    ssl_ports: List[int] = field(default_factory=list)
    totalwaitms: int = 5000
    tcpwrappedms: int = 3000
    rarity: int = 1
    fallback: Optional[str] = None
    matches: List[ServiceMatch] = field(default_factory=list)
    softmatches: List[ServiceMatch] = field(default_factory=list)


@dataclass
class ServiceSignature:
    """High-level service signature for matching."""
    
    name: str
    ports: List[int]
    protocol: str
    patterns: List[str]
    version_pattern: Optional[str] = None
    cpe: Optional[str] = None
    confidence: int = 80
    probes: List[bytes] = field(default_factory=list)


class ProbeParser:
    """Parser for nmap-service-probes format."""
    
    def __init__(self):
        self.probes: List[ServiceProbe] = []
        self.exclude_ports: Dict[str, List[int]] = {"tcp": [], "udp": []}
        
    def parse_file(self, filepath: Path) -> List[ServiceProbe]:
        """
        Parse nmap-service-probes file.
        
        Args:
            filepath: Path to nmap-service-probes file
            
        Returns:
            List of ServiceProbe objects
        """
        if not filepath.exists():
            logger.error(f"Probe file not found: {filepath}")
            return []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return self.parse_content(content)
    
    def parse_content(self, content: str) -> List[ServiceProbe]:
        """
        Parse nmap-service-probes content.
        
        Args:
            content: File content as string
            
        Returns:
            List of ServiceProbe objects
        """
        lines = content.split('\n')
        current_probe = None
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            try:
                # Probe directive
                if line.startswith('Probe '):
                    if current_probe:
                        self.probes.append(current_probe)
                    current_probe = self._parse_probe_line(line)
                
                # Match directive
                elif line.startswith('match ') and current_probe:
                    match = self._parse_match_line(line)
                    if match:
                        current_probe.matches.append(match)
                
                # Softmatch directive
                elif line.startswith('softmatch ') and current_probe:
                    match = self._parse_match_line(line, soft=True)
                    if match:
                        current_probe.softmatches.append(match)
                
                # Ports directive
                elif line.startswith('ports ') and current_probe:
                    current_probe.ports = self._parse_ports(line[6:])
                
                # SSLPorts directive
                elif line.startswith('sslports ') and current_probe:
                    current_probe.ssl_ports = self._parse_ports(line[9:])
                
                # TotalWaitMS directive
                elif line.startswith('totalwaitms ') and current_probe:
                    try:
                        current_probe.totalwaitms = int(line[12:])
                    except ValueError:
                        pass
                
                # TCPWrappedMS directive
                elif line.startswith('tcpwrappedms ') and current_probe:
                    try:
                        current_probe.tcpwrappedms = int(line[13:])
                    except ValueError:
                        pass
                
                # Rarity directive
                elif line.startswith('rarity ') and current_probe:
                    try:
                        current_probe.rarity = int(line[7:])
                    except ValueError:
                        pass
                
                # Fallback directive
                elif line.startswith('fallback ') and current_probe:
                    current_probe.fallback = line[9:].strip()
                
                # Exclude directive
                elif line.startswith('Exclude '):
                    self._parse_exclude_line(line)
            
            except Exception as e:
                logger.debug(f"Error parsing line {line_num}: {e}")
                continue
        
        # Add the last probe
        if current_probe:
            self.probes.append(current_probe)
        
        logger.info(f"Parsed {len(self.probes)} probes from nmap-service-probes")
        return self.probes
    
    def _parse_probe_line(self, line: str) -> ServiceProbe:
        """Parse a Probe directive line."""
        # Format: Probe <protocol> <probename> <probestring>
        parts = line.split(None, 3)
        if len(parts) < 4:
            raise ValueError(f"Invalid Probe line: {line}")
        
        protocol = parts[1]  # TCP or UDP
        name = parts[2]
        probe_string = self._decode_probe_string(parts[3])
        
        return ServiceProbe(
            protocol=protocol,
            name=name,
            probe_string=probe_string
        )
    
    def _parse_match_line(self, line: str, soft: bool = False) -> Optional[ServiceMatch]:
        """Parse a match or softmatch directive line."""
        # Format: match <service> <pattern> [<versioninfo>]
        # or: softmatch <service> <pattern>
        
        prefix = 'softmatch ' if soft else 'match '
        line = line[len(prefix):]
        
        # Split by space, but respect quoted strings
        parts = self._split_match_line(line)
        if len(parts) < 2:
            return None
        
        service = parts[0]
        pattern = parts[1]
        
        match = ServiceMatch(
            service=service,
            pattern=pattern
        )
        
        # Parse optional version info flags
        for part in parts[2:]:
            if part.startswith('v/'):
                match.version_info = part[2:].rstrip('/')
            elif part.startswith('i/'):
                match.info = part[2:].rstrip('/')
            elif part.startswith('h/'):
                match.hostname = part[2:].rstrip('/')
            elif part.startswith('o/'):
                match.os = part[2:].rstrip('/')
            elif part.startswith('d/'):
                match.device_type = part[2:].rstrip('/')
            elif part.startswith('cpe:/'):
                match.cpe.append(part)
        
        return match
    
    def _split_match_line(self, line: str) -> List[str]:
        """Split match line respecting quoted strings and delimiters."""
        parts = []
        current = ""
        in_pattern = False
        delimiter = None
        
        i = 0
        while i < len(line):
            char = line[i]
            
            if not in_pattern:
                if char in ' \t':
                    if current:
                        parts.append(current)
                        current = ""
                elif char in 'm/':
                    # Start of pattern
                    in_pattern = True
                    if i + 1 < len(line):
                        delimiter = line[i + 1]
                        i += 1  # Skip the m
                    current = char
                else:
                    current += char
            else:
                current += char
                if char == delimiter and (i == 0 or line[i-1] != '\\'):
                    # End of pattern (check for flags)
                    while i + 1 < len(line) and line[i + 1] in 'ism':
                        i += 1
                        current += line[i]
                    parts.append(current)
                    current = ""
                    in_pattern = False
                    delimiter = None
            
            i += 1
        
        if current:
            parts.append(current)
        
        return parts
    
    def _parse_ports(self, ports_str: str) -> List[int]:
        """Parse port list (e.g., '22,80,443,8080-8090')."""
        ports = []
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = part.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        return ports
    
    def _parse_exclude_line(self, line: str):
        """Parse an Exclude directive line."""
        # Format: Exclude <protocol> <ports>
        parts = line.split(None, 2)
        if len(parts) < 3:
            return
        
        protocol = parts[1].lower()
        if protocol in self.exclude_ports:
            self.exclude_ports[protocol].extend(self._parse_ports(parts[2]))
    
    def _decode_probe_string(self, probe_str: str) -> bytes:
        """
        Decode probe string from nmap format.
        Format: q|<data>|
        """
        if not probe_str.startswith('q|') or not probe_str.endswith('|'):
            return probe_str.encode('latin-1')
        
        # Remove q| and trailing |
        data = probe_str[2:-1]
        
        # Decode escape sequences
        result = []
        i = 0
        while i < len(data):
            if data[i] == '\\' and i + 1 < len(data):
                next_char = data[i + 1]
                if next_char == 'r':
                    result.append(ord('\r'))
                elif next_char == 'n':
                    result.append(ord('\n'))
                elif next_char == 't':
                    result.append(ord('\t'))
                elif next_char == '0':
                    result.append(0)
                elif next_char == '\\':
                    result.append(ord('\\'))
                elif next_char == 'x' and i + 3 < len(data):
                    # Hex escape
                    try:
                        hex_val = int(data[i+2:i+4], 16)
                        result.append(hex_val)
                        i += 2
                    except ValueError:
                        result.append(ord(next_char))
                else:
                    result.append(ord(next_char))
                i += 2
            else:
                result.append(ord(data[i]))
                i += 1
        
        return bytes(result)
    
    def get_probes_for_port(self, port: int, protocol: str = "TCP") -> List[ServiceProbe]:
        """
        Get probes that are appropriate for a given port.
        
        Args:
            port: Port number
            protocol: "TCP" or "UDP"
            
        Returns:
            List of ServiceProbe objects sorted by rarity
        """
        matching_probes = []
        
        for probe in self.probes:
            if probe.protocol.upper() != protocol.upper():
                continue
            
            # Check if port is in probe's port list (or no port restriction)
            if not probe.ports or port in probe.ports:
                matching_probes.append(probe)
        
        # Sort by rarity (lower rarity = more common = try first)
        matching_probes.sort(key=lambda p: p.rarity)
        
        return matching_probes
    
    def get_all_services(self) -> Dict[str, List[ServiceMatch]]:
        """
        Get all unique services and their matches.
        
        Returns:
            Dictionary mapping service names to list of matches
        """
        services = {}
        
        for probe in self.probes:
            for match in probe.matches + probe.softmatches:
                if match.service not in services:
                    services[match.service] = []
                services[match.service].append(match)
        
        return services
    
    def create_signatures(self) -> List[ServiceSignature]:
        """
        Create simplified ServiceSignature objects from parsed probes.
        
        Returns:
            List of ServiceSignature objects
        """
        signatures = []
        services = self.get_all_services()
        
        for service_name, matches in services.items():
            # Collect unique patterns and ports
            patterns = []
            ports = set()
            cpes = []
            probes = []
            
            for match in matches:
                if match.pattern:
                    patterns.append(match.pattern)
                if match.cpe:
                    cpes.extend(match.cpe)
            
            # Find probes that have this service
            for probe in self.probes:
                for match in probe.matches:
                    if match.service == service_name:
                        if probe.ports:
                            ports.update(probe.ports)
                        if probe.probe_string not in probes:
                            probes.append(probe.probe_string)
            
            signature = ServiceSignature(
                name=service_name,
                ports=sorted(list(ports)) if ports else [],
                protocol="tcp",
                patterns=patterns[:10],  # Limit to top 10 patterns
                cpe=cpes[0] if cpes else None,
                probes=probes[:5]  # Limit to top 5 probes
            )
            signatures.append(signature)
        
        return signatures


def parse_nmap_service_probes(filepath: Path) -> Tuple[List[ServiceProbe], List[ServiceSignature]]:
    """
    Parse nmap-service-probes file and return probes and signatures.
    
    Args:
        filepath: Path to nmap-service-probes file
        
    Returns:
        Tuple of (probes list, signatures list)
    """
    parser = ProbeParser()
    probes = parser.parse_file(filepath)
    signatures = parser.create_signatures()
    
    logger.info(f"Created {len(signatures)} service signatures from {len(probes)} probes")
    
    return probes, signatures
