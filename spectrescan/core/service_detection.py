"""
Service Detection Engine

Advanced service detection using probe-based fingerprinting and signature matching.
Inspired by Nmap's service detection (-sV) functionality.

File: spectrescan/core/service_detection.py
Author: BitSpectreLabs
"""

import asyncio
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from pathlib import Path
import logging

from .probe_parser import (
    ProbeParser, ServiceProbe, ServiceMatch, ServiceSignature,
    parse_nmap_service_probes
)

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Detected service information."""
    
    name: str
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    device_type: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    confidence: int = 0
    banner: Optional[str] = None


class ServiceDetector:
    """Advanced service detection engine."""
    
    def __init__(
        self,
        probes_file: Optional[Path] = None,
        timeout: float = 5.0,
        max_probes: int = 7,
        intensity: int = 7
    ):
        """
        Initialize service detector.
        
        Args:
            probes_file: Path to nmap-service-probes file
            timeout: Timeout for probe responses
            max_probes: Maximum number of probes to send
            intensity: Detection intensity (1-9, like Nmap)
        """
        self.timeout = timeout
        self.max_probes = max_probes
        self.intensity = intensity
        
        self.parser = ProbeParser()
        self.probes: List[ServiceProbe] = []
        self.signatures: List[ServiceSignature] = []
        
        # Load probes if file provided
        if probes_file and probes_file.exists():
            self.load_probes(probes_file)
        
        # Cache for service matches
        self._match_cache: Dict[str, ServiceInfo] = {}
    
    def load_probes(self, filepath: Path) -> None:
        """
        Load service probes from file.
        
        Args:
            filepath: Path to nmap-service-probes file
        """
        logger.info(f"Loading service probes from {filepath}")
        self.probes, self.signatures = parse_nmap_service_probes(filepath)
        logger.info(f"Loaded {len(self.probes)} probes and {len(self.signatures)} signatures")
    
    async def detect_service(
        self,
        host: str,
        port: int,
        protocol: str = "TCP",
        initial_banner: Optional[str] = None
    ) -> ServiceInfo:
        """
        Detect service on a port using probe-based detection.
        
        Args:
            host: Target host
            port: Target port
            protocol: "TCP" or "UDP"
            initial_banner: Banner grabbed during port scan (optional)
            
        Returns:
            ServiceInfo object with detection results
        """
        # Try matching initial banner first (NULL probe response)
        if initial_banner:
            service = self._match_banner(initial_banner, port, protocol)
            if service and service.confidence > 70:
                service.banner = initial_banner
                return service
        
        # Get appropriate probes for this port
        probes = self.parser.get_probes_for_port(port, protocol)
        
        # Limit probes based on intensity
        max_probes_to_try = min(self.max_probes, len(probes), self.intensity)
        probes = probes[:max_probes_to_try]
        
        # Try each probe
        for probe in probes:
            try:
                response = await self._send_probe(host, port, probe, protocol)
                if response:
                    service = self._match_response(response, probe, port)
                    if service and service.confidence > 50:
                        service.banner = response[:200]  # Store first 200 chars
                        return service
            except Exception as e:
                logger.debug(f"Probe {probe.name} failed on {host}:{port} - {e}")
                continue
        
        # If we have an initial banner but no high-confidence match, return it
        if initial_banner:
            service = self._match_banner(initial_banner, port, protocol)
            if service:
                service.banner = initial_banner
                return service
        
        # Fall back to port-based detection
        return self._detect_by_port(port, protocol)
    
    async def _send_probe(
        self,
        host: str,
        port: int,
        probe: ServiceProbe,
        protocol: str
    ) -> Optional[str]:
        """
        Send a probe to a service and get response.
        
        Args:
            host: Target host
            port: Target port
            probe: ServiceProbe to send
            protocol: "TCP" or "UDP"
            
        Returns:
            Response string or None
        """
        if protocol.upper() == "TCP":
            return await self._send_tcp_probe(host, port, probe)
        else:
            return await self._send_udp_probe(host, port, probe)
    
    async def _send_tcp_probe(
        self,
        host: str,
        port: int,
        probe: ServiceProbe
    ) -> Optional[str]:
        """Send TCP probe and get response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Send probe data
            writer.write(probe.probe_string)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=probe.totalwaitms / 1000.0
            )
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode('latin-1', errors='ignore')
        
        except Exception as e:
            logger.debug(f"TCP probe failed: {e}")
            return None
    
    async def _send_udp_probe(
        self,
        host: str,
        port: int,
        probe: ServiceProbe
    ) -> Optional[str]:
        """Send UDP probe and get response."""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send probe
            sock.sendto(probe.probe_string, (host, port))
            
            # Receive response
            data, _ = sock.recvfrom(4096)
            sock.close()
            
            return data.decode('latin-1', errors='ignore')
        
        except Exception as e:
            logger.debug(f"UDP probe failed: {e}")
            return None
    
    def _match_banner(
        self,
        banner: str,
        port: int,
        protocol: str
    ) -> Optional[ServiceInfo]:
        """
        Match banner against service signatures.
        
        Args:
            banner: Banner text
            port: Port number
            protocol: "TCP" or "UDP"
            
        Returns:
            ServiceInfo or None
        """
        # Check cache
        cache_key = f"{banner[:100]}:{port}"
        if cache_key in self._match_cache:
            return self._match_cache[cache_key]
        
        best_match = None
        best_confidence = 0
        
        # Try all probes' matches
        for probe in self.probes:
            if probe.protocol.upper() != protocol.upper():
                continue
            
            # Check matches
            for match in probe.matches:
                if match.compiled_pattern:
                    regex_match = match.compiled_pattern.search(banner)
                    if regex_match:
                        service = self._extract_service_info(match, regex_match)
                        service.confidence = 90  # High confidence for match
                        
                        if service.confidence > best_confidence:
                            best_match = service
                            best_confidence = service.confidence
            
            # Check soft matches if no hard match
            if not best_match:
                for match in probe.softmatches:
                    if match.compiled_pattern:
                        regex_match = match.compiled_pattern.search(banner)
                        if regex_match:
                            service = self._extract_service_info(match, regex_match)
                            service.confidence = 60  # Lower confidence for softmatch
                            
                            if service.confidence > best_confidence:
                                best_match = service
                                best_confidence = service.confidence
        
        # Cache result
        if best_match:
            self._match_cache[cache_key] = best_match
        
        return best_match
    
    def _match_response(
        self,
        response: str,
        probe: ServiceProbe,
        port: int
    ) -> Optional[ServiceInfo]:
        """
        Match probe response against signatures.
        
        Args:
            response: Response from probe
            probe: ServiceProbe that was sent
            port: Port number
            
        Returns:
            ServiceInfo or None
        """
        return self._match_banner(response, port, probe.protocol)
    
    def _extract_service_info(
        self,
        match: ServiceMatch,
        regex_match: re.Match
    ) -> ServiceInfo:
        """
        Extract service information from a match.
        
        Args:
            match: ServiceMatch object
            regex_match: Regex match object
            
        Returns:
            ServiceInfo object
        """
        service = ServiceInfo(name=match.service)
        
        # Extract version info using captured groups
        if match.version_info and regex_match.groups():
            try:
                version = self._substitute_captures(match.version_info, regex_match)
                service.version = version
            except Exception as e:
                logger.debug(f"Version extraction failed: {e}")
        
        # Extract other info
        if match.info and regex_match.groups():
            try:
                service.extra_info = self._substitute_captures(match.info, regex_match)
            except Exception:
                pass
        
        if match.hostname:
            service.hostname = match.hostname
        
        if match.os:
            service.os = match.os
        
        if match.device_type:
            service.device_type = match.device_type
        
        if match.cpe:
            service.cpe = match.cpe
        
        return service
    
    def _substitute_captures(self, template: str, regex_match: re.Match) -> str:
        """
        Substitute $1, $2, etc. with regex capture groups.
        
        Args:
            template: Template string with $1, $2, etc.
            regex_match: Regex match with captured groups
            
        Returns:
            String with substitutions
        """
        result = template
        
        # Replace $n with captured group n
        for i, group in enumerate(regex_match.groups(), 1):
            if group:
                result = result.replace(f'${i}', group)
        
        return result
    
    def _detect_by_port(self, port: int, protocol: str) -> ServiceInfo:
        """
        Fall back to simple port-based service detection.
        
        Args:
            port: Port number
            protocol: "TCP" or "UDP"
            
        Returns:
            ServiceInfo with port-based guess
        """
        # Common port mappings
        port_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "domain",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            3389: "ms-wbt-server",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            9200: "elasticsearch",
            27017: "mongodb",
        }
        
        service_name = port_services.get(port, "unknown")
        
        return ServiceInfo(
            name=service_name,
            confidence=30  # Low confidence for port-based detection
        )
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get detection statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_probes": len(self.probes),
            "total_signatures": len(self.signatures),
            "cached_matches": len(self._match_cache),
            "unique_services": len(self.parser.get_all_services())
        }


async def detect_service_async(
    host: str,
    port: int,
    protocol: str = "TCP",
    banner: Optional[str] = None,
    detector: Optional[ServiceDetector] = None,
    intensity: int = 7
) -> ServiceInfo:
    """
    Convenience function for async service detection.
    
    Args:
        host: Target host
        port: Target port
        protocol: "TCP" or "UDP"
        banner: Initial banner (optional)
        detector: Existing ServiceDetector (optional)
        intensity: Detection intensity (1-9)
        
    Returns:
        ServiceInfo object
    """
    if detector is None:
        detector = ServiceDetector(intensity=intensity)
    
    return await detector.detect_service(host, port, protocol, banner)
