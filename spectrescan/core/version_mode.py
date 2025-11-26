"""
Version Detection Mode (-sV)
Implements Nmap-style -sV service version detection with intensity levels.

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Callable
from pathlib import Path

from .service_detection import ServiceDetector, ServiceInfo
from .banner_parser import BannerParser
from .version_detection import VersionExtractor

logger = logging.getLogger(__name__)


@dataclass
class VersionScanResult:
    """Result from version detection scan."""
    host: str
    port: int
    protocol: str
    state: str
    service: Optional[str]
    version: Optional[str]
    product: Optional[str]
    extra_info: Optional[str]
    hostname: Optional[str]
    os: Optional[str]
    device_type: Optional[str]
    cpe: List[str]
    confidence: int
    method: str  # "probe", "banner", "port", "unknown"
    detection_time: float


class VersionScanner:
    """
    Service version detection scanner with configurable intensity.
    
    Intensity levels (like Nmap):
    - 0: No version detection (just port scanning)
    - 1: Light probing (NULL probe only)
    - 2-6: Increasing probe intensity
    - 7: All probes
    - 8: Try all combinations
    - 9: Aggressive - slowest but most complete
    """
    
    def __init__(
        self,
        intensity: int = 7,
        timeout: float = 10.0,
        max_probes: int = 7,
        enable_banner_grabbing: bool = True,
        enable_application_fingerprinting: bool = True,
        threads: int = 100
    ):
        """
        Initialize version scanner.
        
        Args:
            intensity: Detection intensity (0-9, default 7)
            timeout: Probe timeout in seconds
            max_probes: Maximum probes per port
            enable_banner_grabbing: Enable initial banner grab
            enable_application_fingerprinting: Enable app detection
            threads: Number of concurrent scans
        """
        self.intensity = max(0, min(9, intensity))
        self.timeout = timeout
        self.max_probes = max_probes
        self.enable_banner_grabbing = enable_banner_grabbing
        self.enable_application_fingerprinting = enable_application_fingerprinting
        self.threads = threads
        
        # Adjust timeouts based on intensity
        self._adjust_settings()
        
        # Initialize detection engines
        self.service_detector = ServiceDetector(
            timeout=self.timeout,
            max_probes=self.max_probes,
            intensity=self.intensity
        )
        self.banner_parser = BannerParser()
        self.version_extractor = VersionExtractor()
        
        logger.info(f"VersionScanner initialized with intensity={self.intensity}, timeout={self.timeout}s")
    
    def _adjust_settings(self):
        """Adjust scanner settings based on intensity level."""
        if self.intensity == 0:
            self.enable_banner_grabbing = False
            self.max_probes = 0
        elif self.intensity == 1:
            self.max_probes = 1  # NULL probe only
            self.timeout = 5.0
        elif self.intensity <= 3:
            self.max_probes = 2
            self.timeout = 7.0
        elif self.intensity <= 6:
            self.max_probes = 5
            self.timeout = 10.0
        elif self.intensity == 7:
            self.max_probes = 7
            self.timeout = 15.0
        elif self.intensity == 8:
            self.max_probes = 10
            self.timeout = 20.0
        else:  # intensity == 9
            self.max_probes = 15
            self.timeout = 30.0
    
    async def scan_port(
        self,
        host: str,
        port: int,
        protocol: str = "TCP",
        initial_banner: Optional[str] = None
    ) -> VersionScanResult:
        """
        Scan a single port for service version.
        
        Args:
            host: Target host
            port: Target port
            protocol: "TCP" or "UDP"
            initial_banner: Pre-captured banner (optional)
        
        Returns:
            VersionScanResult with detected service info
        """
        import time
        start_time = time.time()
        
        try:
            # Intensity 0: No version detection
            if self.intensity == 0:
                return VersionScanResult(
                    host=host,
                    port=port,
                    protocol=protocol,
                    state="open",
                    service=None,
                    version=None,
                    product=None,
                    extra_info=None,
                    hostname=None,
                    os=None,
                    device_type=None,
                    cpe=[],
                    confidence=0,
                    method="none",
                    detection_time=time.time() - start_time
                )
            
            # Use service detector
            service_info = await self.service_detector.detect_service(
                host=host,
                port=port,
                protocol=protocol,
                initial_banner=initial_banner
            )
            
            detection_time = time.time() - start_time
            
            return VersionScanResult(
                host=host,
                port=port,
                protocol=protocol,
                state="open",
                service=service_info.name,
                version=service_info.version,
                product=service_info.product,
                extra_info=service_info.extra_info,
                hostname=service_info.hostname,
                os=service_info.os,
                device_type=service_info.device_type,
                cpe=service_info.cpe,
                confidence=service_info.confidence,
                method=self._determine_method(service_info),
                detection_time=detection_time
            )
            
        except Exception as e:
            logger.error(f"Error scanning {host}:{port} - {e}")
            return VersionScanResult(
                host=host,
                port=port,
                protocol=protocol,
                state="open",
                service=None,
                version=None,
                product=None,
                extra_info=None,
                hostname=None,
                os=None,
                device_type=None,
                cpe=[],
                confidence=0,
                method="error",
                detection_time=time.time() - start_time
            )
    
    def _determine_method(self, service_info: ServiceInfo) -> str:
        """Determine detection method from confidence level."""
        if service_info.confidence >= 90:
            return "probe"
        elif service_info.confidence >= 60:
            return "banner"
        elif service_info.confidence >= 30:
            return "port"
        else:
            return "unknown"
    
    async def scan_ports(
        self,
        host: str,
        ports: List[int],
        protocol: str = "TCP",
        callback: Optional[Callable[[VersionScanResult], None]] = None
    ) -> List[VersionScanResult]:
        """
        Scan multiple ports for service versions.
        
        Args:
            host: Target host
            ports: List of ports to scan
            protocol: "TCP" or "UDP"
            callback: Optional callback for each result
        
        Returns:
            List of VersionScanResult objects
        """
        results = []
        semaphore = asyncio.Semaphore(self.threads)
        
        async def scan_with_semaphore(port: int):
            async with semaphore:
                result = await self.scan_port(host, port, protocol)
                if callback:
                    callback(result)
                return result
        
        tasks = [scan_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        return results
    
    def get_intensity_description(self) -> str:
        """Get human-readable description of current intensity level."""
        descriptions = {
            0: "Disabled - No version detection",
            1: "Light - Banner grabbing only",
            2: "Default - Basic probing",
            3: "Moderate - Common probes",
            4: "Normal - Standard probes",
            5: "Thorough - Extended probes",
            6: "Comprehensive - Most probes",
            7: "All - All standard probes",
            8: "Aggressive - All probes + combinations",
            9: "Insane - Exhaustive detection (slowest)"
        }
        return descriptions.get(self.intensity, "Unknown")
    
    def get_settings_summary(self) -> Dict[str, Any]:
        """Get summary of current scanner settings."""
        return {
            "intensity": self.intensity,
            "intensity_description": self.get_intensity_description(),
            "timeout": self.timeout,
            "max_probes": self.max_probes,
            "banner_grabbing": self.enable_banner_grabbing,
            "app_fingerprinting": self.enable_application_fingerprinting,
            "threads": self.threads
        }


def format_version_result(result: VersionScanResult, verbose: bool = False) -> str:
    """
    Format version scan result for display.
    
    Args:
        result: VersionScanResult to format
        verbose: Include extra details
    
    Returns:
        Formatted string
    """
    output = f"{result.port}/{result.protocol}"
    
    if result.state:
        output += f"  {result.state}"
    
    if result.service:
        output += f"  {result.service}"
    
    if result.product:
        output += f"  {result.product}"
        if result.version:
            output += f" {result.version}"
    elif result.version:
        output += f"  version {result.version}"
    
    if verbose:
        if result.extra_info:
            output += f"  ({result.extra_info})"
        
        if result.hostname:
            output += f"  hostname: {result.hostname}"
        
        if result.os:
            output += f"  OS: {result.os}"
        
        if result.cpe:
            output += f"  CPE: {', '.join(result.cpe[:3])}"
        
        output += f"  [confidence: {result.confidence}%, method: {result.method}]"
    
    return output


async def run_version_scan(
    hosts: List[str],
    ports: List[int],
    intensity: int = 7,
    timeout: float = 10.0,
    protocol: str = "TCP",
    callback: Optional[Callable[[VersionScanResult], None]] = None
) -> Dict[str, List[VersionScanResult]]:
    """
    Convenience function to run version detection scan.
    
    Args:
        hosts: List of target hosts
        ports: List of ports to scan
        intensity: Detection intensity (0-9)
        timeout: Probe timeout
        protocol: "TCP" or "UDP"
        callback: Optional callback for results
    
    Returns:
        Dictionary mapping host to list of results
    """
    scanner = VersionScanner(intensity=intensity, timeout=timeout)
    
    results = {}
    for host in hosts:
        logger.info(f"Scanning {host} with intensity {intensity}...")
        host_results = await scanner.scan_ports(host, ports, protocol, callback)
        results[host] = host_results
    
    return results
