"""
Main port scanner engine for SpectreScan
by BitSpectreLabs
"""

import socket
import random
import logging
from typing import List, Optional, Callable, Dict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from spectrescan.core.utils import (
    ScanResult, HostInfo, parse_target, parse_ports,
    get_service_name, calculate_scan_time
)
from spectrescan.core.presets import ScanConfig, ScanPreset, get_preset_config
from spectrescan.core.syn_scan import SynScanner
from spectrescan.core.udp_scan import UdpScanner
from spectrescan.core.async_scan import AsyncScanner
from spectrescan.core.banners import BannerGrabber
from spectrescan.core.os_detect import OSDetector
from spectrescan.core.host_discovery import HostDiscovery


logger = logging.getLogger(__name__)


class PortScanner:
    """Main port scanning engine."""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """
        Initialize port scanner.
        
        Args:
            config: Scan configuration (default: normal scan)
        """
        if config is None:
            config = get_preset_config(ScanPreset.TOP_PORTS)
        
        self.config = config
        self.results: List[ScanResult] = []
        self.host_info: Dict[str, HostInfo] = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        # Initialize subsystems
        self.syn_scanner = SynScanner(timeout=config.timeout)
        self.udp_scanner = UdpScanner(timeout=config.timeout)
        self.async_scanner = AsyncScanner(
            timeout=config.timeout,
            max_concurrent=config.threads,
            rate_limit=config.rate_limit
        )
        self.banner_grabber = BannerGrabber(timeout=config.timeout)
        self.os_detector = OSDetector(timeout=config.timeout)
        self.host_discovery = HostDiscovery(
            timeout=config.timeout,
            threads=config.threads
        )
    
    def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        callback: Optional[Callable[[ScanResult], None]] = None,
        host_discovery: bool = True,
        target_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> List[ScanResult]:
        """
        Perform port scan on single or multiple targets.
        
        Args:
            target: Target specification (IP, hostname, CIDR, range, comma-separated)
            ports: List of ports to scan (uses config if None)
            callback: Optional callback for each port scan result
            host_discovery: Perform host discovery first (for CIDR/ranges)
            target_callback: Optional callback(target, current_index, total) for multi-target progress
            
        Returns:
            List of ScanResult objects
            
        Examples:
            >>> scanner = PortScanner()
            >>> # Single target
            >>> results = scanner.scan("192.168.1.1")
            >>> # Multiple targets
            >>> results = scanner.scan("192.168.1.1,192.168.1.2,example.com")
            >>> # CIDR range
            >>> results = scanner.scan("192.168.1.0/24")
        """
        self.start_time = datetime.now()
        self.results = []
        
        # Parse target
        targets = parse_target(target)
        logger.info(f"Scanning {len(targets)} target(s)")
        
        # Get ports to scan
        if ports is None:
            ports = self.config.ports
        
        # Randomize if configured
        if self.config.randomize:
            random.shuffle(ports)
            random.shuffle(targets)
        
        # Host discovery phase
        if host_discovery and len(targets) > 1:
            logger.info("Performing host discovery...")
            live_hosts = self.host_discovery.discover_hosts(target)
            targets = [h.ip for h in live_hosts]
            
            # Store host info
            for host in live_hosts:
                self.host_info[host.ip] = host
            
            logger.info(f"Found {len(targets)} live host(s)")
        
        # Scan each target
        total_targets = len(targets)
        for idx, target_ip in enumerate(targets, 1):
            logger.info(f"Scanning {target_ip}... ({idx}/{total_targets})")
            
            # Call target callback if provided
            if target_callback:
                target_callback(target_ip, idx, total_targets)
            
            # Determine scan method
            if "tcp" in self.config.scan_types:
                results = self._tcp_scan(target_ip, ports, callback)
                self.results.extend(results)
            
            if "syn" in self.config.scan_types:
                results = self._syn_scan(target_ip, ports, callback)
                self.results.extend(results)
            
            if "udp" in self.config.scan_types:
                results = self._udp_scan(target_ip, ports, callback)
                self.results.extend(results)
            
            # Additional detection for open ports
            open_ports = [r for r in self.results if r.state == "open" and r.host == target_ip]
            
            if open_ports:
                if self.config.enable_banner_grabbing:
                    self._grab_banners(open_ports)
                
                if self.config.enable_service_detection:
                    self._detect_services(open_ports)
                
                if self.config.enable_os_detection:
                    self._detect_os(target_ip, open_ports)
        
        self.end_time = datetime.now()
        logger.info(f"Scan complete in {calculate_scan_time(self.start_time, self.end_time)}")
        
        return self.results
    
    def _tcp_scan(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Perform TCP connect scan.
        
        Args:
            host: Target host
            ports: List of ports
            callback: Optional callback
            
        Returns:
            List of results
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._tcp_connect, host, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                
                if callback:
                    callback(result)
        
        return results
    
    def _tcp_connect(self, host: str, port: int) -> ScanResult:
        """
        Perform single TCP connect.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            ScanResult
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return ScanResult(
                    host=host,
                    port=port,
                    state="open",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
            else:
                return ScanResult(
                    host=host,
                    port=port,
                    state="closed",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
        except socket.timeout:
            return ScanResult(
                host=host,
                port=port,
                state="filtered",
                protocol="tcp",
                timestamp=datetime.now()
            )
        except (socket.error, OSError):
            return ScanResult(
                host=host,
                port=port,
                state="filtered",
                protocol="tcp",
                timestamp=datetime.now()
            )
    
    def _syn_scan(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Perform SYN scan.
        
        Args:
            host: Target host
            ports: List of ports
            callback: Optional callback
            
        Returns:
            List of results
        """
        return self.syn_scanner.scan_ports(host, ports, callback)
    
    def _udp_scan(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Perform UDP scan.
        
        Args:
            host: Target host
            ports: List of ports
            callback: Optional callback
            
        Returns:
            List of results
        """
        return self.udp_scanner.scan_ports(host, ports, callback)
    
    def _grab_banners(self, results: List[ScanResult]) -> None:
        """
        Grab banners for open ports.
        
        Args:
            results: List of scan results
        """
        for result in results:
            if result.state == "open":
                banner, service = self.banner_grabber.grab_banner(
                    result.host,
                    result.port,
                    result.protocol
                )
                result.banner = banner
                if service and not result.service:
                    result.service = service
    
    def _detect_services(self, results: List[ScanResult]) -> None:
        """
        Detect services for open ports.
        
        Args:
            results: List of scan results
        """
        for result in results:
            if result.state == "open" and not result.service:
                service = get_service_name(result.port, result.protocol)
                result.service = service
    
    def _detect_os(self, host: str, results: List[ScanResult]) -> None:
        """
        Detect operating system.
        
        Args:
            host: Target host
            results: List of scan results
        """
        # Find first open TCP port
        open_tcp_port = None
        for result in results:
            if result.state == "open" and result.protocol == "tcp":
                open_tcp_port = result.port
                break
        
        # Perform OS detection
        fingerprint = self.os_detector.detect_os(host, open_tcp_port)
        
        # Enhance with banner information
        for result in results:
            if result.banner:
                fingerprint = self.os_detector.enhance_with_banner(
                    fingerprint,
                    result.banner
                )
                break
        
        # Store in host info
        if host not in self.host_info:
            self.host_info[host] = HostInfo(ip=host)
        
        self.host_info[host].os_guess = fingerprint.os_guess
        self.host_info[host].ttl = fingerprint.ttl
    
    def get_open_ports(self, host: Optional[str] = None) -> List[ScanResult]:
        """
        Get all open ports.
        
        Args:
            host: Optional host filter
            
        Returns:
            List of open port results
        """
        if host:
            return [r for r in self.results if r.state == "open" and r.host == host]
        else:
            return [r for r in self.results if r.state == "open"]
    
    def get_scan_summary(self) -> dict:
        """
        Get scan summary statistics.
        
        Returns:
            Dictionary with summary data
        """
        open_count = len([r for r in self.results if r.state == "open"])
        closed_count = len([r for r in self.results if r.state == "closed"])
        filtered_count = len([r for r in self.results if "filtered" in r.state])
        
        duration = "N/A"
        if self.start_time and self.end_time:
            duration = calculate_scan_time(self.start_time, self.end_time)
        
        return {
            "total_ports": len(self.results),
            "open_ports": open_count,
            "closed_ports": closed_count,
            "filtered_ports": filtered_count,
            "hosts_scanned": len(set(r.host for r in self.results)),
            "scan_duration": duration,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


def quick_scan(target: str, callback: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
    """Quick scan preset."""
    config = get_preset_config(ScanPreset.QUICK)
    scanner = PortScanner(config)
    return scanner.scan(target, callback=callback)


def full_scan(target: str, callback: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
    """Full scan preset."""
    config = get_preset_config(ScanPreset.FULL)
    scanner = PortScanner(config)
    return scanner.scan(target, callback=callback)


def stealth_scan(target: str, callback: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
    """Stealth scan preset."""
    config = get_preset_config(ScanPreset.STEALTH)
    scanner = PortScanner(config)
    return scanner.scan(target, callback=callback)
