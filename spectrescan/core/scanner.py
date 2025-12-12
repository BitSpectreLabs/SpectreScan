"""
Main port scanner engine for SpectreScan
by BitSpectreLabs
"""

import socket
import random
import logging
import asyncio
from typing import List, Optional, Callable, Dict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from spectrescan.core.utils import (
    ScanResult, HostInfo, parse_target, parse_ports,
    get_service_name, calculate_scan_time, is_ipv6
)
from spectrescan.core.presets import ScanConfig, ScanPreset, get_preset_config
from spectrescan.core.syn_scan import SynScanner
from spectrescan.core.udp_scan import UdpScanner
from spectrescan.core.async_scan import AsyncScanner
from spectrescan.core.banners import BannerGrabber
from spectrescan.core.os_detect import OSDetector
from spectrescan.core.host_discovery import HostDiscovery
from spectrescan.core.timing_engine import TimingTemplate, TimingLevel, get_timing_template
from spectrescan.core.connection_pool import ConnectionPool


logger = logging.getLogger(__name__)


class PortScanner:
    """Main port scanning engine with async-first architecture."""
    
    def __init__(
        self, 
        config: Optional[ScanConfig] = None,
        timing_template: Optional[TimingTemplate] = None,
        use_async: bool = True,
        proxy: Optional["ProxyConfig"] = None,
        proxy_pool: Optional["ProxyPool"] = None,
        evasion: Optional["EvasionManager"] = None
    ):
        """
        Initialize port scanner.
        
        Args:
            config: Scan configuration (default: normal scan)
            timing_template: Timing template (T0-T5) for speed control
            use_async: Use async scanner by default (recommended)
            proxy: Single proxy configuration for scanning through proxy
            proxy_pool: Pool of proxies with rotation for scanning
            evasion: Evasion manager for IDS/IPS evasion techniques
        """
        if config is None:
            config = get_preset_config(ScanPreset.TOP_PORTS)
        
        # Use timing template if provided
        if timing_template:
            self.timing_template = timing_template
        else:
            # Default to T3 (Normal) if timing_template not in config
            self.timing_template = getattr(config, 'timing_template', None) or get_timing_template(TimingLevel.NORMAL)
        
        self.config = config
        self.use_async = use_async
        self.results: List[ScanResult] = []
        self.host_info: Dict[str, HostInfo] = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        # Proxy configuration
        self.proxy = proxy
        self.proxy_pool = proxy_pool
        
        # Evasion configuration
        self.evasion = evasion
        
        # Connection pool for async scanner
        self.connection_pool = ConnectionPool(
            max_connections=self.timing_template.max_concurrent,
            max_connections_per_host=min(50, self.timing_template.max_concurrent // 10),
            max_age=30.0,
            idle_timeout=5.0
        )
        
        # Initialize subsystems
        self.syn_scanner = SynScanner(timeout=self.timing_template.timeout)
        self.udp_scanner = UdpScanner(timeout=self.timing_template.timeout)
        self.async_scanner = AsyncScanner(
            timing_template=self.timing_template,
            connection_pool=self.connection_pool,
            enable_rtt_adjustment=True,
            proxy=proxy,
            proxy_pool=proxy_pool,
            evasion=evasion
        )
        self.banner_grabber = BannerGrabber(timeout=self.timing_template.timeout)
        self.os_detector = OSDetector(timeout=self.timing_template.timeout)
        self.host_discovery = HostDiscovery(
            timeout=self.timing_template.host_timeout,
            threads=min(100, self.timing_template.max_concurrent)
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
            
            # Determine scan method (prefer async for TCP)
            if "tcp" in self.config.scan_types:
                if self.use_async:
                    # Use high-speed async scanner with integrated banner grabbing
                    results = self._async_tcp_scan(target_ip, ports, callback)
                else:
                    # Fallback to threaded scanner
                    results = self._tcp_scan(target_ip, ports, callback)
                self.results.extend(results)
            
            if "syn" in self.config.scan_types:
                results = self._syn_scan(target_ip, ports, callback)
                self.results.extend(results)
            
            if "udp" in self.config.scan_types:
                results = self._udp_scan(target_ip, ports, callback)
                self.results.extend(results)
            
            # Additional detection for open ports (only if not already done by async scanner)
            open_ports = [r for r in self.results if r.state == "open" and r.host == target_ip]
            
            if open_ports:
                # Banner grabbing (skip if async scanner already did it)
                if self.config.enable_banner_grabbing and not (self.use_async and "tcp" in self.config.scan_types):
                    self._grab_banners(open_ports)
                
                if self.config.enable_service_detection:
                    self._detect_services(open_ports)
                
                if self.config.enable_os_detection:
                    self._detect_os(target_ip, open_ports)
        
        self.end_time = datetime.now()
        duration = calculate_scan_time(self.start_time, self.end_time)
        logger.info(f"Scan complete in {duration}")
        
        # Log performance stats
        stats = self.async_scanner.get_stats()
        if stats.get("ports_scanned", 0) > 0:
            logger.info(f"Async scanner stats: {stats['ports_scanned']} ports, "
                       f"{stats['open_ports']} open, {stats['retries']} retries")
        
        return self.results
    
    def _async_tcp_scan(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Perform high-speed async TCP scan with integrated banner grabbing.
        
        Args:
            host: Target host
            ports: List of ports
            callback: Optional callback
            
        Returns:
            List of results
        """
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(
                self.async_scanner.scan_ports(
                    host, 
                    ports, 
                    callback,
                    grab_banners=self.config.enable_banner_grabbing
                )
            )
            return results
        finally:
            loop.close()
    
    def _tcp_scan(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Perform TCP connect scan (legacy threaded method).
        
        Args:
            host: Target host
            ports: List of ports
            callback: Optional callback
            
        Returns:
            List of results
        """
        results = []
        
        # Use timing template settings for thread count
        max_workers = min(self.timing_template.max_concurrent, len(ports))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._tcp_connect, host, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                
                if callback:
                    callback(result)
        
        return results
    
    def _tcp_connect(self, host: str, port: int) -> ScanResult:
        """
        Perform single TCP connect (legacy method).
        
        Supports both IPv4 and IPv6 addresses.
        
        Args:
            host: Target host (IPv4 or IPv6)
            port: Target port
            
        Returns:
            ScanResult
        """
        try:
            # Determine address family based on IP version
            af = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(self.timing_template.timeout)
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
        Detect services for open ports using enhanced signature matching.
        
        Args:
            results: List of scan results
        """
        # Import signature cache only when needed (lazy loading)
        from spectrescan.core.signature_cache import get_signature_cache
        
        cache = get_signature_cache()
        
        for result in results:
            if result.state == "open":
                # Try signature matching if we have a banner
                if result.banner and not result.service:
                    sig_match = cache.match_service_signature(
                        result.banner, 
                        result.port, 
                        result.protocol
                    )
                    if sig_match:
                        result.service = sig_match.get('name')
                        
                        # Extract version if we can
                        if result.banner:
                            version = cache.extract_version(result.banner, result.service)
                            if version:
                                result.service = f"{result.service}/{version}"
                
                # Fallback to port-based detection
                if not result.service:
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
        duration_seconds = 0.0
        if self.start_time and self.end_time:
            duration = calculate_scan_time(self.start_time, self.end_time)
            duration_seconds = (self.end_time - self.start_time).total_seconds()
        
        return {
            "total_ports": len(self.results),
            "open_ports": open_count,
            "closed_ports": closed_count,
            "filtered_ports": filtered_count,
            "hosts_scanned": len(set(r.host for r in self.results)),
            "scan_duration": duration,
            "scan_duration_seconds": duration_seconds,
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
