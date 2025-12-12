"""
High-speed asynchronous scanner using asyncio
by BitSpectreLabs
"""

import asyncio
import socket
import time
from typing import List, Optional, Callable, Tuple
from spectrescan.core.utils import ScanResult
from spectrescan.core.timing_engine import TimingTemplate, TimingLevel, get_timing_template, RTTCalculator
from spectrescan.core.connection_pool import ConnectionPool
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AsyncScanner:
    """Asynchronous high-speed port scanner with timing templates and connection pooling."""
    
    def __init__(
        self,
        timeout: float = 2.0,
        max_concurrent: int = 1000,
        rate_limit: Optional[int] = None,
        timing_template: Optional[TimingTemplate] = None,
        connection_pool: Optional[ConnectionPool] = None,
        enable_rtt_adjustment: bool = True,
        proxy: Optional["ProxyConfig"] = None,
        proxy_pool: Optional["ProxyPool"] = None,
        evasion: Optional["EvasionManager"] = None
    ):
        """
        Initialize async scanner.
        
        Args:
            timeout: Connection timeout in seconds (overridden by timing_template)
            max_concurrent: Maximum concurrent connections (overridden by timing_template)
            rate_limit: Optional rate limit (connections per second)
            timing_template: Timing template (T0-T5)
            connection_pool: Connection pool for reuse
            enable_rtt_adjustment: Enable dynamic RTT-based timeout adjustment
            proxy: Single proxy configuration for scanning through proxy
            proxy_pool: Pool of proxies with rotation for scanning
            evasion: Evasion manager for IDS/IPS evasion techniques
        """
        # Use timing template if provided
        if timing_template:
            self.timing_template = timing_template
            self.timeout = timing_template.timeout
            self.max_concurrent = timing_template.max_concurrent
            self.scan_delay = timing_template.scan_delay
            self.max_retries = timing_template.max_retries
        else:
            self.timing_template = get_timing_template(TimingLevel.NORMAL)
            self.timeout = timeout
            self.max_concurrent = max_concurrent
            self.scan_delay = 0.0
            self.max_retries = 3
        
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.connection_pool = connection_pool
        self.enable_rtt_adjustment = enable_rtt_adjustment
        
        # Proxy configuration
        self.proxy = proxy
        self.proxy_pool = proxy_pool
        self.proxy_connector = None
        if proxy or proxy_pool:
            from spectrescan.core.proxy import ProxyConnector
            self.proxy_connector = ProxyConnector(
                proxy=proxy,
                proxy_pool=proxy_pool,
                timeout=self.timeout
            )
        
        # Evasion configuration
        self.evasion = evasion
        self.evasion_scanner = None
        if evasion:
            from spectrescan.core.evasion import EvasionScanner
            self.evasion_scanner = EvasionScanner(evasion.config)
        
        # RTT calculator for adaptive timeouts
        self.rtt_calculator = RTTCalculator(self.timing_template) if enable_rtt_adjustment else None
        
        # Statistics
        self.stats = {
            "ports_scanned": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "filtered_ports": 0,
            "retries": 0,
            "errors": 0
        }
    
    async def scan_port(
        self, 
        host: str, 
        port: int,
        grab_banner: bool = False
    ) -> Tuple[ScanResult, Optional[Tuple[Optional[str], Optional[str]]]]:
        """
        Asynchronously scan a single port with optional banner grabbing.
        
        Args:
            host: Target host
            port: Target port
            grab_banner: Whether to grab banner if port is open
            
        Returns:
            Tuple of (ScanResult, Optional[banner_info])
            banner_info is (banner, service) tuple if grab_banner=True
        """
        async with self.semaphore:
            # Apply rate limiting
            if self.rate_limit:
                await asyncio.sleep(1.0 / self.rate_limit)
            
            # Apply scan delay (for stealth)
            if self.scan_delay > 0:
                await asyncio.sleep(self.scan_delay)
            
            # Get current timeout (may be adjusted by RTT)
            current_timeout = self.rtt_calculator.get_timeout() if self.rtt_calculator else self.timeout
            
            # Try scan with retries
            for attempt in range(self.max_retries):
                try:
                    start_time = time.time()
                    
                    # Use proxy if configured
                    if self.proxy_connector:
                        try:
                            reader, writer = await asyncio.wait_for(
                                self.proxy_connector.connect(host, port, current_timeout),
                                timeout=current_timeout * 2  # Allow extra time for proxy handshake
                            )
                        except Exception as e:
                            # Proxy connection failed
                            if attempt < self.max_retries - 1:
                                self.stats["retries"] += 1
                                await asyncio.sleep(0.1 * (attempt + 1))
                                continue
                            raise
                    # Use connection pool if available (and no proxy)
                    elif self.connection_pool:
                        try:
                            reader, writer = await self.connection_pool.acquire(
                                host, port, current_timeout
                            )
                        except Exception as e:
                            # Connection failed
                            if attempt < self.max_retries - 1:
                                self.stats["retries"] += 1
                                await asyncio.sleep(0.1 * (attempt + 1))  # Exponential backoff
                                continue
                            raise
                    else:
                        # Direct connection
                        conn = asyncio.open_connection(host, port)
                        reader, writer = await asyncio.wait_for(conn, timeout=current_timeout)
                    
                    # Measure RTT
                    rtt = time.time() - start_time
                    if self.rtt_calculator:
                        self.rtt_calculator.add_sample(rtt)
                    
                    # Port is open
                    banner_info = None
                    
                    # Grab banner if requested
                    if grab_banner:
                        try:
                            banner_info = await self._grab_banner_from_connection(
                                reader, writer, port, timeout=current_timeout
                            )
                        except Exception as e:
                            logger.debug(f"Banner grab failed for {host}:{port}: {e}")
                    
                    # Release connection back to pool or close
                    if self.connection_pool:
                        await self.connection_pool.release(host, port, reader, writer, reusable=not grab_banner)
                    else:
                        writer.close()
                        await writer.wait_closed()
                    
                    self.stats["ports_scanned"] += 1
                    self.stats["open_ports"] += 1
                    
                    return ScanResult(
                        host=host,
                        port=port,
                        state="open",
                        protocol="tcp",
                        timestamp=datetime.now()
                    ), banner_info
                    
                except asyncio.TimeoutError:
                    # Connection timeout - port filtered
                    if attempt < self.max_retries - 1:
                        self.stats["retries"] += 1
                        await asyncio.sleep(0.1 * (attempt + 1))
                        continue
                    
                    self.stats["ports_scanned"] += 1
                    self.stats["filtered_ports"] += 1
                    
                    return ScanResult(
                        host=host,
                        port=port,
                        state="filtered",
                        protocol="tcp",
                        timestamp=datetime.now()
                    ), None
                    
                except ConnectionRefusedError:
                    # Connection refused - port closed (no retry needed)
                    self.stats["ports_scanned"] += 1
                    self.stats["closed_ports"] += 1
                    
                    return ScanResult(
                        host=host,
                        port=port,
                        state="closed",
                        protocol="tcp",
                        timestamp=datetime.now()
                    ), None
                    
                except OSError as e:
                    # Other error - likely filtered
                    if attempt < self.max_retries - 1:
                        self.stats["retries"] += 1
                        await asyncio.sleep(0.1 * (attempt + 1))
                        continue
                    
                    self.stats["ports_scanned"] += 1
                    self.stats["filtered_ports"] += 1
                    
                    return ScanResult(
                        host=host,
                        port=port,
                        state="filtered",
                        protocol="tcp",
                        timestamp=datetime.now()
                    ), None
            
            # All retries exhausted
            self.stats["errors"] += 1
            return ScanResult(
                host=host,
                port=port,
                state="filtered",
                protocol="tcp",
                timestamp=datetime.now()
            ), None
    
    async def _grab_banner_from_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
        timeout: float = 2.0
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Grab banner from an open connection.
        
        Args:
            reader: Stream reader
            writer: Stream writer
            port: Port number (for probe selection)
            timeout: Read timeout
            
        Returns:
            Tuple of (banner, service_name)
        """
        try:
            # Try to read initial banner (some services send immediately)
            data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
                # Simple service identification
                service = self._identify_service_from_banner(banner, port)
                return banner, service
        except asyncio.TimeoutError:
            # No immediate banner, try sending probe
            pass
        except Exception as e:
            logger.debug(f"Error reading initial banner: {e}")
        
        # Try sending a simple probe
        try:
            probe = self._get_probe_for_port(port)
            if probe:
                writer.write(probe)
                await writer.drain()
                
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    service = self._identify_service_from_banner(banner, port)
                    return banner, service
        except Exception as e:
            logger.debug(f"Error with probe banner grab: {e}")
        
        return None, None
    
    def _get_probe_for_port(self, port: int) -> Optional[bytes]:
        """Get appropriate probe for port."""
        probes = {
            80: b"GET / HTTP/1.0\r\n\r\n",
            443: b"GET / HTTP/1.0\r\n\r\n",
            8080: b"GET / HTTP/1.0\r\n\r\n",
            21: b"",  # FTP sends banner first
            22: b"",  # SSH sends banner first
            25: b"EHLO scanner\r\n",
            110: b"",  # POP3 sends banner first
            143: b"",  # IMAP sends banner first
        }
        return probes.get(port, b"")
    
    def _identify_service_from_banner(self, banner: str, port: int) -> Optional[str]:
        """Simple service identification from banner."""
        banner_lower = banner.lower()
        
        if "http" in banner_lower or "html" in banner_lower:
            return "http"
        elif "ssh" in banner_lower:
            return "ssh"
        elif "ftp" in banner_lower:
            return "ftp"
        elif "smtp" in banner_lower:
            return "smtp"
        elif "pop3" in banner_lower:
            return "pop3"
        elif "imap" in banner_lower:
            return "imap"
        elif "mysql" in banner_lower:
            return "mysql"
        elif "postgresql" in banner_lower:
            return "postgresql"
        
        return None
    
    async def scan_ports(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None,
        grab_banners: bool = False
    ) -> List[ScanResult]:
        """
        Asynchronously scan multiple ports with optional banner grabbing.
        
        Args:
            host: Target host
            ports: List of ports to scan
            callback: Optional callback for each result
            grab_banners: Whether to grab banners for open ports
            
        Returns:
            List of ScanResult objects (with banners if grab_banners=True)
        """
        tasks = []
        
        for port in ports:
            task = self.scan_port(host, port, grab_banner=grab_banners)
            tasks.append(task)
        
        results = []
        
        # Process results as they complete (streaming)
        for coro in asyncio.as_completed(tasks):
            result, banner_info = await coro
            
            # Add banner info if available
            if banner_info:
                banner, service = banner_info
                result.banner = banner
                if service and not result.service:
                    result.service = service
            
            results.append(result)
            
            if callback:
                callback(result)
        
        return results
    
    async def scan_multiple_hosts(
        self,
        hosts: List[str],
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None,
        grab_banners: bool = False,
        host_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> dict:
        """
        Scan multiple hosts and ports in parallel.
        
        Args:
            hosts: List of target hosts
            ports: List of ports to scan
            callback: Optional callback for each result
            grab_banners: Whether to grab banners for open ports
            host_callback: Optional callback(host, current_idx, total) for host progress
            
        Returns:
            Dictionary mapping host to list of results
        """
        all_results = {}
        
        # Scan each host (hosts are scanned in parallel)
        host_tasks = []
        for idx, host in enumerate(hosts, 1):
            if host_callback:
                host_callback(host, idx, len(hosts))
            
            task = self.scan_ports(host, ports, callback, grab_banners)
            host_tasks.append((host, task))
        
        # Wait for all hosts to complete
        for host, task in host_tasks:
            results = await task
            all_results[host] = results
        
        return all_results
    
    def get_stats(self) -> dict:
        """
        Get scanner statistics.
        
        Returns:
            Dictionary with scan statistics
        """
        stats = self.stats.copy()
        
        if self.connection_pool:
            stats["connection_pool"] = self.connection_pool.get_stats()
        
        if self.rtt_calculator:
            stats["current_timeout"] = self.rtt_calculator.get_timeout()
            stats["rtt_samples"] = len(self.rtt_calculator.rtt_samples)
        
        return stats
    
    def reset_stats(self) -> None:
        """Reset statistics."""
        self.stats = {
            "ports_scanned": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "filtered_ports": 0,
            "retries": 0,
            "errors": 0
        }
        
        if self.rtt_calculator:
            self.rtt_calculator.reset()


def run_async_scan(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    max_concurrent: int = 1000,
    rate_limit: Optional[int] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
    timing_template: Optional[TimingTemplate] = None,
    grab_banners: bool = False
) -> List[ScanResult]:
    """
    Convenience function to run async scan.
    
    Args:
        host: Target host
        ports: List of ports
        timeout: Timeout in seconds (overridden by timing_template)
        max_concurrent: Max concurrent connections (overridden by timing_template)
        rate_limit: Optional rate limit
        callback: Optional callback function
        timing_template: Timing template (T0-T5)
        grab_banners: Whether to grab banners for open ports
        
    Returns:
        List of ScanResult objects
    """
    scanner = AsyncScanner(
        timeout=timeout,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit,
        timing_template=timing_template
    )
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(
            scanner.scan_ports(host, ports, callback, grab_banners)
        )
        return results
    finally:
        loop.close()


def run_async_scan_multiple(
    hosts: List[str],
    ports: List[int],
    timeout: float = 2.0,
    max_concurrent: int = 1000,
    rate_limit: Optional[int] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
    timing_template: Optional[TimingTemplate] = None,
    grab_banners: bool = False,
    host_callback: Optional[Callable[[str, int, int], None]] = None
) -> dict:
    """
    Convenience function to run async scan on multiple hosts.
    
    Args:
        hosts: List of target hosts
        ports: List of ports
        timeout: Timeout in seconds (overridden by timing_template)
        max_concurrent: Max concurrent connections (overridden by timing_template)
        rate_limit: Optional rate limit
        callback: Optional callback function
        timing_template: Timing template (T0-T5)
        grab_banners: Whether to grab banners for open ports
        host_callback: Optional callback for host progress
        
    Returns:
        Dictionary mapping host to results
    """
    scanner = AsyncScanner(
        timeout=timeout,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit,
        timing_template=timing_template
    )
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(
            scanner.scan_multiple_hosts(hosts, ports, callback, grab_banners, host_callback)
        )
        return results
    finally:
        loop.close()
