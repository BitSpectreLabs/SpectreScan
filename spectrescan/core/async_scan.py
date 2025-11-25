"""
High-speed asynchronous scanner using asyncio
by BitSpectreLabs
"""

import asyncio
import socket
from typing import List, Optional, Callable
from spectrescan.core.utils import ScanResult
from datetime import datetime


class AsyncScanner:
    """Asynchronous high-speed port scanner."""
    
    def __init__(
        self,
        timeout: float = 2.0,
        max_concurrent: int = 1000,
        rate_limit: Optional[int] = None
    ):
        """
        Initialize async scanner.
        
        Args:
            timeout: Connection timeout in seconds
            max_concurrent: Maximum concurrent connections
            rate_limit: Optional rate limit (connections per second)
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_port(self, host: str, port: int) -> ScanResult:
        """
        Asynchronously scan a single port.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            ScanResult object
        """
        async with self.semaphore:
            if self.rate_limit:
                await asyncio.sleep(1.0 / self.rate_limit)
            
            try:
                # Try to establish connection
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                
                # Connection successful - port is open
                writer.close()
                await writer.wait_closed()
                
                return ScanResult(
                    host=host,
                    port=port,
                    state="open",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
                
            except asyncio.TimeoutError:
                # Connection timeout - port filtered
                return ScanResult(
                    host=host,
                    port=port,
                    state="filtered",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
            except ConnectionRefusedError:
                # Connection refused - port closed
                return ScanResult(
                    host=host,
                    port=port,
                    state="closed",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
            except OSError:
                # Other error - likely filtered
                return ScanResult(
                    host=host,
                    port=port,
                    state="filtered",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
    
    async def scan_ports(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Asynchronously scan multiple ports.
        
        Args:
            host: Target host
            ports: List of ports to scan
            callback: Optional callback for each result
            
        Returns:
            List of ScanResult objects
        """
        tasks = []
        
        for port in ports:
            task = self.scan_port(host, port)
            tasks.append(task)
        
        results = []
        
        # Process results as they complete
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            
            if callback:
                callback(result)
        
        return results
    
    async def scan_multiple_hosts(
        self,
        hosts: List[str],
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> dict:
        """
        Scan multiple hosts and ports.
        
        Args:
            hosts: List of target hosts
            ports: List of ports to scan
            callback: Optional callback for each result
            
        Returns:
            Dictionary mapping host to list of results
        """
        all_results = {}
        tasks = []
        
        for host in hosts:
            for port in ports:
                tasks.append(self.scan_port(host, port))
        
        results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            
            if callback:
                callback(result)
        
        # Group results by host
        for result in results:
            if result.host not in all_results:
                all_results[result.host] = []
            all_results[result.host].append(result)
        
        return all_results


def run_async_scan(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    max_concurrent: int = 1000,
    rate_limit: Optional[int] = None,
    callback: Optional[Callable[[ScanResult], None]] = None
) -> List[ScanResult]:
    """
    Convenience function to run async scan.
    
    Args:
        host: Target host
        ports: List of ports
        timeout: Timeout in seconds
        max_concurrent: Max concurrent connections
        rate_limit: Optional rate limit
        callback: Optional callback function
        
    Returns:
        List of ScanResult objects
    """
    scanner = AsyncScanner(
        timeout=timeout,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit
    )
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(
            scanner.scan_ports(host, ports, callback)
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
    callback: Optional[Callable[[ScanResult], None]] = None
) -> dict:
    """
    Convenience function to run async scan on multiple hosts.
    
    Args:
        hosts: List of target hosts
        ports: List of ports
        timeout: Timeout in seconds
        max_concurrent: Max concurrent connections
        rate_limit: Optional rate limit
        callback: Optional callback function
        
    Returns:
        Dictionary mapping host to results
    """
    scanner = AsyncScanner(
        timeout=timeout,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit
    )
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(
            scanner.scan_multiple_hosts(hosts, ports, callback)
        )
        return results
    finally:
        loop.close()
