"""
Host discovery module for SpectreScan
by BitSpectreLabs

Supports both IPv4 and IPv6 host discovery.
"""

import socket
import subprocess
import platform
import concurrent.futures
from typing import List, Optional, Callable
from spectrescan.core.utils import HostInfo, parse_target, is_ipv6, get_ip_version, IPVersion


class HostDiscovery:
    """Service for discovering live hosts on network."""
    
    def __init__(self, timeout: float = 2.0, threads: int = 50):
        """
        Initialize host discovery.
        
        Args:
            timeout: Timeout for each probe in seconds
            threads: Number of concurrent threads
        """
        self.timeout = timeout
        self.threads = threads
    
    def discover_hosts(
        self, 
        target: str,
        method: str = "ping",
        callback: Optional[Callable[[HostInfo], None]] = None
    ) -> List[HostInfo]:
        """
        Discover live hosts in target range.
        
        Args:
            target: Target specification (IP, CIDR, range)
            method: Discovery method (ping, tcp, arp)
            callback: Optional callback for each discovered host
            
        Returns:
            List of HostInfo objects for live hosts
        """
        targets = parse_target(target)
        live_hosts = []
        
        if method == "ping":
            live_hosts = self._ping_sweep(targets, callback)
        elif method == "tcp":
            live_hosts = self._tcp_sweep(targets, callback)
        elif method == "arp":
            live_hosts = self._arp_sweep(targets, callback)
        else:
            # Default to ping
            live_hosts = self._ping_sweep(targets, callback)
        
        return live_hosts
    
    def _ping_sweep(
        self, 
        targets: List[str],
        callback: Optional[Callable[[HostInfo], None]] = None
    ) -> List[HostInfo]:
        """
        Perform ping sweep to discover hosts.
        
        Args:
            targets: List of IP addresses
            callback: Optional callback function
            
        Returns:
            List of live hosts
        """
        live_hosts = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._ping_host, ip): ip for ip in targets}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result.is_up:
                    live_hosts.append(result)
                    if callback:
                        callback(result)
        
        return live_hosts
    
    def _ping_host(self, ip: str) -> Optional[HostInfo]:
        """
        Ping a single host (supports both IPv4 and IPv6).
        
        Args:
            ip: IP address (IPv4 or IPv6)
            
        Returns:
            HostInfo if host is up, None otherwise
        """
        # Determine if IPv6
        ipv6 = is_ipv6(ip)
        
        # Determine ping command based on OS and IP version
        is_windows = platform.system().lower() == "windows"
        
        if ipv6:
            # Use ping6 or ping -6 for IPv6
            if is_windows:
                # Windows uses ping -6 for IPv6
                command = ["ping", "-6", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
            else:
                # Linux/macOS: try ping6 first, fall back to ping -6
                ping_cmd = self._get_ping6_command()
                if ping_cmd == "ping6":
                    command = ["ping6", "-c", "1", "-W", str(int(self.timeout)), ip]
                else:
                    command = ["ping", "-6", "-c", "1", "-W", str(int(self.timeout)), ip]
        else:
            # IPv4 ping
            param = "-n" if is_windows else "-c"
            timeout_param = "-w" if is_windows else "-W"
            timeout_value = str(int(self.timeout * 1000)) if is_windows else str(int(self.timeout))
            command = ["ping", param, "1", timeout_param, timeout_value, ip]
        
        try:
            creationflags = subprocess.CREATE_NO_WINDOW if is_windows else 0
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 2,
                creationflags=creationflags
            )
            
            if result.returncode == 0:
                # Try to resolve hostname
                hostname = self._resolve_hostname(ip)
                
                # Parse TTL/hop limit from output if available
                output = result.stdout.decode('utf-8', errors='ignore')
                ttl = self._parse_ttl_from_ping(output)
                
                return HostInfo(
                    ip=ip,
                    hostname=hostname,
                    is_up=True,
                    ttl=ttl,
                    ip_version=6 if ipv6 else 4
                )
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return None
    
    def _get_ping6_command(self) -> str:
        """
        Determine the correct ping6 command for the system.
        
        Returns:
            'ping6' if available, otherwise 'ping'
        """
        try:
            result = subprocess.run(
                ["which", "ping6"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            if result.returncode == 0:
                return "ping6"
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return "ping"
    
    def _tcp_sweep(
        self, 
        targets: List[str],
        callback: Optional[Callable[[HostInfo], None]] = None,
        ports: List[int] = None
    ) -> List[HostInfo]:
        """
        Perform TCP sweep to discover hosts.
        
        Args:
            targets: List of IP addresses
            callback: Optional callback function
            ports: List of ports to check (default: [80, 443, 22, 21, 25])
            
        Returns:
            List of live hosts
        """
        if ports is None:
            ports = [80, 443, 22, 21, 25, 3389, 8080]
        
        live_hosts = []
        discovered_ips = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for ip in targets:
                for port in ports:
                    futures.append(executor.submit(self._tcp_probe, ip, port))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result.is_up and result.ip not in discovered_ips:
                    discovered_ips.add(result.ip)
                    live_hosts.append(result)
                    if callback:
                        callback(result)
        
        return live_hosts
    
    def _tcp_probe(self, ip: str, port: int) -> Optional[HostInfo]:
        """
        Probe host with TCP connection (supports both IPv4 and IPv6).
        
        Args:
            ip: IP address (IPv4 or IPv6)
            port: Port number
            
        Returns:
            HostInfo if host responds, None otherwise
        """
        try:
            # Determine address family based on IP version
            ipv6 = is_ipv6(ip)
            af = socket.AF_INET6 if ipv6 else socket.AF_INET
            
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                hostname = self._resolve_hostname(ip)
                return HostInfo(
                    ip=ip,
                    hostname=hostname,
                    is_up=True,
                    ip_version=6 if ipv6 else 4
                )
        except (socket.error, OSError):
            pass
        
        return None
    
    def _arp_sweep(
        self, 
        targets: List[str],
        callback: Optional[Callable[[HostInfo], None]] = None
    ) -> List[HostInfo]:
        """
        Perform ARP sweep (requires elevated privileges).
        
        Args:
            targets: List of IP addresses
            callback: Optional callback function
            
        Returns:
            List of live hosts
        """
        # ARP sweep requires raw socket access
        # This is a placeholder for future implementation with scapy
        # For now, fall back to ping sweep
        return self._ping_sweep(targets, callback)
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """
        Resolve hostname for IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _parse_ttl_from_ping(self, output: str) -> Optional[int]:
        """
        Parse TTL/Hop Limit value from ping output.
        
        Supports both IPv4 TTL and IPv6 Hop Limit.
        
        Args:
            output: Ping command output
            
        Returns:
            TTL/Hop Limit value or None
        """
        import re
        
        # Windows IPv4: TTL=64
        # Linux IPv4: ttl=64
        # Windows IPv6: Hop Limit = 64
        # Linux IPv6: hlim=64
        patterns = [
            r'TTL=(\d+)',
            r'ttl=(\d+)',
            r'hlim=(\d+)',
            r'Hop Limit\s*=\s*(\d+)',
            r'hop limit=(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        return None
    
    def check_single_host(self, ip: str, method: str = "ping") -> Optional[HostInfo]:
        """
        Check if a single host is alive.
        
        Args:
            ip: IP address
            method: Discovery method
            
        Returns:
            HostInfo if host is up, None otherwise
        """
        if method == "ping":
            return self._ping_host(ip)
        elif method == "tcp":
            # Try multiple common ports
            for port in [80, 443, 22, 21, 25, 3389]:
                result = self._tcp_probe(ip, port)
                if result:
                    return result
            return None
        else:
            return self._ping_host(ip)


def discover_network(
    target: str,
    timeout: float = 2.0,
    threads: int = 50,
    method: str = "ping"
) -> List[HostInfo]:
    """
    Convenience function to discover hosts.
    
    Args:
        target: Target specification
        timeout: Timeout in seconds
        threads: Number of threads
        method: Discovery method
        
    Returns:
        List of live hosts
    """
    discovery = HostDiscovery(timeout=timeout, threads=threads)
    return discovery.discover_hosts(target, method=method)
