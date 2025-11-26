"""
Banner grabbing module for service identification
by BitSpectreLabs

Supports both IPv4 and IPv6 addresses.
"""

import socket
import ssl
from typing import Optional, Tuple
from spectrescan.core.utils import format_banner, is_ipv6


# Common service probes
SERVICE_PROBES = {
    "http": b"GET / HTTP/1.0\r\n\r\n",
    "https": b"GET / HTTP/1.0\r\n\r\n",
    "ftp": b"",
    "ssh": b"",
    "smtp": b"EHLO scanner\r\n",
    "pop3": b"",
    "imap": b"",
    "telnet": b"",
    "mysql": b"",
    "postgresql": b"",
    "rdp": b"",
    "vnc": b"",
}


# Service signatures for identification
SERVICE_SIGNATURES = {
    b"HTTP/": "HTTP",
    b"SSH-": "SSH",
    b"220": "SMTP/FTP",
    b"+OK": "POP3",
    b"* OK": "IMAP",
    b"MySQL": "MySQL",
    b"PostgreSQL": "PostgreSQL",
    b"RFB": "VNC",
    b"rdp": "RDP",
    b"redis": "Redis",
    b"mongodb": "MongoDB",
    b"elasticsearch": "Elasticsearch",
    b"nginx": "Nginx",
    b"Apache": "Apache",
    b"Microsoft": "Microsoft",
    b"220-": "FTP",
}


class BannerGrabber:
    """Service for grabbing and analyzing service banners."""
    
    def __init__(self, timeout: float = 3.0):
        """
        Initialize banner grabber.
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
    
    def grab_banner(
        self, 
        host: str, 
        port: int, 
        protocol: str = "tcp"
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Grab banner from a service.
        
        Args:
            host: Target host
            port: Target port
            protocol: Protocol (tcp/udp)
            
        Returns:
            Tuple of (banner, service_name)
        """
        if protocol == "udp":
            return self._grab_udp_banner(host, port)
        else:
            return self._grab_tcp_banner(host, port)
    
    def _grab_tcp_banner(self, host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """
        Grab banner from TCP service.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Tuple of (banner, service_name)
        """
        banner = None
        service = None
        
        try:
            # Try standard connection first
            # Select address family based on IP version
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Some services send banner immediately
            try:
                data = sock.recv(4096)
                if data:
                    banner = format_banner(data)
                    service = self._identify_service(data)
            except socket.timeout:
                pass
            
            # If no banner, try sending a probe
            if not banner:
                probe = self._get_probe_for_port(port)
                if probe:
                    sock.send(probe)
                    try:
                        data = sock.recv(4096)
                        if data:
                            banner = format_banner(data)
                            service = self._identify_service(data)
                    except socket.timeout:
                        pass
            
            sock.close()
            
            # Try SSL/TLS for common HTTPS ports
            if port in [443, 8443, 8080] and not banner:
                banner, service = self._grab_ssl_banner(host, port)
            
        except (socket.error, ssl.SSLError, ConnectionRefusedError, OSError):
            pass
        
        return banner, service
    
    def _grab_ssl_banner(self, host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """
        Grab banner from SSL/TLS service.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Tuple of (banner, service_name)
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Select address family based on IP version
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            # Send HTTP GET request
            ssl_sock.send(b"GET / HTTP/1.0\r\n\r\n")
            data = ssl_sock.recv(4096)
            
            ssl_sock.close()
            
            if data:
                banner = format_banner(data)
                service = self._identify_service(data)
                return banner, service or "HTTPS"
            
        except (socket.error, ssl.SSLError, ConnectionRefusedError, OSError):
            pass
        
        return None, None
    
    def _grab_udp_banner(self, host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """
        Grab banner from UDP service.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Tuple of (banner, service_name)
        """
        try:
            # Select address family based on IP version
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty probe
            sock.sendto(b"", (host, port))
            
            try:
                data, _ = sock.recvfrom(4096)
                if data:
                    banner = format_banner(data)
                    service = self._identify_service(data)
                    sock.close()
                    return banner, service
            except socket.timeout:
                pass
            
            sock.close()
            
        except (socket.error, OSError):
            pass
        
        return None, None
    
    def _get_probe_for_port(self, port: int) -> Optional[bytes]:
        """
        Get appropriate probe for a port.
        
        Args:
            port: Port number
            
        Returns:
            Probe bytes or None
        """
        probe_map = {
            21: SERVICE_PROBES["ftp"],
            22: SERVICE_PROBES["ssh"],
            25: SERVICE_PROBES["smtp"],
            80: SERVICE_PROBES["http"],
            110: SERVICE_PROBES["pop3"],
            143: SERVICE_PROBES["imap"],
            443: SERVICE_PROBES["https"],
            587: SERVICE_PROBES["smtp"],
            8080: SERVICE_PROBES["http"],
            8443: SERVICE_PROBES["https"],
        }
        
        return probe_map.get(port, b"")
    
    def _identify_service(self, data: bytes) -> Optional[str]:
        """
        Identify service from banner data.
        
        Args:
            data: Banner data
            
        Returns:
            Service name or None
        """
        data_lower = data.lower()
        
        for signature, service_name in SERVICE_SIGNATURES.items():
            if signature.lower() in data_lower:
                return service_name
        
        return None
    
    def grab_multiple(
        self, 
        host: str, 
        ports: list, 
        protocol: str = "tcp"
    ) -> dict:
        """
        Grab banners from multiple ports.
        
        Args:
            host: Target host
            ports: List of ports
            protocol: Protocol (tcp/udp)
            
        Returns:
            Dictionary mapping port to (banner, service)
        """
        results = {}
        
        for port in ports:
            banner, service = self.grab_banner(host, port, protocol)
            if banner or service:
                results[port] = (banner, service)
        
        return results


def detect_service_version(banner: Optional[str]) -> Optional[str]:
    """
    Detect service version from banner.
    
    Args:
        banner: Service banner
        
    Returns:
        Version string or None
    """
    if not banner:
        return None
    
    import re
    
    # Common version patterns
    patterns = [
        r'(\d+\.\d+\.?\d*)',  # X.Y.Z or X.Y
        r'version[:\s]+(\d+\.\d+\.?\d*)',
        r'v(\d+\.\d+\.?\d*)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


def is_http_service(banner: Optional[str]) -> bool:
    """Check if banner indicates HTTP service."""
    if not banner:
        return False
    return "HTTP/" in banner or "http" in banner.lower()


def is_ssh_service(banner: Optional[str]) -> bool:
    """Check if banner indicates SSH service."""
    if not banner:
        return False
    return "SSH-" in banner or "OpenSSH" in banner
