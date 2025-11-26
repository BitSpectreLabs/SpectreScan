"""
TCP SYN scan implementation using scapy
by BitSpectreLabs

Supports both IPv4 and IPv6 addresses.
"""

import socket
from typing import List, Optional, Callable
from spectrescan.core.utils import ScanResult, is_ipv6
from datetime import datetime


class SynScanner:
    """TCP SYN (half-open) scanner using raw sockets."""
    
    def __init__(self, timeout: float = 2.0, use_scapy: bool = True):
        """
        Initialize SYN scanner.
        
        Args:
            timeout: Timeout for responses in seconds
            use_scapy: Whether to use scapy (if available)
        """
        self.timeout = timeout
        self.use_scapy = use_scapy
        self.scapy_available = False
        
        # Try to import scapy
        if use_scapy:
            try:
                import scapy.all as scapy
                self.scapy = scapy
                self.scapy_available = True
            except ImportError:
                self.scapy_available = False
    
    def scan_port(self, host: str, port: int) -> ScanResult:
        """
        Perform SYN scan on a single port.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            ScanResult object
        """
        if self.scapy_available:
            return self._syn_scan_scapy(host, port)
        else:
            # Fallback to connect scan
            return self._fallback_connect_scan(host, port)
    
    def scan_ports(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Perform SYN scan on multiple ports.
        
        Args:
            host: Target host
            ports: List of ports
            callback: Optional callback for each result
            
        Returns:
            List of ScanResult objects
        """
        results = []
        
        for port in ports:
            result = self.scan_port(host, port)
            results.append(result)
            
            if callback:
                callback(result)
        
        return results
    
    def _syn_scan_scapy(self, host: str, port: int) -> ScanResult:
        """
        Perform SYN scan using scapy.
        
        Supports both IPv4 and IPv6 addresses.
        
        Args:
            host: Target host (IPv4 or IPv6)
            port: Target port
            
        Returns:
            ScanResult object
        """
        try:
            # Determine if IPv6 and create appropriate packet
            ipv6 = is_ipv6(host)
            
            if ipv6:
                # Create IPv6 SYN packet
                ip_packet = self.scapy.IPv6(dst=host)
            else:
                # Create IPv4 SYN packet
                ip_packet = self.scapy.IP(dst=host)
            
            tcp_packet = self.scapy.TCP(dport=port, flags='S')
            packet = ip_packet / tcp_packet
            
            # Send packet and wait for response
            response = self.scapy.sr1(
                packet,
                timeout=self.timeout,
                verbose=0
            )
            
            if response is None:
                # No response - filtered or host down
                return ScanResult(
                    host=host,
                    port=port,
                    state="filtered",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
            
            # Check response flags
            if response.haslayer(self.scapy.TCP):
                tcp_layer = response.getlayer(self.scapy.TCP)
                
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    # Port is open - send RST to close connection
                    if ipv6:
                        rst_packet = self.scapy.IPv6(dst=host) / self.scapy.TCP(
                            dport=port,
                            flags='R'
                        )
                    else:
                        rst_packet = self.scapy.IP(dst=host) / self.scapy.TCP(
                            dport=port,
                            flags='R'
                        )
                    self.scapy.send(rst_packet, verbose=0)
                    
                    return ScanResult(
                        host=host,
                        port=port,
                        state="open",
                        protocol="tcp",
                        timestamp=datetime.now()
                    )
                elif tcp_layer.flags == 0x14:  # RST-ACK
                    # Port is closed
                    return ScanResult(
                        host=host,
                        port=port,
                        state="closed",
                        protocol="tcp",
                        timestamp=datetime.now()
                    )
            
            # ICMP/ICMPv6 response indicates filtered
            if response.haslayer(self.scapy.ICMP) or (ipv6 and response.haslayer(self.scapy.ICMPv6DestUnreach)):
                return ScanResult(
                    host=host,
                    port=port,
                    state="filtered",
                    protocol="tcp",
                    timestamp=datetime.now()
                )
            
        except Exception as e:
            # Error during scan
            pass
        
        # Default to filtered
        return ScanResult(
            host=host,
            port=port,
            state="filtered",
            protocol="tcp",
            timestamp=datetime.now()
        )
    
    def _fallback_connect_scan(self, host: str, port: int) -> ScanResult:
        """
        Fallback to connect scan if scapy not available.
        
        Supports both IPv4 and IPv6 addresses.
        
        Args:
            host: Target host (IPv4 or IPv6)
            port: Target port
            
        Returns:
            ScanResult object
        """
        try:
            # Determine address family based on IP version
            af = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
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
    
    def requires_root(self) -> bool:
        """
        Check if SYN scan requires root privileges.
        
        Returns:
            True if root required
        """
        return self.scapy_available


def is_scapy_available() -> bool:
    """Check if scapy is available."""
    try:
        import scapy.all
        return True
    except ImportError:
        return False


def get_syn_scan_warning() -> str:
    """Get warning message about SYN scan requirements."""
    if not is_scapy_available():
        return (
            "SYN scan requires scapy library. "
            "Install with: pip install scapy\n"
            "Falling back to TCP connect scan."
        )
    else:
        import platform
        if platform.system() != "Windows":
            return (
                "SYN scan requires root/administrator privileges on most systems.\n"
                "Run with sudo on Linux/macOS or as Administrator on Windows."
            )
    return ""
