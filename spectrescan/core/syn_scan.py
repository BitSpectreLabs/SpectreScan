"""
TCP SYN scan implementation using scapy
by BitSpectreLabs
"""

import socket
from typing import List, Optional, Callable
from spectrescan.core.utils import ScanResult
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
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            ScanResult object
        """
        try:
            # Create SYN packet
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
            
            # ICMP response indicates filtered
            if response.haslayer(self.scapy.ICMP):
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
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            ScanResult object
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
