"""
UDP scan implementation
by BitSpectreLabs
"""

import socket
from typing import List, Optional, Callable
from spectrescan.core.utils import ScanResult
from datetime import datetime


class UdpScanner:
    """UDP port scanner with heuristics."""
    
    def __init__(self, timeout: float = 3.0):
        """
        Initialize UDP scanner.
        
        Args:
            timeout: Timeout for responses in seconds
        """
        self.timeout = timeout
    
    def scan_port(self, host: str, port: int) -> ScanResult:
        """
        Perform UDP scan on a single port.
        
        UDP scanning is challenging because:
        - Open ports may not respond
        - Closed ports send ICMP port unreachable
        - No response can mean open|filtered
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            ScanResult object
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet (or service-specific probe)
            probe = self._get_udp_probe(port)
            sock.sendto(probe, (host, port))
            
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                sock.close()
                
                # Got response - port is open
                return ScanResult(
                    host=host,
                    port=port,
                    state="open",
                    protocol="udp",
                    timestamp=datetime.now()
                )
                
            except socket.timeout:
                # No response - could be open or filtered
                sock.close()
                
                # Try to determine if filtered by checking for ICMP unreachable
                # This would require raw socket access, so we mark as open|filtered
                return ScanResult(
                    host=host,
                    port=port,
                    state="open|filtered",
                    protocol="udp",
                    timestamp=datetime.now()
                )
            
        except socket.error as e:
            # ICMP port unreachable received - port is closed
            if "forcibly closed" in str(e).lower() or "connection refused" in str(e).lower():
                return ScanResult(
                    host=host,
                    port=port,
                    state="closed",
                    protocol="udp",
                    timestamp=datetime.now()
                )
            else:
                return ScanResult(
                    host=host,
                    port=port,
                    state="filtered",
                    protocol="udp",
                    timestamp=datetime.now()
                )
    
    def scan_ports(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Perform UDP scan on multiple ports.
        
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
    
    def _get_udp_probe(self, port: int) -> bytes:
        """
        Get service-specific UDP probe for better detection.
        
        Args:
            port: Port number
            
        Returns:
            Probe payload
        """
        # Service-specific probes for common UDP services
        probes = {
            53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS
            67: b'\x01\x01\x06\x00',  # DHCP
            68: b'\x01\x01\x06\x00',  # DHCP
            69: b'\x00\x01',  # TFTP
            123: b'\x1b' + b'\x00' * 47,  # NTP
            137: b'\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00',  # NetBIOS
            161: b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63',  # SNMP
            500: b'\x00\x00\x00\x00',  # ISAKMP
            514: b'<0>test',  # Syslog
            520: b'\x01\x01\x00\x00',  # RIP
            1900: b'M-SEARCH * HTTP/1.1\r\n',  # SSDP
        }
        
        return probes.get(port, b'')
    
    def scan_common_udp_ports(
        self,
        host: str,
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Scan common UDP ports.
        
        Args:
            host: Target host
            callback: Optional callback for each result
            
        Returns:
            List of ScanResult objects
        """
        common_udp_ports = [
            53,    # DNS
            67,    # DHCP Server
            68,    # DHCP Client
            69,    # TFTP
            123,   # NTP
            137,   # NetBIOS Name Service
            138,   # NetBIOS Datagram Service
            161,   # SNMP
            162,   # SNMP Trap
            500,   # ISAKMP
            514,   # Syslog
            520,   # RIP
            1434,  # MSSQL Monitor
            1900,  # SSDP
            4500,  # IPSec NAT-T
            5353,  # mDNS
        ]
        
        return self.scan_ports(host, common_udp_ports, callback)


def get_udp_scan_warning() -> str:
    """Get warning about UDP scan limitations."""
    return (
        "UDP scanning has limitations:\n"
        "- Slower than TCP scanning\n"
        "- May produce false positives (open|filtered)\n"
        "- Requires longer timeout for accuracy\n"
        "- Some firewalls drop UDP packets silently\n"
        "Consider using service-specific tools for accurate UDP service detection."
    )
