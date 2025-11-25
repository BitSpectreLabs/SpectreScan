"""
OS detection module using TCP fingerprinting
by BitSpectreLabs
"""

import socket
import struct
from typing import Optional, Dict, Tuple
from dataclasses import dataclass


@dataclass
class OSFingerprint:
    """Operating system fingerprint data."""
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    df_flag: Optional[bool] = None  # Don't Fragment flag
    tcp_options: Optional[str] = None
    os_guess: Optional[str] = None
    confidence: int = 0  # 0-100


# TTL-based OS detection
TTL_SIGNATURES = {
    (64, 64): ("Linux/Unix", 70),
    (128, 128): ("Windows", 70),
    (255, 255): ("Cisco/Network Device", 60),
    (32, 32): ("Windows 95/98", 50),
    (60, 64): ("Linux (modified)", 60),
    (120, 128): ("Windows (modified)", 60),
}


# Window size signatures
WINDOW_SIGNATURES = {
    5840: ("Linux 2.4/2.6", 50),
    8192: ("Windows 7/8/10", 50),
    65535: ("FreeBSD/OpenBSD", 50),
    16384: ("macOS", 50),
}


class OSDetector:
    """Service for detecting operating systems."""
    
    def __init__(self, timeout: float = 2.0):
        """
        Initialize OS detector.
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
    
    def detect_os(self, host: str, open_port: Optional[int] = None) -> OSFingerprint:
        """
        Detect operating system of target host.
        
        Args:
            host: Target host
            open_port: Known open port for testing
            
        Returns:
            OSFingerprint object
        """
        fingerprint = OSFingerprint()
        
        # Get TTL from ICMP/TCP
        ttl = self._get_ttl(host, open_port)
        if ttl:
            fingerprint.ttl = ttl
            os_from_ttl = self._guess_os_from_ttl(ttl)
            if os_from_ttl:
                fingerprint.os_guess = os_from_ttl[0]
                fingerprint.confidence = os_from_ttl[1]
        
        # Get TCP window size if we have an open port
        if open_port:
            window_size = self._get_window_size(host, open_port)
            if window_size:
                fingerprint.window_size = window_size
                os_from_window = self._guess_os_from_window(window_size)
                if os_from_window:
                    # Combine confidence if OS matches
                    if fingerprint.os_guess and os_from_window[0] in fingerprint.os_guess:
                        fingerprint.confidence = min(100, fingerprint.confidence + 20)
                    elif not fingerprint.os_guess:
                        fingerprint.os_guess = os_from_window[0]
                        fingerprint.confidence = os_from_window[1]
        
        return fingerprint
    
    def _get_ttl(self, host: str, port: Optional[int] = None) -> Optional[int]:
        """
        Get TTL value from target.
        
        Args:
            host: Target host
            port: Optional port to connect to
            
        Returns:
            TTL value or None
        """
        # Try TCP connection if port provided
        if port:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                # Set socket option to receive IP headers
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTTL, 1)
                except (OSError, AttributeError):
                    pass
                
                sock.connect((host, port))
                
                # Try to get TTL from socket options
                try:
                    ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    sock.close()
                    return ttl
                except (OSError, AttributeError):
                    pass
                
                sock.close()
                
            except (socket.error, OSError):
                pass
        
        # Fallback: Use platform-specific ping to estimate TTL
        # This is a heuristic based on initial TTL values
        return self._estimate_ttl_from_connection(host, port)
    
    def _estimate_ttl_from_connection(self, host: str, port: Optional[int]) -> Optional[int]:
        """
        Estimate initial TTL from connection attempt.
        
        This is a heuristic method since we can't always get the actual TTL
        from the response without raw socket access.
        
        Args:
            host: Target host
            port: Port to connect to
            
        Returns:
            Estimated TTL or None
        """
        # Common initial TTL values
        # Linux/Unix: 64, Windows: 128, Network devices: 255
        
        # Without raw sockets, we can't get the actual TTL reliably
        # Return None to indicate TTL detection requires elevated privileges
        return None
    
    def _get_window_size(self, host: str, port: int) -> Optional[int]:
        """
        Get TCP window size from target.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Window size or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((host, port))
            
            # Try to get window size from socket
            try:
                window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                sock.close()
                return window_size
            except (OSError, AttributeError):
                pass
            
            sock.close()
            
        except (socket.error, OSError):
            pass
        
        return None
    
    def _guess_os_from_ttl(self, ttl: int) -> Optional[Tuple[str, int]]:
        """
        Guess OS from TTL value.
        
        Args:
            ttl: TTL value
            
        Returns:
            Tuple of (OS name, confidence) or None
        """
        # Find closest matching TTL signature
        for (low, high), (os_name, confidence) in TTL_SIGNATURES.items():
            if low <= ttl <= high:
                return (os_name, confidence)
        
        # Heuristic guesses based on common initial TTL values
        if 60 <= ttl <= 70:
            return ("Linux/Unix", 60)
        elif 120 <= ttl <= 130:
            return ("Windows", 60)
        elif 250 <= ttl <= 255:
            return ("Network Device", 50)
        
        return None
    
    def _guess_os_from_window(self, window_size: int) -> Optional[Tuple[str, int]]:
        """
        Guess OS from TCP window size.
        
        Args:
            window_size: Window size value
            
        Returns:
            Tuple of (OS name, confidence) or None
        """
        if window_size in WINDOW_SIGNATURES:
            return WINDOW_SIGNATURES[window_size]
        
        return None
    
    def enhance_with_banner(
        self, 
        fingerprint: OSFingerprint, 
        banner: Optional[str]
    ) -> OSFingerprint:
        """
        Enhance OS detection with banner information.
        
        Args:
            fingerprint: Existing fingerprint
            banner: Service banner
            
        Returns:
            Enhanced fingerprint
        """
        if not banner:
            return fingerprint
        
        banner_lower = banner.lower()
        
        # Check for OS hints in banner
        os_hints = {
            "ubuntu": ("Ubuntu Linux", 80),
            "debian": ("Debian Linux", 80),
            "centos": ("CentOS Linux", 80),
            "red hat": ("Red Hat Linux", 80),
            "fedora": ("Fedora Linux", 80),
            "windows": ("Windows", 80),
            "win32": ("Windows", 75),
            "microsoft": ("Windows", 70),
            "freebsd": ("FreeBSD", 80),
            "openbsd": ("OpenBSD", 80),
            "netbsd": ("NetBSD", 80),
            "macos": ("macOS", 80),
            "darwin": ("macOS", 75),
            "cisco": ("Cisco IOS", 80),
            "linux": ("Linux", 70),
            "unix": ("Unix", 60),
        }
        
        for hint, (os_name, confidence) in os_hints.items():
            if hint in banner_lower:
                # If we already have a guess, increase confidence if they match
                if fingerprint.os_guess:
                    if hint in fingerprint.os_guess.lower():
                        fingerprint.confidence = min(100, fingerprint.confidence + 20)
                        fingerprint.os_guess = os_name
                else:
                    fingerprint.os_guess = os_name
                    fingerprint.confidence = confidence
                break
        
        return fingerprint


def format_os_detection(fingerprint: OSFingerprint) -> str:
    """
    Format OS detection results for display.
    
    Args:
        fingerprint: OS fingerprint
        
    Returns:
        Formatted string
    """
    if not fingerprint.os_guess:
        return "Unknown"
    
    output = fingerprint.os_guess
    
    if fingerprint.confidence:
        output += f" ({fingerprint.confidence}% confidence)"
    
    details = []
    if fingerprint.ttl:
        details.append(f"TTL={fingerprint.ttl}")
    if fingerprint.window_size:
        details.append(f"Window={fingerprint.window_size}")
    
    if details:
        output += f" [{', '.join(details)}]"
    
    return output


def requires_privileges() -> bool:
    """
    Check if current process has privileges for advanced OS detection.
    
    Returns:
        True if has elevated privileges
    """
    import os
    import platform
    
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0
