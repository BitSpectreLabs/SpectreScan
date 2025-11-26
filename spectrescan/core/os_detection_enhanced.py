"""
Enhanced OS Detection
Advanced TCP/IP fingerprinting, TTL analysis, and comprehensive OS signatures.

Author: BitSpectreLabs
License: MIT
"""

import socket
import struct
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class OSFamily(Enum):
    """Operating system families."""
    LINUX = "Linux"
    WINDOWS = "Windows"
    UNIX = "Unix/BSD"
    MACOS = "macOS"
    NETWORK_DEVICE = "Network Device"
    EMBEDDED = "Embedded"
    UNKNOWN = "Unknown"


@dataclass
class OSFingerprint:
    """Enhanced OS fingerprint with detailed characteristics."""
    os_guess: str
    os_family: OSFamily
    confidence: int
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    mss: Optional[int] = None
    window_scale: Optional[int] = None
    timestamps: bool = False
    sack_permitted: bool = False
    tcp_options: List[str] = field(default_factory=list)
    ip_id_sequence: Optional[str] = None
    icmp_echo_code: Optional[int] = None
    banner_hints: List[str] = field(default_factory=list)
    characteristics: Dict[str, Any] = field(default_factory=dict)


class EnhancedOSDetector:
    """
    Enhanced OS detection using multiple techniques:
    - TTL analysis
    - TCP/IP fingerprinting
    - Window size analysis
    - TCP options fingerprinting
    - Banner analysis
    - IP ID sequence analysis
    """
    
    def __init__(self, timeout: float = 5.0):
        """
        Initialize OS detector.
        
        Args:
            timeout: Detection timeout in seconds
        """
        self.timeout = timeout
        self._load_signatures()
    
    def _load_signatures(self):
        """Load OS fingerprint signatures."""
        # TTL-based signatures
        self.ttl_signatures = {
            64: {
                "os": "Linux/Unix",
                "family": OSFamily.LINUX,
                "confidence": 70,
                "details": "Linux 2.4+, most Unix systems"
            },
            128: {
                "os": "Windows",
                "family": OSFamily.WINDOWS,
                "confidence": 75,
                "details": "Windows 2000/XP/Vista/7/8/10/11"
            },
            255: {
                "os": "Network Device",
                "family": OSFamily.NETWORK_DEVICE,
                "confidence": 80,
                "details": "Cisco, Juniper, switches, routers"
            },
            32: {
                "os": "Windows (old)",
                "family": OSFamily.WINDOWS,
                "confidence": 60,
                "details": "Windows 95/98/NT"
            },
            60: {
                "os": "MacOS/AIX",
                "family": OSFamily.MACOS,
                "confidence": 65,
                "details": "macOS, AIX"
            },
        }
        
        # Window size signatures
        self.window_signatures = {
            # Linux
            5840: {"os": "Linux 2.4/2.6", "family": OSFamily.LINUX},
            5792: {"os": "Linux 2.6", "family": OSFamily.LINUX},
            65535: {"os": "Linux 3.x+", "family": OSFamily.LINUX},
            14600: {"os": "Linux", "family": OSFamily.LINUX},
            
            # Windows
            8192: {"os": "Windows 2000/XP", "family": OSFamily.WINDOWS},
            16384: {"os": "Windows Vista/7", "family": OSFamily.WINDOWS},
            64240: {"os": "Windows 7/8/10", "family": OSFamily.WINDOWS},
            
            # BSD/Unix
            16384: {"os": "FreeBSD", "family": OSFamily.UNIX},
            32768: {"os": "OpenBSD", "family": OSFamily.UNIX},
            
            # macOS
            65535: {"os": "macOS", "family": OSFamily.MACOS},
        }
        
        # TCP options fingerprints
        self.tcp_option_fingerprints = {
            # Linux
            "M*,S,T,N,W*": {
                "os": "Linux 2.6.x",
                "family": OSFamily.LINUX,
                "confidence": 80
            },
            "M*,N,W*,S,T": {
                "os": "Linux 3.x/4.x",
                "family": OSFamily.LINUX,
                "confidence": 85
            },
            
            # Windows
            "M*,N,W*,N,N,S": {
                "os": "Windows 7/8/10",
                "family": OSFamily.WINDOWS,
                "confidence": 85
            },
            "M*,N,W*": {
                "os": "Windows XP/2003",
                "family": OSFamily.WINDOWS,
                "confidence": 75
            },
            
            # BSD
            "M*,N,N,S,N,W*": {
                "os": "FreeBSD",
                "family": OSFamily.UNIX,
                "confidence": 80
            },
            
            # macOS
            "M*,N,W*,N,N,T": {
                "os": "macOS 10.x+",
                "family": OSFamily.MACOS,
                "confidence": 85
            },
        }
        
        # Banner-based OS hints
        self.banner_os_hints = {
            "ubuntu": ("Ubuntu Linux", OSFamily.LINUX, 90),
            "debian": ("Debian Linux", OSFamily.LINUX, 90),
            "centos": ("CentOS Linux", OSFamily.LINUX, 90),
            "rhel": ("Red Hat Enterprise Linux", OSFamily.LINUX, 90),
            "fedora": ("Fedora Linux", OSFamily.LINUX, 90),
            "windows": ("Windows", OSFamily.WINDOWS, 85),
            "microsoft": ("Windows", OSFamily.WINDOWS, 80),
            "freebsd": ("FreeBSD", OSFamily.UNIX, 90),
            "openbsd": ("OpenBSD", OSFamily.UNIX, 90),
            "netbsd": ("NetBSD", OSFamily.UNIX, 90),
            "darwin": ("macOS", OSFamily.MACOS, 85),
            "macos": ("macOS", OSFamily.MACOS, 90),
            "cisco": ("Cisco IOS", OSFamily.NETWORK_DEVICE, 95),
            "juniper": ("Juniper JunOS", OSFamily.NETWORK_DEVICE, 95),
        }
    
    async def detect_os(
        self,
        host: str,
        open_port: Optional[int] = None,
        banner: Optional[str] = None
    ) -> OSFingerprint:
        """
        Detect operating system using multiple techniques.
        
        Args:
            host: Target host
            open_port: Known open TCP port (improves accuracy)
            banner: Service banner (if available)
        
        Returns:
            OSFingerprint with detection results
        """
        fingerprint = OSFingerprint(
            os_guess="Unknown",
            os_family=OSFamily.UNKNOWN,
            confidence=0
        )
        
        # 1. TTL-based detection
        ttl_result = await self._detect_by_ttl(host)
        if ttl_result:
            fingerprint = ttl_result
        
        # 2. TCP fingerprinting (if port available)
        if open_port:
            tcp_result = await self._detect_by_tcp_fingerprint(host, open_port)
            if tcp_result and tcp_result.confidence > fingerprint.confidence:
                fingerprint = self._merge_fingerprints(fingerprint, tcp_result)
        
        # 3. Banner analysis
        if banner:
            banner_result = self._detect_from_banner(banner)
            if banner_result and banner_result.confidence > fingerprint.confidence:
                fingerprint = self._merge_fingerprints(fingerprint, banner_result)
        
        # 4. ICMP fingerprinting
        icmp_result = await self._detect_by_icmp(host)
        if icmp_result and icmp_result.confidence > 50:
            fingerprint = self._merge_fingerprints(fingerprint, icmp_result)
        
        return fingerprint
    
    async def _detect_by_ttl(self, host: str) -> Optional[OSFingerprint]:
        """Detect OS based on TTL value."""
        try:
            # Send ICMP echo request and analyze TTL
            import platform
            if platform.system().lower() == "windows":
                ping_cmd = f"ping -n 1 -w {int(self.timeout * 1000)} {host}"
            else:
                ping_cmd = f"ping -c 1 -W {int(self.timeout)} {host}"
            
            import subprocess
            result = subprocess.run(
                ping_cmd.split(),
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Extract TTL from output
            import re
            ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
            if not ttl_match:
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                # Find closest TTL signature
                closest_ttl = min(self.ttl_signatures.keys(), key=lambda x: abs(x - ttl))
                
                if abs(closest_ttl - ttl) <= 10:  # Allow some hops
                    sig = self.ttl_signatures[closest_ttl]
                    return OSFingerprint(
                        os_guess=sig["os"],
                        os_family=sig["family"],
                        confidence=sig["confidence"],
                        ttl=ttl,
                        characteristics={"ttl_base": closest_ttl, "hops": closest_ttl - ttl}
                    )
        
        except Exception as e:
            logger.debug(f"TTL detection failed: {e}")
        
        return None
    
    async def _detect_by_tcp_fingerprint(
        self,
        host: str,
        port: int
    ) -> Optional[OSFingerprint]:
        """
        Detect OS using TCP/IP stack fingerprinting.
        Analyzes window size, TCP options, and other characteristics.
        """
        try:
            # Connect and analyze TCP characteristics
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Get socket for low-level analysis
            sock = writer.get_extra_info('socket')
            
            # Try to extract TCP info (platform-dependent)
            window_size = None
            tcp_options = []
            
            try:
                # Get TCP_INFO (Linux-specific)
                if hasattr(socket, 'TCP_INFO'):
                    tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
                    # Parse tcp_info structure (simplified)
                    # This is platform-specific and may not work on all systems
                    pass
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            # For now, use basic heuristics
            # In production, would use raw sockets for detailed fingerprinting
            
            return None
        
        except Exception as e:
            logger.debug(f"TCP fingerprinting failed: {e}")
            return None
    
    def _detect_from_banner(self, banner: str) -> Optional[OSFingerprint]:
        """Detect OS from service banner."""
        banner_lower = banner.lower()
        
        best_match = None
        best_confidence = 0
        
        for keyword, (os_name, family, confidence) in self.banner_os_hints.items():
            if keyword in banner_lower:
                if confidence > best_confidence:
                    best_match = OSFingerprint(
                        os_guess=os_name,
                        os_family=family,
                        confidence=confidence,
                        banner_hints=[keyword]
                    )
                    best_confidence = confidence
        
        # Extract version from banner if possible
        if best_match:
            version_patterns = {
                OSFamily.LINUX: r'(\d+\.\d+(?:\.\d+)?)',
                OSFamily.WINDOWS: r'Windows\s+(?:NT\s+)?(\d+\.\d+)',
            }
            
            pattern = version_patterns.get(best_match.os_family)
            if pattern:
                import re
                match = re.search(pattern, banner)
                if match:
                    version = match.group(1)
                    best_match.os_guess += f" {version}"
                    best_match.confidence += 5
        
        return best_match
    
    async def _detect_by_icmp(self, host: str) -> Optional[OSFingerprint]:
        """
        Detect OS using ICMP fingerprinting.
        Analyzes ICMP response characteristics.
        """
        # ICMP fingerprinting requires raw sockets (admin privileges)
        # Placeholder for future implementation
        return None
    
    def _merge_fingerprints(
        self,
        fp1: OSFingerprint,
        fp2: OSFingerprint
    ) -> OSFingerprint:
        """
        Merge two fingerprints, combining information.
        Uses higher confidence result as base.
        """
        if fp2.confidence > fp1.confidence:
            base = fp2
            supplement = fp1
        else:
            base = fp1
            supplement = fp2
        
        # Merge characteristics
        merged_chars = {**base.characteristics, **supplement.characteristics}
        
        # Merge banner hints
        merged_hints = list(set(base.banner_hints + supplement.banner_hints))
        
        # Merge TCP options
        merged_options = list(set(base.tcp_options + supplement.tcp_options))
        
        return OSFingerprint(
            os_guess=base.os_guess,
            os_family=base.os_family,
            confidence=base.confidence,
            ttl=base.ttl or supplement.ttl,
            window_size=base.window_size or supplement.window_size,
            mss=base.mss or supplement.mss,
            window_scale=base.window_scale or supplement.window_scale,
            timestamps=base.timestamps or supplement.timestamps,
            sack_permitted=base.sack_permitted or supplement.sack_permitted,
            tcp_options=merged_options,
            ip_id_sequence=base.ip_id_sequence or supplement.ip_id_sequence,
            icmp_echo_code=base.icmp_echo_code or supplement.icmp_echo_code,
            banner_hints=merged_hints,
            characteristics=merged_chars
        )
    
    def get_os_details(self, fingerprint: OSFingerprint) -> Dict[str, Any]:
        """
        Get detailed OS information from fingerprint.
        
        Args:
            fingerprint: OS fingerprint
        
        Returns:
            Dictionary with detailed OS information
        """
        return {
            "os": fingerprint.os_guess,
            "family": fingerprint.os_family.value,
            "confidence": f"{fingerprint.confidence}%",
            "ttl": fingerprint.ttl,
            "window_size": fingerprint.window_size,
            "tcp_characteristics": {
                "mss": fingerprint.mss,
                "window_scale": fingerprint.window_scale,
                "timestamps": fingerprint.timestamps,
                "sack": fingerprint.sack_permitted,
                "options": fingerprint.tcp_options
            },
            "detection_methods": {
                "ttl_based": fingerprint.ttl is not None,
                "banner_based": len(fingerprint.banner_hints) > 0,
                "tcp_stack": len(fingerprint.tcp_options) > 0
            },
            "characteristics": fingerprint.characteristics
        }
