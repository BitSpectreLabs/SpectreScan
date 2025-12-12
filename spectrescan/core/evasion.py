"""
IDS/IPS Evasion Techniques Module
by BitSpectreLabs

Provides advanced evasion techniques for bypassing intrusion detection
and prevention systems during port scanning operations.
"""

import asyncio
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class EvasionTechnique(Enum):
    """Available evasion techniques."""
    FRAGMENTATION = "fragmentation"
    DECOY = "decoy"
    SOURCE_PORT = "source_port"
    RANDOMIZE_HOSTS = "randomize_hosts"
    TTL_MANIPULATION = "ttl_manipulation"
    BAD_CHECKSUM = "bad_checksum"
    TIMING = "timing"
    IDLE_SCAN = "idle_scan"
    DATA_LENGTH = "data_length"
    IP_OPTIONS = "ip_options"


class EvasionProfile(Enum):
    """Predefined evasion profiles."""
    NONE = "none"
    STEALTH = "stealth"
    PARANOID = "paranoid"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


class TimingLevel(Enum):
    """Timing levels for evasion (T0-T5 compatible)."""
    PARANOID = 0      # 5 min between probes
    SNEAKY = 1        # 15 sec between probes
    POLITE = 2        # 400 ms between probes
    NORMAL = 3        # Default timing
    AGGRESSIVE = 4    # 10 ms between probes
    INSANE = 5        # No delay


# Common source ports that look legitimate
COMMON_SOURCE_PORTS = [
    20,    # FTP data
    21,    # FTP control
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    443,   # HTTPS
    993,   # IMAPS
    995,   # POP3S
    8080,  # HTTP Proxy
]

# TTL values that mimic common OS
TTL_VALUES = {
    "linux": 64,
    "windows": 128,
    "solaris": 255,
    "cisco": 255,
    "random": None,  # Will be randomized
}

# Timing delays per level (in seconds)
TIMING_DELAYS = {
    TimingLevel.PARANOID: 300.0,    # 5 minutes
    TimingLevel.SNEAKY: 15.0,       # 15 seconds
    TimingLevel.POLITE: 0.4,        # 400 ms
    TimingLevel.NORMAL: 0.0,        # No delay
    TimingLevel.AGGRESSIVE: 0.01,   # 10 ms
    TimingLevel.INSANE: 0.0,        # No delay
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class DecoyConfig:
    """Configuration for decoy scanning."""
    decoys: List[str] = field(default_factory=list)
    include_real: bool = True
    real_position: str = "random"  # "first", "last", "random", or index
    random_decoys: int = 0  # Number of random decoys to generate
    
    def get_scan_order(self, real_ip: str) -> List[str]:
        """Get list of IPs to scan from (decoys + real)."""
        ips = list(self.decoys)
        
        # Add random decoys if requested
        for _ in range(self.random_decoys):
            ips.append(generate_random_ip())
        
        if self.include_real:
            if self.real_position == "first":
                ips.insert(0, real_ip)
            elif self.real_position == "last":
                ips.append(real_ip)
            elif self.real_position == "random":
                pos = random.randint(0, len(ips))
                ips.insert(pos, real_ip)
            elif isinstance(self.real_position, int):
                ips.insert(self.real_position, real_ip)
            else:
                ips.append(real_ip)
        
        return ips


@dataclass
class FragmentConfig:
    """Configuration for packet fragmentation."""
    enabled: bool = False
    mtu: int = 8  # Minimum fragment size (must be multiple of 8)
    overlap: bool = False  # Enable overlapping fragments
    out_of_order: bool = False  # Send fragments out of order
    delay_between: float = 0.0  # Delay between fragments


@dataclass
class TimingConfig:
    """Configuration for timing-based evasion."""
    level: TimingLevel = TimingLevel.NORMAL
    delay_ms: Optional[float] = None  # Custom delay in ms
    jitter_percent: float = 0.0  # Random variation in timing
    max_parallelism: int = 100  # Maximum concurrent probes
    min_parallelism: int = 1
    max_rate: Optional[int] = None  # Max packets per second
    
    def get_delay(self) -> float:
        """Get delay in seconds with optional jitter."""
        if self.delay_ms is not None:
            base_delay = self.delay_ms / 1000.0
        else:
            base_delay = TIMING_DELAYS.get(self.level, 0.0)
        
        if self.jitter_percent > 0 and base_delay > 0:
            jitter = base_delay * (self.jitter_percent / 100.0)
            return base_delay + random.uniform(-jitter, jitter)
        
        return base_delay


@dataclass 
class IdleScanConfig:
    """Configuration for idle/zombie scanning."""
    zombie_host: str = ""
    zombie_port: int = 80
    probe_count: int = 2  # Number of probes to verify IP ID increment


@dataclass
class EvasionConfig:
    """Complete evasion configuration."""
    profile: EvasionProfile = EvasionProfile.NONE
    techniques: List[EvasionTechnique] = field(default_factory=list)
    
    # Fragmentation
    fragmentation: FragmentConfig = field(default_factory=FragmentConfig)
    
    # Decoys
    decoy: DecoyConfig = field(default_factory=DecoyConfig)
    
    # Source port
    source_port: Optional[int] = None
    randomize_source_port: bool = False
    use_common_source_port: bool = False
    
    # TTL manipulation
    ttl: Optional[int] = None
    ttl_style: str = "default"  # "linux", "windows", "solaris", "random"
    
    # Bad checksum (for firewall testing)
    bad_checksum: bool = False
    
    # Timing
    timing: TimingConfig = field(default_factory=TimingConfig)
    
    # Idle scan
    idle_scan: IdleScanConfig = field(default_factory=IdleScanConfig)
    
    # Data length padding
    data_length: int = 0  # Extra bytes to pad packets
    
    # IP options
    ip_options: bytes = b""  # Raw IP options
    
    # Host randomization
    randomize_hosts: bool = False
    randomize_ports: bool = False
    
    @classmethod
    def from_profile(cls, profile: EvasionProfile) -> "EvasionConfig":
        """Create config from predefined profile."""
        if profile == EvasionProfile.NONE:
            return cls(profile=profile)
        
        elif profile == EvasionProfile.STEALTH:
            return cls(
                profile=profile,
                techniques=[
                    EvasionTechnique.TIMING,
                    EvasionTechnique.RANDOMIZE_HOSTS,
                    EvasionTechnique.SOURCE_PORT,
                ],
                timing=TimingConfig(
                    level=TimingLevel.SNEAKY,
                    jitter_percent=20.0,
                    max_parallelism=10,
                ),
                randomize_hosts=True,
                randomize_ports=True,
                use_common_source_port=True,
            )
        
        elif profile == EvasionProfile.PARANOID:
            return cls(
                profile=profile,
                techniques=[
                    EvasionTechnique.TIMING,
                    EvasionTechnique.RANDOMIZE_HOSTS,
                    EvasionTechnique.SOURCE_PORT,
                    EvasionTechnique.FRAGMENTATION,
                    EvasionTechnique.TTL_MANIPULATION,
                    EvasionTechnique.DECOY,
                ],
                timing=TimingConfig(
                    level=TimingLevel.PARANOID,
                    jitter_percent=50.0,
                    max_parallelism=1,
                ),
                fragmentation=FragmentConfig(enabled=True, mtu=8),
                decoy=DecoyConfig(random_decoys=5),
                randomize_hosts=True,
                randomize_ports=True,
                use_common_source_port=True,
                ttl_style="random",
            )
        
        elif profile == EvasionProfile.AGGRESSIVE:
            return cls(
                profile=profile,
                techniques=[
                    EvasionTechnique.DECOY,
                    EvasionTechnique.FRAGMENTATION,
                    EvasionTechnique.BAD_CHECKSUM,
                ],
                timing=TimingConfig(
                    level=TimingLevel.AGGRESSIVE,
                    max_parallelism=500,
                ),
                fragmentation=FragmentConfig(enabled=True, mtu=8, out_of_order=True),
                decoy=DecoyConfig(random_decoys=10),
                bad_checksum=True,
            )
        
        return cls(profile=profile)


# ============================================================================
# Helper Functions
# ============================================================================

def generate_random_ip() -> str:
    """Generate a random non-reserved IP address."""
    while True:
        octets = [random.randint(1, 254) for _ in range(4)]
        ip = ".".join(map(str, octets))
        
        # Avoid reserved ranges
        if octets[0] == 10:  # 10.0.0.0/8
            continue
        if octets[0] == 172 and 16 <= octets[1] <= 31:  # 172.16.0.0/12
            continue
        if octets[0] == 192 and octets[1] == 168:  # 192.168.0.0/16
            continue
        if octets[0] == 127:  # 127.0.0.0/8
            continue
        if octets[0] >= 224:  # Multicast/reserved
            continue
        
        return ip


def get_random_source_port(common_only: bool = False) -> int:
    """Get a random source port."""
    if common_only:
        return random.choice(COMMON_SOURCE_PORTS)
    return random.randint(1024, 65535)


def get_ttl_for_style(style: str) -> int:
    """Get TTL value for given style."""
    if style == "random":
        return random.randint(32, 255)
    return TTL_VALUES.get(style, 64)


def randomize_list(items: List[Any]) -> List[Any]:
    """Randomize order of items."""
    shuffled = list(items)
    random.shuffle(shuffled)
    return shuffled


def calculate_checksum(data: bytes) -> int:
    """Calculate IP/TCP checksum."""
    if len(data) % 2:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF


def corrupt_checksum(checksum: int) -> int:
    """Corrupt a checksum value for testing."""
    return (checksum + random.randint(1, 100)) & 0xFFFF


# ============================================================================
# Packet Crafting Classes
# ============================================================================

class PacketCrafter:
    """
    Craft custom packets for evasion techniques.
    
    Provides low-level packet construction without requiring scapy,
    though scapy integration is supported when available.
    """
    
    def __init__(self, config: EvasionConfig):
        self.config = config
        self._scapy_available = self._check_scapy()
    
    def _check_scapy(self) -> bool:
        """Check if scapy is available."""
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False
    
    def create_ip_header(
        self,
        src: str,
        dst: str,
        protocol: int = 6,  # TCP
        ttl: Optional[int] = None,
        ip_id: Optional[int] = None,
        flags: int = 0,
        fragment_offset: int = 0,
        options: bytes = b"",
    ) -> bytes:
        """Create raw IP header."""
        version = 4
        ihl = 5 + (len(options) // 4)  # Header length in 32-bit words
        tos = 0
        total_length = 0  # Will be filled later
        
        if ip_id is None:
            ip_id = random.randint(0, 65535)
        
        if ttl is None:
            if self.config.ttl is not None:
                ttl = self.config.ttl
            else:
                ttl = get_ttl_for_style(self.config.ttl_style)
        
        checksum = 0  # Will be calculated
        
        src_bytes = socket.inet_aton(src)
        dst_bytes = socket.inet_aton(dst)
        
        header = struct.pack(
            "!BBHHHBBH4s4s",
            (version << 4) | ihl,
            tos,
            total_length,
            ip_id,
            (flags << 13) | fragment_offset,
            ttl,
            protocol,
            checksum,
            src_bytes,
            dst_bytes,
        )
        
        if options:
            header += options
        
        # Calculate checksum
        checksum = calculate_checksum(header)
        if self.config.bad_checksum:
            checksum = corrupt_checksum(checksum)
        
        header = header[:10] + struct.pack("!H", checksum) + header[12:]
        
        return header
    
    def create_tcp_header(
        self,
        src_port: int,
        dst_port: int,
        seq: Optional[int] = None,
        ack: int = 0,
        flags: int = 0x02,  # SYN
        window: int = 65535,
        urgent: int = 0,
        options: bytes = b"",
    ) -> bytes:
        """Create raw TCP header."""
        if seq is None:
            seq = random.randint(0, 0xFFFFFFFF)
        
        data_offset = 5 + (len(options) // 4)
        reserved = 0
        checksum = 0  # Will be calculated with pseudo-header
        
        header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            (data_offset << 4) | reserved,
            flags,
            window,
            checksum,
            urgent,
        )
        
        if options:
            # Pad options to 4-byte boundary
            padding_needed = (4 - (len(options) % 4)) % 4
            options += b'\x00' * padding_needed
            header += options
        
        return header
    
    def create_syn_packet(
        self,
        src: str,
        dst: str,
        dst_port: int,
        src_port: Optional[int] = None,
    ) -> bytes:
        """Create a SYN packet."""
        if src_port is None:
            if self.config.source_port is not None:
                src_port = self.config.source_port
            elif self.config.randomize_source_port:
                src_port = get_random_source_port(self.config.use_common_source_port)
            else:
                src_port = random.randint(49152, 65535)
        
        ip_header = self.create_ip_header(src, dst, protocol=6)
        tcp_header = self.create_tcp_header(src_port, dst_port, flags=0x02)
        
        # Add data padding if configured
        data = b'\x00' * self.config.data_length
        
        return ip_header + tcp_header + data
    
    def fragment_packet(
        self,
        packet: bytes,
        mtu: int = 8,
    ) -> List[bytes]:
        """Fragment a packet into smaller pieces."""
        if not self.config.fragmentation.enabled:
            return [packet]
        
        if mtu < 8:
            mtu = 8
        
        # Ensure MTU is multiple of 8
        mtu = (mtu // 8) * 8
        
        ip_header_len = (packet[0] & 0x0F) * 4
        ip_header = packet[:ip_header_len]
        payload = packet[ip_header_len:]
        
        fragments = []
        offset = 0
        
        while offset < len(payload):
            chunk = payload[offset:offset + mtu]
            is_last = (offset + mtu >= len(payload))
            
            # Modify IP header for fragment
            frag_header = bytearray(ip_header)
            
            # Set fragment offset and MF flag
            flags_offset = struct.unpack("!H", bytes(frag_header[6:8]))[0]
            new_flags_offset = (offset // 8)
            if not is_last:
                new_flags_offset |= 0x2000  # More Fragments flag
            
            frag_header[6:8] = struct.pack("!H", new_flags_offset)
            
            # Update total length
            new_length = ip_header_len + len(chunk)
            frag_header[2:4] = struct.pack("!H", new_length)
            
            # Recalculate checksum
            frag_header[10:12] = b'\x00\x00'
            checksum = calculate_checksum(bytes(frag_header))
            if self.config.bad_checksum:
                checksum = corrupt_checksum(checksum)
            frag_header[10:12] = struct.pack("!H", checksum)
            
            fragments.append(bytes(frag_header) + chunk)
            offset += mtu
        
        # Apply out-of-order if configured
        if self.config.fragmentation.out_of_order and len(fragments) > 1:
            random.shuffle(fragments)
        
        return fragments


# ============================================================================
# Evasion Scanner Classes
# ============================================================================

class EvasionScanner:
    """
    Port scanner with IDS/IPS evasion capabilities.
    
    Wraps scanning operations with evasion techniques to bypass
    intrusion detection systems.
    """
    
    def __init__(
        self,
        config: EvasionConfig,
        timeout: float = 2.0,
        callback: Optional[Callable] = None,
    ):
        self.config = config
        self.timeout = timeout
        self.callback = callback
        self.crafter = PacketCrafter(config)
        self._scapy_available = self._check_scapy()
        self._stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "decoys_used": 0,
            "fragments_sent": 0,
            "retries": 0,
        }
    
    def _check_scapy(self) -> bool:
        """Check if scapy is available."""
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False
    
    @property
    def stats(self) -> Dict[str, int]:
        """Get scan statistics."""
        return self._stats.copy()
    
    def prepare_targets(
        self,
        hosts: List[str],
        ports: List[int],
    ) -> List[Tuple[str, int]]:
        """Prepare target list with evasion options applied."""
        # Randomize hosts if configured
        if self.config.randomize_hosts:
            hosts = randomize_list(hosts)
        
        # Randomize ports if configured
        if self.config.randomize_ports:
            ports = randomize_list(ports)
        
        # Create target pairs
        targets = [(host, port) for host in hosts for port in ports]
        
        return targets
    
    async def apply_timing_delay(self) -> None:
        """Apply timing delay based on configuration."""
        delay = self.config.timing.get_delay()
        if delay > 0:
            await asyncio.sleep(delay)
    
    def get_source_port(self) -> int:
        """Get source port based on configuration."""
        if self.config.source_port is not None:
            return self.config.source_port
        elif self.config.randomize_source_port or self.config.use_common_source_port:
            return get_random_source_port(self.config.use_common_source_port)
        return random.randint(49152, 65535)
    
    async def scan_with_decoys(
        self,
        target: str,
        port: int,
        real_ip: str,
    ) -> Optional[str]:
        """
        Scan with decoy addresses.
        
        Sends packets appearing to come from multiple source addresses
        to confuse IDS systems.
        """
        if not self._scapy_available:
            logger.warning("Decoy scanning requires scapy")
            return await self._fallback_scan(target, port)
        
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
        except ImportError:
            return await self._fallback_scan(target, port)
        
        decoy_ips = self.config.decoy.get_scan_order(real_ip)
        self._stats["decoys_used"] += len(decoy_ips) - 1
        
        result = None
        src_port = self.get_source_port()
        
        for src_ip in decoy_ips:
            # Apply timing
            await self.apply_timing_delay()
            
            # Create and send packet
            pkt = IP(src=src_ip, dst=target) / TCP(sport=src_port, dport=port, flags="S")
            
            # Apply TTL manipulation
            if self.config.ttl is not None:
                pkt[IP].ttl = self.config.ttl
            elif self.config.ttl_style != "default":
                pkt[IP].ttl = get_ttl_for_style(self.config.ttl_style)
            
            self._stats["packets_sent"] += 1
            
            # Only wait for response from real IP
            if src_ip == real_ip:
                try:
                    response = sr1(pkt, timeout=self.timeout, verbose=0)
                    self._stats["packets_received"] += 1 if response else 0
                    
                    if response and response.haslayer(TCP):
                        flags = response[TCP].flags
                        if flags & 0x12:  # SYN-ACK
                            result = "open"
                        elif flags & 0x14:  # RST-ACK
                            result = "closed"
                except Exception as e:
                    logger.debug(f"Decoy scan error: {e}")
            else:
                # Send decoy packet without waiting
                try:
                    from scapy.all import send
                    send(pkt, verbose=0)
                except Exception:
                    pass
        
        return result
    
    async def scan_with_fragmentation(
        self,
        target: str,
        port: int,
        src_ip: str,
    ) -> Optional[str]:
        """
        Scan using fragmented packets.
        
        Splits packets into small fragments to evade signature-based detection.
        """
        if not self._scapy_available:
            logger.warning("Fragment scanning requires scapy")
            return await self._fallback_scan(target, port)
        
        try:
            from scapy.all import IP, TCP, fragment, sr1, conf
            conf.verb = 0
        except ImportError:
            return await self._fallback_scan(target, port)
        
        src_port = self.get_source_port()
        
        # Create base packet
        pkt = IP(src=src_ip, dst=target) / TCP(sport=src_port, dport=port, flags="S")
        
        # Apply TTL
        if self.config.ttl is not None:
            pkt[IP].ttl = self.config.ttl
        elif self.config.ttl_style != "default":
            pkt[IP].ttl = get_ttl_for_style(self.config.ttl_style)
        
        # Fragment the packet
        mtu = self.config.fragmentation.mtu
        frags = fragment(pkt, fragsize=mtu)
        self._stats["fragments_sent"] += len(frags)
        
        # Optionally reorder fragments
        if self.config.fragmentation.out_of_order:
            random.shuffle(frags)
        
        # Send fragments
        result = None
        for i, frag in enumerate(frags):
            await self.apply_timing_delay()
            
            if self.config.fragmentation.delay_between > 0:
                await asyncio.sleep(self.config.fragmentation.delay_between)
            
            self._stats["packets_sent"] += 1
            
            # Only expect response for last fragment
            if i == len(frags) - 1:
                try:
                    response = sr1(frag, timeout=self.timeout, verbose=0)
                    self._stats["packets_received"] += 1 if response else 0
                    
                    if response and response.haslayer(TCP):
                        flags = response[TCP].flags
                        if flags & 0x12:
                            result = "open"
                        elif flags & 0x14:
                            result = "closed"
                except Exception as e:
                    logger.debug(f"Fragment scan error: {e}")
            else:
                try:
                    from scapy.all import send
                    send(frag, verbose=0)
                except Exception:
                    pass
        
        return result
    
    async def idle_scan(
        self,
        target: str,
        port: int,
    ) -> Optional[str]:
        """
        Perform idle/zombie scan.
        
        Uses a third-party "zombie" host to scan the target indirectly,
        making attribution extremely difficult.
        """
        if not self._scapy_available:
            logger.warning("Idle scanning requires scapy")
            return None
        
        zombie_host = self.config.idle_scan.zombie_host
        zombie_port = self.config.idle_scan.zombie_port
        
        if not zombie_host:
            logger.error("Zombie host not configured for idle scan")
            return None
        
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
        except ImportError:
            return None
        
        try:
            # Step 1: Get zombie's current IP ID
            probe1 = IP(dst=zombie_host) / TCP(dport=zombie_port, flags="SA")
            response1 = sr1(probe1, timeout=self.timeout, verbose=0)
            
            if not response1 or not response1.haslayer(IP):
                return None
            
            ipid1 = response1[IP].id
            
            # Step 2: Send SYN to target with spoofed zombie source
            await self.apply_timing_delay()
            
            syn = IP(src=zombie_host, dst=target) / TCP(dport=port, flags="S")
            from scapy.all import send
            send(syn, verbose=0)
            self._stats["packets_sent"] += 1
            
            # Wait for target to respond to zombie
            await asyncio.sleep(0.5)
            
            # Step 3: Probe zombie again to check IP ID increment
            await self.apply_timing_delay()
            
            probe2 = IP(dst=zombie_host) / TCP(dport=zombie_port, flags="SA")
            response2 = sr1(probe2, timeout=self.timeout, verbose=0)
            
            if not response2 or not response2.haslayer(IP):
                return None
            
            ipid2 = response2[IP].id
            self._stats["packets_received"] += 2
            
            # Analyze IP ID increment
            increment = (ipid2 - ipid1) % 65536
            
            if increment == 1:
                # Zombie only sent response to us - port is closed/filtered
                return "closed"
            elif increment == 2:
                # Zombie sent response to us AND to target - port is open
                return "open"
            else:
                # Unusual increment - zombie not suitable or port filtered
                return "filtered"
                
        except Exception as e:
            logger.error(f"Idle scan error: {e}")
            return None
    
    async def _fallback_scan(
        self,
        target: str,
        port: int,
    ) -> Optional[str]:
        """Fallback to basic TCP connect scan when scapy unavailable."""
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return "open"
        except asyncio.TimeoutError:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except Exception:
            return None
    
    async def scan_port(
        self,
        target: str,
        port: int,
        src_ip: Optional[str] = None,
    ) -> Optional[str]:
        """
        Scan a single port with configured evasion techniques.
        
        Args:
            target: Target host
            port: Target port
            src_ip: Source IP (for decoys, defaults to local IP)
            
        Returns:
            Port state: "open", "closed", "filtered", or None
        """
        if src_ip is None:
            src_ip = self._get_local_ip(target)
        
        # Apply timing delay
        await self.apply_timing_delay()
        
        # Select scan method based on techniques
        techniques = self.config.techniques
        
        if EvasionTechnique.IDLE_SCAN in techniques:
            return await self.idle_scan(target, port)
        
        if EvasionTechnique.DECOY in techniques:
            return await self.scan_with_decoys(target, port, src_ip)
        
        if EvasionTechnique.FRAGMENTATION in techniques:
            return await self.scan_with_fragmentation(target, port, src_ip)
        
        # Default: basic scan with applied evasion options
        return await self._basic_evasion_scan(target, port, src_ip)
    
    async def _basic_evasion_scan(
        self,
        target: str,
        port: int,
        src_ip: str,
    ) -> Optional[str]:
        """Basic scan with source port and TTL manipulation."""
        if not self._scapy_available:
            return await self._fallback_scan(target, port)
        
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
        except ImportError:
            return await self._fallback_scan(target, port)
        
        src_port = self.get_source_port()
        
        pkt = IP(src=src_ip, dst=target) / TCP(sport=src_port, dport=port, flags="S")
        
        # Apply TTL
        if self.config.ttl is not None:
            pkt[IP].ttl = self.config.ttl
        elif self.config.ttl_style != "default":
            pkt[IP].ttl = get_ttl_for_style(self.config.ttl_style)
        
        # Apply data padding
        if self.config.data_length > 0:
            pkt = pkt / (b'\x00' * self.config.data_length)
        
        self._stats["packets_sent"] += 1
        
        try:
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            self._stats["packets_received"] += 1 if response else 0
            
            if response and response.haslayer(TCP):
                flags = response[TCP].flags
                if flags & 0x12:
                    return "open"
                elif flags & 0x14:
                    return "closed"
            
            return "filtered"
            
        except Exception as e:
            logger.debug(f"Basic evasion scan error: {e}")
            return None
    
    def _get_local_ip(self, target: str) -> str:
        """Get local IP address for reaching target."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"
    
    async def scan_ports(
        self,
        target: str,
        ports: List[int],
        callback: Optional[Callable] = None,
    ) -> Dict[int, str]:
        """
        Scan multiple ports with evasion.
        
        Args:
            target: Target host
            ports: List of ports to scan
            callback: Optional callback for each result
            
        Returns:
            Dict mapping port to state
        """
        results = {}
        src_ip = self._get_local_ip(target)
        
        # Randomize ports if configured
        if self.config.randomize_ports:
            ports = randomize_list(ports)
        
        # Respect max parallelism
        semaphore = asyncio.Semaphore(self.config.timing.max_parallelism)
        
        async def scan_with_semaphore(port: int) -> Tuple[int, Optional[str]]:
            async with semaphore:
                state = await self.scan_port(target, port, src_ip)
                if callback:
                    callback(target, port, state)
                return port, state
        
        tasks = [scan_with_semaphore(port) for port in ports]
        
        for coro in asyncio.as_completed(tasks):
            port, state = await coro
            if state:
                results[port] = state
        
        return results


# ============================================================================
# Evasion Manager
# ============================================================================

class EvasionManager:
    """
    High-level manager for applying evasion techniques.
    
    Integrates with existing scanner classes to add evasion capabilities.
    """
    
    def __init__(self, config: Optional[EvasionConfig] = None):
        self.config = config or EvasionConfig()
        self._scanner: Optional[EvasionScanner] = None
    
    @classmethod
    def from_profile(cls, profile: Union[str, EvasionProfile]) -> "EvasionManager":
        """Create manager from profile name."""
        if isinstance(profile, str):
            try:
                profile = EvasionProfile(profile.lower())
            except ValueError:
                profile = EvasionProfile.NONE
        
        config = EvasionConfig.from_profile(profile)
        return cls(config)
    
    @classmethod
    def from_cli_args(
        cls,
        evasion: Optional[str] = None,
        decoys: Optional[List[str]] = None,
        decoy_count: int = 0,
        source_port: Optional[int] = None,
        randomize_source_port: bool = False,
        common_source_port: bool = False,
        ttl: Optional[int] = None,
        ttl_style: str = "default",
        fragment: bool = False,
        fragment_mtu: int = 8,
        bad_checksum: bool = False,
        randomize_hosts: bool = False,
        randomize_ports: bool = False,
        timing_level: int = 3,
        max_parallelism: int = 100,
        scan_delay: Optional[float] = None,
        zombie_host: Optional[str] = None,
        zombie_port: int = 80,
        data_length: int = 0,
    ) -> "EvasionManager":
        """Create manager from CLI arguments."""
        # Start with profile if specified
        if evasion:
            try:
                profile = EvasionProfile(evasion.lower())
                config = EvasionConfig.from_profile(profile)
            except ValueError:
                config = EvasionConfig()
        else:
            config = EvasionConfig()
        
        # Override with specific options
        techniques = list(config.techniques)
        
        # Decoys
        if decoys or decoy_count > 0:
            config.decoy = DecoyConfig(
                decoys=decoys or [],
                random_decoys=decoy_count,
            )
            if EvasionTechnique.DECOY not in techniques:
                techniques.append(EvasionTechnique.DECOY)
        
        # Source port
        if source_port is not None:
            config.source_port = source_port
            if EvasionTechnique.SOURCE_PORT not in techniques:
                techniques.append(EvasionTechnique.SOURCE_PORT)
        config.randomize_source_port = randomize_source_port
        config.use_common_source_port = common_source_port
        
        # TTL
        if ttl is not None:
            config.ttl = ttl
            if EvasionTechnique.TTL_MANIPULATION not in techniques:
                techniques.append(EvasionTechnique.TTL_MANIPULATION)
        config.ttl_style = ttl_style
        
        # Fragmentation
        if fragment:
            config.fragmentation = FragmentConfig(
                enabled=True,
                mtu=fragment_mtu,
            )
            if EvasionTechnique.FRAGMENTATION not in techniques:
                techniques.append(EvasionTechnique.FRAGMENTATION)
        
        # Bad checksum
        if bad_checksum:
            config.bad_checksum = True
            if EvasionTechnique.BAD_CHECKSUM not in techniques:
                techniques.append(EvasionTechnique.BAD_CHECKSUM)
        
        # Randomization
        config.randomize_hosts = randomize_hosts
        config.randomize_ports = randomize_ports
        if randomize_hosts or randomize_ports:
            if EvasionTechnique.RANDOMIZE_HOSTS not in techniques:
                techniques.append(EvasionTechnique.RANDOMIZE_HOSTS)
        
        # Timing
        try:
            timing_enum = TimingLevel(timing_level)
        except ValueError:
            timing_enum = TimingLevel.NORMAL
        
        config.timing = TimingConfig(
            level=timing_enum,
            delay_ms=scan_delay * 1000 if scan_delay else None,
            max_parallelism=max_parallelism,
        )
        if timing_level != 3:  # Not normal
            if EvasionTechnique.TIMING not in techniques:
                techniques.append(EvasionTechnique.TIMING)
        
        # Idle scan
        if zombie_host:
            config.idle_scan = IdleScanConfig(
                zombie_host=zombie_host,
                zombie_port=zombie_port,
            )
            if EvasionTechnique.IDLE_SCAN not in techniques:
                techniques.append(EvasionTechnique.IDLE_SCAN)
        
        # Data length
        if data_length > 0:
            config.data_length = data_length
            if EvasionTechnique.DATA_LENGTH not in techniques:
                techniques.append(EvasionTechnique.DATA_LENGTH)
        
        config.techniques = techniques
        
        return cls(config)
    
    def get_scanner(self, timeout: float = 2.0) -> EvasionScanner:
        """Get configured evasion scanner."""
        if self._scanner is None:
            self._scanner = EvasionScanner(self.config, timeout=timeout)
        return self._scanner
    
    def apply_to_targets(
        self,
        hosts: List[str],
        ports: List[int],
    ) -> Tuple[List[str], List[int]]:
        """Apply randomization to targets."""
        if self.config.randomize_hosts:
            hosts = randomize_list(hosts)
        if self.config.randomize_ports:
            ports = randomize_list(ports)
        return hosts, ports
    
    def get_timing_delay(self) -> float:
        """Get configured timing delay."""
        return self.config.timing.get_delay()
    
    def get_max_parallelism(self) -> int:
        """Get maximum parallelism setting."""
        return self.config.timing.max_parallelism
    
    def get_source_port(self) -> int:
        """Get source port to use."""
        if self.config.source_port is not None:
            return self.config.source_port
        elif self.config.randomize_source_port or self.config.use_common_source_port:
            return get_random_source_port(self.config.use_common_source_port)
        return random.randint(49152, 65535)
    
    def get_ttl(self) -> int:
        """Get TTL value to use."""
        if self.config.ttl is not None:
            return self.config.ttl
        return get_ttl_for_style(self.config.ttl_style)
    
    def is_evasion_enabled(self) -> bool:
        """Check if any evasion technique is enabled."""
        return (
            len(self.config.techniques) > 0 or
            self.config.profile != EvasionProfile.NONE
        )
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of enabled evasion options."""
        return {
            "profile": self.config.profile.value,
            "techniques": [t.value for t in self.config.techniques],
            "timing_level": self.config.timing.level.value,
            "max_parallelism": self.config.timing.max_parallelism,
            "randomize_hosts": self.config.randomize_hosts,
            "randomize_ports": self.config.randomize_ports,
            "fragmentation": self.config.fragmentation.enabled,
            "decoys": len(self.config.decoy.decoys) + self.config.decoy.random_decoys,
            "source_port": self.config.source_port,
            "ttl": self.config.ttl,
            "ttl_style": self.config.ttl_style,
            "bad_checksum": self.config.bad_checksum,
            "idle_scan": bool(self.config.idle_scan.zombie_host),
        }


# ============================================================================
# Convenience Functions
# ============================================================================

def create_evasion_config(
    profile: str = "none",
    **kwargs,
) -> EvasionConfig:
    """Create evasion config from profile and options."""
    try:
        profile_enum = EvasionProfile(profile.lower())
    except ValueError:
        profile_enum = EvasionProfile.NONE
    
    config = EvasionConfig.from_profile(profile_enum)
    
    # Apply any additional kwargs
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
    
    return config


async def scan_with_evasion(
    target: str,
    ports: List[int],
    config: Optional[EvasionConfig] = None,
    timeout: float = 2.0,
    callback: Optional[Callable] = None,
) -> Dict[int, str]:
    """
    Convenience function to scan with evasion.
    
    Args:
        target: Target host
        ports: Ports to scan
        config: Evasion configuration
        timeout: Scan timeout
        callback: Optional callback for results
        
    Returns:
        Dict mapping port to state
    """
    if config is None:
        config = EvasionConfig()
    
    scanner = EvasionScanner(config, timeout=timeout)
    return await scanner.scan_ports(target, ports, callback=callback)
