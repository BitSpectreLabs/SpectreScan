"""
Proxy support for SpectreScan
by BitSpectreLabs

Supports SOCKS4, SOCKS4a, SOCKS5, HTTP, and HTTPS proxies
with authentication, chaining, rotation, and health checking.
"""

import socket
import struct
import asyncio
import logging
import ssl
import base64
import random
import time
from typing import List, Optional, Tuple, Dict, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


class ProxyType(Enum):
    """Proxy protocol types."""
    SOCKS4 = "socks4"
    SOCKS4A = "socks4a"
    SOCKS5 = "socks5"
    HTTP = "http"
    HTTPS = "https"


class ProxyAuthType(Enum):
    """Proxy authentication types."""
    NONE = "none"
    BASIC = "basic"          # Username/password
    NTLM = "ntlm"            # Windows NTLM (HTTP only)


class ProxyStatus(Enum):
    """Proxy health status."""
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    SLOW = "slow"
    TIMEOUT = "timeout"


@dataclass
class ProxyAuth:
    """Proxy authentication credentials."""
    username: str = ""
    password: str = ""
    auth_type: ProxyAuthType = ProxyAuthType.BASIC


@dataclass
class ProxyConfig:
    """Configuration for a single proxy."""
    host: str
    port: int
    proxy_type: ProxyType = ProxyType.SOCKS5
    auth: Optional[ProxyAuth] = None
    name: Optional[str] = None
    timeout: float = 10.0
    
    # Health tracking
    status: ProxyStatus = ProxyStatus.UNKNOWN
    last_check: Optional[float] = None
    latency_ms: Optional[float] = None
    consecutive_failures: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    
    def __post_init__(self):
        if self.name is None:
            self.name = f"{self.proxy_type.value}://{self.host}:{self.port}"
    
    @property
    def url(self) -> str:
        """Get proxy URL string."""
        auth_str = ""
        if self.auth and self.auth.username:
            auth_str = f"{self.auth.username}:{self.auth.password}@"
        return f"{self.proxy_type.value}://{auth_str}{self.host}:{self.port}"
    
    @classmethod
    def from_url(cls, url: str, timeout: float = 10.0) -> "ProxyConfig":
        """
        Create ProxyConfig from URL string.
        
        Args:
            url: Proxy URL (e.g., socks5://user:pass@127.0.0.1:1080)
            timeout: Connection timeout
            
        Returns:
            ProxyConfig instance
            
        Examples:
            >>> ProxyConfig.from_url("socks5://127.0.0.1:9050")
            >>> ProxyConfig.from_url("http://user:pass@proxy.example.com:8080")
        """
        parsed = urlparse(url)
        
        # Determine proxy type
        scheme = parsed.scheme.lower()
        try:
            proxy_type = ProxyType(scheme)
        except ValueError:
            raise ValueError(f"Unsupported proxy type: {scheme}")
        
        # Extract host and port
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or cls._default_port(proxy_type)
        
        # Extract authentication
        auth = None
        if parsed.username:
            auth = ProxyAuth(
                username=parsed.username,
                password=parsed.password or ""
            )
        
        return cls(
            host=host,
            port=port,
            proxy_type=proxy_type,
            auth=auth,
            timeout=timeout
        )
    
    @staticmethod
    def _default_port(proxy_type: ProxyType) -> int:
        """Get default port for proxy type."""
        defaults = {
            ProxyType.SOCKS4: 1080,
            ProxyType.SOCKS4A: 1080,
            ProxyType.SOCKS5: 1080,
            ProxyType.HTTP: 8080,
            ProxyType.HTTPS: 8080,
        }
        return defaults.get(proxy_type, 1080)


@dataclass
class ProxyChain:
    """Chain of proxies for multi-hop connections."""
    proxies: List[ProxyConfig] = field(default_factory=list)
    name: Optional[str] = None
    
    def add_proxy(self, proxy: ProxyConfig) -> None:
        """Add a proxy to the chain."""
        self.proxies.append(proxy)
    
    def remove_proxy(self, index: int) -> None:
        """Remove proxy at index."""
        if 0 <= index < len(self.proxies):
            self.proxies.pop(index)
    
    def __len__(self) -> int:
        return len(self.proxies)
    
    def __iter__(self):
        return iter(self.proxies)


@dataclass
class ProxyPool:
    """Pool of proxies with rotation support."""
    proxies: List[ProxyConfig] = field(default_factory=list)
    rotation_strategy: str = "round_robin"  # round_robin, random, least_used, fastest
    current_index: int = 0
    name: Optional[str] = None
    
    # Health check settings
    health_check_interval: float = 60.0  # seconds
    max_consecutive_failures: int = 3
    
    def add_proxy(self, proxy: ProxyConfig) -> None:
        """Add a proxy to the pool."""
        self.proxies.append(proxy)
    
    def remove_proxy(self, proxy: ProxyConfig) -> None:
        """Remove a proxy from the pool."""
        if proxy in self.proxies:
            self.proxies.remove(proxy)
    
    def get_healthy_proxies(self) -> List[ProxyConfig]:
        """Get list of healthy proxies."""
        return [p for p in self.proxies if p.status in (ProxyStatus.HEALTHY, ProxyStatus.UNKNOWN)]
    
    def get_next_proxy(self) -> Optional[ProxyConfig]:
        """Get next proxy based on rotation strategy."""
        healthy = self.get_healthy_proxies()
        if not healthy:
            return None
        
        if self.rotation_strategy == "random":
            return random.choice(healthy)
        
        elif self.rotation_strategy == "least_used":
            return min(healthy, key=lambda p: p.total_requests)
        
        elif self.rotation_strategy == "fastest":
            # Sort by latency, unknown latency gets low priority
            with_latency = [p for p in healthy if p.latency_ms is not None]
            if with_latency:
                return min(with_latency, key=lambda p: p.latency_ms)
            return healthy[0] if healthy else None
        
        else:  # round_robin (default)
            proxy = healthy[self.current_index % len(healthy)]
            self.current_index = (self.current_index + 1) % len(healthy)
            return proxy
    
    def mark_failure(self, proxy: ProxyConfig) -> None:
        """Mark a proxy as having failed."""
        proxy.consecutive_failures += 1
        proxy.failed_requests += 1
        if proxy.consecutive_failures >= self.max_consecutive_failures:
            proxy.status = ProxyStatus.UNHEALTHY
    
    def mark_success(self, proxy: ProxyConfig, latency_ms: float = 0) -> None:
        """Mark a proxy as having succeeded."""
        proxy.consecutive_failures = 0
        proxy.total_requests += 1
        proxy.status = ProxyStatus.HEALTHY
        if latency_ms > 0:
            proxy.latency_ms = latency_ms
    
    def __len__(self) -> int:
        return len(self.proxies)


class SOCKS4Error(Exception):
    """SOCKS4 protocol error."""
    pass


class SOCKS5Error(Exception):
    """SOCKS5 protocol error."""
    pass


class HTTPProxyError(Exception):
    """HTTP proxy error."""
    pass


class ProxyConnectionError(Exception):
    """General proxy connection error."""
    pass


class ProxyConnector:
    """
    Proxy connector for establishing connections through various proxy types.
    
    Supports SOCKS4, SOCKS4a, SOCKS5 (with authentication), HTTP, and HTTPS proxies.
    """
    
    # SOCKS4 constants
    SOCKS4_VERSION = 0x04
    SOCKS4_CMD_CONNECT = 0x01
    SOCKS4_REPLY_SUCCESS = 0x5A
    
    # SOCKS5 constants
    SOCKS5_VERSION = 0x05
    SOCKS5_CMD_CONNECT = 0x01
    SOCKS5_ADDR_IPV4 = 0x01
    SOCKS5_ADDR_DOMAIN = 0x03
    SOCKS5_ADDR_IPV6 = 0x04
    SOCKS5_AUTH_NONE = 0x00
    SOCKS5_AUTH_USERPASS = 0x02
    SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF
    
    def __init__(
        self,
        proxy: Optional[ProxyConfig] = None,
        proxy_chain: Optional[ProxyChain] = None,
        proxy_pool: Optional[ProxyPool] = None,
        timeout: float = 10.0
    ):
        """
        Initialize proxy connector.
        
        Args:
            proxy: Single proxy configuration
            proxy_chain: Chain of proxies for multi-hop
            proxy_pool: Pool of proxies with rotation
            timeout: Default connection timeout
        """
        self.proxy = proxy
        self.proxy_chain = proxy_chain
        self.proxy_pool = proxy_pool
        self.timeout = timeout
        self._current_proxy: Optional[ProxyConfig] = None
    
    async def connect(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to target through proxy.
        
        Args:
            host: Target hostname or IP
            port: Target port
            timeout: Connection timeout (uses default if not specified)
            
        Returns:
            Tuple of (StreamReader, StreamWriter)
            
        Raises:
            ProxyConnectionError: If connection fails
        """
        timeout = timeout or self.timeout
        
        # Determine which proxy to use
        if self.proxy_pool:
            self._current_proxy = self.proxy_pool.get_next_proxy()
            if not self._current_proxy:
                raise ProxyConnectionError("No healthy proxies available in pool")
        elif self.proxy_chain and len(self.proxy_chain) > 0:
            # For chains, we connect through each proxy in sequence
            return await self._connect_through_chain(host, port, timeout)
        elif self.proxy:
            self._current_proxy = self.proxy
        else:
            raise ProxyConnectionError("No proxy configured")
        
        return await self._connect_through_proxy(self._current_proxy, host, port, timeout)
    
    async def _connect_through_chain(
        self,
        host: str,
        port: int,
        timeout: float
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect through a chain of proxies."""
        if not self.proxy_chain or len(self.proxy_chain) == 0:
            raise ProxyConnectionError("Empty proxy chain")
        
        # Start with the first proxy
        proxies = list(self.proxy_chain)
        first_proxy = proxies[0]
        
        # Connect to first proxy
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(first_proxy.host, first_proxy.port),
            timeout=timeout
        )
        
        # Tunnel through each proxy to the next (or to target)
        for i, proxy in enumerate(proxies):
            if i == len(proxies) - 1:
                # Last proxy - connect to actual target
                target_host, target_port = host, port
            else:
                # Connect to next proxy in chain
                next_proxy = proxies[i + 1]
                target_host, target_port = next_proxy.host, next_proxy.port
            
            # Perform proxy handshake
            await self._proxy_handshake(reader, writer, proxy, target_host, target_port)
        
        return reader, writer
    
    async def _connect_through_proxy(
        self,
        proxy: ProxyConfig,
        host: str,
        port: int,
        timeout: float
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to target through a single proxy."""
        start_time = time.time()
        
        try:
            # Connect to proxy server
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=timeout
            )
            
            # Perform proxy-specific handshake
            await self._proxy_handshake(reader, writer, proxy, host, port)
            
            # Track latency on success
            latency_ms = (time.time() - start_time) * 1000
            if self.proxy_pool:
                self.proxy_pool.mark_success(proxy, latency_ms)
            
            return reader, writer
            
        except Exception as e:
            if self.proxy_pool:
                self.proxy_pool.mark_failure(proxy)
            raise ProxyConnectionError(f"Failed to connect through {proxy.url}: {e}") from e
    
    async def _proxy_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        proxy: ProxyConfig,
        host: str,
        port: int
    ) -> None:
        """Perform proxy-specific handshake."""
        if proxy.proxy_type == ProxyType.SOCKS4:
            await self._socks4_handshake(reader, writer, host, port)
        elif proxy.proxy_type == ProxyType.SOCKS4A:
            await self._socks4a_handshake(reader, writer, host, port)
        elif proxy.proxy_type == ProxyType.SOCKS5:
            await self._socks5_handshake(reader, writer, proxy, host, port)
        elif proxy.proxy_type in (ProxyType.HTTP, ProxyType.HTTPS):
            await self._http_connect_handshake(reader, writer, proxy, host, port)
        else:
            raise ProxyConnectionError(f"Unsupported proxy type: {proxy.proxy_type}")
    
    async def _socks4_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int
    ) -> None:
        """
        Perform SOCKS4 handshake.
        
        SOCKS4 only supports IPv4 addresses (not domain names).
        """
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            raise SOCKS4Error(f"Cannot resolve hostname: {host}") from e
        
        # Build SOCKS4 connect request
        # VN(1) | CD(1) | DSTPORT(2) | DSTIP(4) | USERID | NULL
        ip_bytes = socket.inet_aton(ip)
        request = struct.pack(
            ">BBH4sB",
            self.SOCKS4_VERSION,  # Version
            self.SOCKS4_CMD_CONNECT,  # Command
            port,  # Destination port
            ip_bytes,  # Destination IP
            0  # Null-terminated user ID
        )
        
        writer.write(request)
        await writer.drain()
        
        # Read response (8 bytes)
        response = await reader.read(8)
        if len(response) < 8:
            raise SOCKS4Error("Incomplete SOCKS4 response")
        
        # VN(1) | REP(1) | DSTPORT(2) | DSTIP(4)
        vn, rep = struct.unpack(">BB", response[:2])
        
        if rep != self.SOCKS4_REPLY_SUCCESS:
            error_msgs = {
                91: "Request rejected or failed",
                92: "Request rejected (no identd)",
                93: "Request rejected (identd mismatch)",
            }
            raise SOCKS4Error(error_msgs.get(rep, f"Unknown error: {rep}"))
    
    async def _socks4a_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int
    ) -> None:
        """
        Perform SOCKS4a handshake.
        
        SOCKS4a extends SOCKS4 to support domain names.
        """
        # Build SOCKS4a connect request with domain name
        # VN(1) | CD(1) | DSTPORT(2) | DSTIP(4, invalid) | USERID | NULL | HOSTNAME | NULL
        request = struct.pack(
            ">BBH4sB",
            self.SOCKS4_VERSION,
            self.SOCKS4_CMD_CONNECT,
            port,
            b"\x00\x00\x00\x01",  # Invalid IP signals SOCKS4a
            0  # Null-terminated user ID
        )
        # Append hostname
        request += host.encode("utf-8") + b"\x00"
        
        writer.write(request)
        await writer.drain()
        
        # Read response
        response = await reader.read(8)
        if len(response) < 8:
            raise SOCKS4Error("Incomplete SOCKS4a response")
        
        vn, rep = struct.unpack(">BB", response[:2])
        
        if rep != self.SOCKS4_REPLY_SUCCESS:
            raise SOCKS4Error(f"SOCKS4a connection failed: {rep}")
    
    async def _socks5_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        proxy: ProxyConfig,
        host: str,
        port: int
    ) -> None:
        """
        Perform SOCKS5 handshake with optional authentication.
        """
        # Determine authentication methods
        if proxy.auth and proxy.auth.username:
            methods = bytes([self.SOCKS5_AUTH_NONE, self.SOCKS5_AUTH_USERPASS])
            nmethods = 2
        else:
            methods = bytes([self.SOCKS5_AUTH_NONE])
            nmethods = 1
        
        # Send greeting
        # VER(1) | NMETHODS(1) | METHODS(1-255)
        greeting = bytes([self.SOCKS5_VERSION, nmethods]) + methods
        writer.write(greeting)
        await writer.drain()
        
        # Read server response
        response = await reader.read(2)
        if len(response) < 2:
            raise SOCKS5Error("Incomplete SOCKS5 greeting response")
        
        version, method = response[0], response[1]
        
        if version != self.SOCKS5_VERSION:
            raise SOCKS5Error(f"Invalid SOCKS5 version: {version}")
        
        if method == self.SOCKS5_AUTH_NO_ACCEPTABLE:
            raise SOCKS5Error("No acceptable authentication method")
        
        # Handle authentication
        if method == self.SOCKS5_AUTH_USERPASS:
            if not proxy.auth or not proxy.auth.username:
                raise SOCKS5Error("Server requires authentication but none provided")
            await self._socks5_authenticate(reader, writer, proxy.auth)
        elif method != self.SOCKS5_AUTH_NONE:
            raise SOCKS5Error(f"Unsupported authentication method: {method}")
        
        # Send connect request
        # VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2)
        request = bytes([self.SOCKS5_VERSION, self.SOCKS5_CMD_CONNECT, 0x00])
        
        # Add address
        try:
            # Try as IPv4
            ip_bytes = socket.inet_aton(host)
            request += bytes([self.SOCKS5_ADDR_IPV4]) + ip_bytes
        except socket.error:
            try:
                # Try as IPv6
                ip_bytes = socket.inet_pton(socket.AF_INET6, host)
                request += bytes([self.SOCKS5_ADDR_IPV6]) + ip_bytes
            except socket.error:
                # Use domain name
                host_bytes = host.encode("utf-8")
                request += bytes([self.SOCKS5_ADDR_DOMAIN, len(host_bytes)]) + host_bytes
        
        # Add port
        request += struct.pack(">H", port)
        
        writer.write(request)
        await writer.drain()
        
        # Read connect response
        response = await reader.read(4)
        if len(response) < 4:
            raise SOCKS5Error("Incomplete SOCKS5 connect response")
        
        version, rep, rsv, atyp = response
        
        if rep != 0x00:
            error_msgs = {
                0x01: "General SOCKS server failure",
                0x02: "Connection not allowed by ruleset",
                0x03: "Network unreachable",
                0x04: "Host unreachable",
                0x05: "Connection refused",
                0x06: "TTL expired",
                0x07: "Command not supported",
                0x08: "Address type not supported",
            }
            raise SOCKS5Error(error_msgs.get(rep, f"Unknown error: {rep}"))
        
        # Read bound address (we don't need it but must consume)
        if atyp == self.SOCKS5_ADDR_IPV4:
            await reader.read(4 + 2)  # IP + port
        elif atyp == self.SOCKS5_ADDR_DOMAIN:
            length = (await reader.read(1))[0]
            await reader.read(length + 2)  # domain + port
        elif atyp == self.SOCKS5_ADDR_IPV6:
            await reader.read(16 + 2)  # IP + port
    
    async def _socks5_authenticate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        auth: ProxyAuth
    ) -> None:
        """Perform SOCKS5 username/password authentication."""
        # VER(1) | ULEN(1) | UNAME | PLEN(1) | PASSWD
        username = auth.username.encode("utf-8")
        password = auth.password.encode("utf-8")
        
        request = bytes([0x01, len(username)]) + username + bytes([len(password)]) + password
        
        writer.write(request)
        await writer.drain()
        
        # Read response
        response = await reader.read(2)
        if len(response) < 2:
            raise SOCKS5Error("Incomplete authentication response")
        
        version, status = response
        if status != 0x00:
            raise SOCKS5Error("Authentication failed")
    
    async def _http_connect_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        proxy: ProxyConfig,
        host: str,
        port: int
    ) -> None:
        """
        Perform HTTP CONNECT handshake for tunneling.
        """
        # Build CONNECT request
        request = f"CONNECT {host}:{port} HTTP/1.1\r\n"
        request += f"Host: {host}:{port}\r\n"
        request += "User-Agent: SpectreScan/3.0.0\r\n"
        
        # Add authentication if provided
        if proxy.auth and proxy.auth.username:
            credentials = f"{proxy.auth.username}:{proxy.auth.password}"
            encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            request += f"Proxy-Authorization: Basic {encoded}\r\n"
        
        request += "Proxy-Connection: Keep-Alive\r\n"
        request += "\r\n"
        
        writer.write(request.encode("utf-8"))
        await writer.drain()
        
        # Read response
        response_line = await reader.readline()
        response_str = response_line.decode("utf-8", errors="ignore").strip()
        
        # Parse status line
        parts = response_str.split(" ", 2)
        if len(parts) < 2:
            raise HTTPProxyError(f"Invalid HTTP response: {response_str}")
        
        try:
            status_code = int(parts[1])
        except ValueError:
            raise HTTPProxyError(f"Invalid status code: {parts[1]}")
        
        # Read headers until empty line
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        
        if status_code != 200:
            error_msgs = {
                407: "Proxy authentication required",
                403: "Forbidden",
                502: "Bad gateway",
                503: "Service unavailable",
            }
            raise HTTPProxyError(
                error_msgs.get(status_code, f"HTTP proxy error: {status_code}")
            )
    
    def get_current_proxy(self) -> Optional[ProxyConfig]:
        """Get the currently active proxy."""
        return self._current_proxy


class ProxyHealthChecker:
    """
    Health checker for proxy servers.
    
    Tests proxy connectivity and measures latency.
    """
    
    def __init__(
        self,
        test_host: str = "www.google.com",
        test_port: int = 80,
        timeout: float = 10.0
    ):
        """
        Initialize health checker.
        
        Args:
            test_host: Host to use for connectivity test
            test_port: Port to use for connectivity test
            timeout: Test timeout
        """
        self.test_host = test_host
        self.test_port = test_port
        self.timeout = timeout
    
    async def check_proxy(self, proxy: ProxyConfig) -> ProxyStatus:
        """
        Check health of a single proxy.
        
        Args:
            proxy: Proxy configuration to test
            
        Returns:
            ProxyStatus indicating health
        """
        connector = ProxyConnector(proxy=proxy, timeout=self.timeout)
        start_time = time.time()
        
        try:
            reader, writer = await asyncio.wait_for(
                connector.connect(self.test_host, self.test_port),
                timeout=self.timeout
            )
            
            latency_ms = (time.time() - start_time) * 1000
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            # Update proxy status
            proxy.latency_ms = latency_ms
            proxy.last_check = time.time()
            proxy.consecutive_failures = 0
            
            # Determine status based on latency
            if latency_ms > 5000:  # > 5 seconds
                proxy.status = ProxyStatus.SLOW
            else:
                proxy.status = ProxyStatus.HEALTHY
            
            return proxy.status
            
        except asyncio.TimeoutError:
            proxy.status = ProxyStatus.TIMEOUT
            proxy.last_check = time.time()
            proxy.consecutive_failures += 1
            return ProxyStatus.TIMEOUT
            
        except Exception as e:
            logger.debug(f"Proxy health check failed for {proxy.url}: {e}")
            proxy.status = ProxyStatus.UNHEALTHY
            proxy.last_check = time.time()
            proxy.consecutive_failures += 1
            return ProxyStatus.UNHEALTHY
    
    async def check_pool(self, pool: ProxyPool) -> Dict[str, ProxyStatus]:
        """
        Check health of all proxies in a pool.
        
        Args:
            pool: Proxy pool to check
            
        Returns:
            Dictionary mapping proxy URLs to their status
        """
        results = {}
        tasks = [self.check_proxy(proxy) for proxy in pool.proxies]
        statuses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for proxy, status in zip(pool.proxies, statuses):
            if isinstance(status, Exception):
                results[proxy.url] = ProxyStatus.UNHEALTHY
            else:
                results[proxy.url] = status
        
        return results


def load_proxies_from_file(filepath: Union[str, Path]) -> List[ProxyConfig]:
    """
    Load proxy configurations from a file.
    
    Args:
        filepath: Path to proxy file
        
    Returns:
        List of ProxyConfig objects
        
    File format (one proxy per line):
        socks5://127.0.0.1:9050
        http://user:pass@proxy.example.com:8080
        socks4://10.0.0.1:1080
        # Comments are ignored
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If proxy URL is invalid
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Proxy file not found: {filepath}")
    
    proxies = []
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            
            try:
                proxy = ProxyConfig.from_url(line)
                proxies.append(proxy)
            except ValueError as e:
                logger.warning(f"Invalid proxy on line {line_num}: {e}")
    
    return proxies


def create_proxy_pool(
    proxies: List[ProxyConfig],
    rotation_strategy: str = "round_robin"
) -> ProxyPool:
    """
    Create a proxy pool from a list of configurations.
    
    Args:
        proxies: List of proxy configurations
        rotation_strategy: Rotation strategy (round_robin, random, least_used, fastest)
        
    Returns:
        ProxyPool instance
    """
    pool = ProxyPool(
        proxies=proxies,
        rotation_strategy=rotation_strategy
    )
    return pool


def create_tor_proxy(
    host: str = "127.0.0.1",
    port: int = 9050
) -> ProxyConfig:
    """
    Create a Tor proxy configuration.
    
    Args:
        host: Tor SOCKS host (default: 127.0.0.1)
        port: Tor SOCKS port (default: 9050)
        
    Returns:
        ProxyConfig for Tor
    """
    return ProxyConfig(
        host=host,
        port=port,
        proxy_type=ProxyType.SOCKS5,
        name="Tor",
        timeout=30.0  # Tor is slower
    )


# Synchronous wrapper for testing and simple use cases
def connect_through_proxy_sync(
    proxy: ProxyConfig,
    host: str,
    port: int,
    timeout: float = 10.0
) -> socket.socket:
    """
    Connect to target through proxy (synchronous version).
    
    Args:
        proxy: Proxy configuration
        host: Target host
        port: Target port
        timeout: Connection timeout
        
    Returns:
        Connected socket
        
    Raises:
        ProxyConnectionError: If connection fails
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        # Connect to proxy
        sock.connect((proxy.host, proxy.port))
        
        if proxy.proxy_type == ProxyType.SOCKS5:
            _socks5_handshake_sync(sock, proxy, host, port)
        elif proxy.proxy_type == ProxyType.SOCKS4:
            _socks4_handshake_sync(sock, host, port)
        elif proxy.proxy_type == ProxyType.SOCKS4A:
            _socks4a_handshake_sync(sock, host, port)
        elif proxy.proxy_type in (ProxyType.HTTP, ProxyType.HTTPS):
            _http_connect_sync(sock, proxy, host, port)
        else:
            raise ProxyConnectionError(f"Unsupported proxy type: {proxy.proxy_type}")
        
        return sock
        
    except Exception as e:
        sock.close()
        raise ProxyConnectionError(f"Proxy connection failed: {e}") from e


def _socks5_handshake_sync(
    sock: socket.socket,
    proxy: ProxyConfig,
    host: str,
    port: int
) -> None:
    """Synchronous SOCKS5 handshake."""
    # Authentication methods
    if proxy.auth and proxy.auth.username:
        sock.sendall(bytes([0x05, 0x02, 0x00, 0x02]))
    else:
        sock.sendall(bytes([0x05, 0x01, 0x00]))
    
    response = sock.recv(2)
    if len(response) < 2 or response[0] != 0x05:
        raise SOCKS5Error("Invalid SOCKS5 response")
    
    method = response[1]
    
    if method == 0x02:  # Username/password auth
        if not proxy.auth:
            raise SOCKS5Error("Authentication required but not provided")
        username = proxy.auth.username.encode("utf-8")
        password = proxy.auth.password.encode("utf-8")
        auth_request = bytes([0x01, len(username)]) + username + bytes([len(password)]) + password
        sock.sendall(auth_request)
        auth_response = sock.recv(2)
        if auth_response[1] != 0x00:
            raise SOCKS5Error("Authentication failed")
    elif method == 0xFF:
        raise SOCKS5Error("No acceptable authentication method")
    
    # Connect request
    request = bytes([0x05, 0x01, 0x00])
    try:
        ip_bytes = socket.inet_aton(host)
        request += bytes([0x01]) + ip_bytes
    except socket.error:
        host_bytes = host.encode("utf-8")
        request += bytes([0x03, len(host_bytes)]) + host_bytes
    request += struct.pack(">H", port)
    
    sock.sendall(request)
    
    response = sock.recv(4)
    if response[1] != 0x00:
        raise SOCKS5Error(f"SOCKS5 connect failed: {response[1]}")
    
    # Consume bound address
    atyp = response[3]
    if atyp == 0x01:
        sock.recv(4 + 2)
    elif atyp == 0x03:
        length = sock.recv(1)[0]
        sock.recv(length + 2)
    elif atyp == 0x04:
        sock.recv(16 + 2)


def _socks4_handshake_sync(sock: socket.socket, host: str, port: int) -> None:
    """Synchronous SOCKS4 handshake."""
    ip = socket.gethostbyname(host)
    ip_bytes = socket.inet_aton(ip)
    request = struct.pack(">BBH4sB", 0x04, 0x01, port, ip_bytes, 0)
    sock.sendall(request)
    response = sock.recv(8)
    if len(response) < 8 or response[1] != 0x5A:
        raise SOCKS4Error(f"SOCKS4 connect failed: {response[1] if len(response) > 1 else 'no response'}")


def _socks4a_handshake_sync(sock: socket.socket, host: str, port: int) -> None:
    """Synchronous SOCKS4a handshake."""
    request = struct.pack(">BBH4sB", 0x04, 0x01, port, b"\x00\x00\x00\x01", 0)
    request += host.encode("utf-8") + b"\x00"
    sock.sendall(request)
    response = sock.recv(8)
    if len(response) < 8 or response[1] != 0x5A:
        raise SOCKS4Error(f"SOCKS4a connect failed: {response[1] if len(response) > 1 else 'no response'}")


def _http_connect_sync(
    sock: socket.socket,
    proxy: ProxyConfig,
    host: str,
    port: int
) -> None:
    """Synchronous HTTP CONNECT."""
    request = f"CONNECT {host}:{port} HTTP/1.1\r\n"
    request += f"Host: {host}:{port}\r\n"
    
    if proxy.auth and proxy.auth.username:
        credentials = f"{proxy.auth.username}:{proxy.auth.password}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        request += f"Proxy-Authorization: Basic {encoded}\r\n"
    
    request += "\r\n"
    sock.sendall(request.encode("utf-8"))
    
    # Read response
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(1024)
        if not chunk:
            break
        response += chunk
    
    first_line = response.split(b"\r\n")[0].decode("utf-8", errors="ignore")
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        raise HTTPProxyError(f"Invalid response: {first_line}")
    
    status_code = int(parts[1])
    if status_code != 200:
        raise HTTPProxyError(f"HTTP CONNECT failed: {status_code}")
