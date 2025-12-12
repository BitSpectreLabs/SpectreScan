"""
Comprehensive unit tests for SpectreScan proxy module
by BitSpectreLabs

Tests for spectrescan.core.proxy module.
"""

import pytest
import asyncio
import socket
import struct
from unittest.mock import patch, MagicMock, AsyncMock, mock_open
from pathlib import Path

from spectrescan.core.proxy import (
    ProxyType,
    ProxyAuthType,
    ProxyStatus,
    ProxyAuth,
    ProxyConfig,
    ProxyChain,
    ProxyPool,
    ProxyConnector,
    ProxyHealthChecker,
    SOCKS4Error,
    SOCKS5Error,
    HTTPProxyError,
    ProxyConnectionError,
    load_proxies_from_file,
    create_proxy_pool,
    create_tor_proxy,
    connect_through_proxy_sync,
)


class TestProxyType:
    """Tests for ProxyType enum."""
    
    def test_socks4_value(self):
        """Test SOCKS4 type value."""
        assert ProxyType.SOCKS4.value == "socks4"
    
    def test_socks4a_value(self):
        """Test SOCKS4a type value."""
        assert ProxyType.SOCKS4A.value == "socks4a"
    
    def test_socks5_value(self):
        """Test SOCKS5 type value."""
        assert ProxyType.SOCKS5.value == "socks5"
    
    def test_http_value(self):
        """Test HTTP type value."""
        assert ProxyType.HTTP.value == "http"
    
    def test_https_value(self):
        """Test HTTPS type value."""
        assert ProxyType.HTTPS.value == "https"


class TestProxyAuthType:
    """Tests for ProxyAuthType enum."""
    
    def test_none_value(self):
        """Test NONE auth type."""
        assert ProxyAuthType.NONE.value == "none"
    
    def test_basic_value(self):
        """Test BASIC auth type."""
        assert ProxyAuthType.BASIC.value == "basic"
    
    def test_ntlm_value(self):
        """Test NTLM auth type."""
        assert ProxyAuthType.NTLM.value == "ntlm"


class TestProxyStatus:
    """Tests for ProxyStatus enum."""
    
    def test_all_statuses(self):
        """Test all status values."""
        assert ProxyStatus.UNKNOWN.value == "unknown"
        assert ProxyStatus.HEALTHY.value == "healthy"
        assert ProxyStatus.UNHEALTHY.value == "unhealthy"
        assert ProxyStatus.SLOW.value == "slow"
        assert ProxyStatus.TIMEOUT.value == "timeout"


class TestProxyAuth:
    """Tests for ProxyAuth dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        auth = ProxyAuth()
        assert auth.username == ""
        assert auth.password == ""
        assert auth.auth_type == ProxyAuthType.BASIC
    
    def test_with_credentials(self):
        """Test with credentials."""
        auth = ProxyAuth(username="user", password="pass")
        assert auth.username == "user"
        assert auth.password == "pass"
    
    def test_custom_auth_type(self):
        """Test custom auth type."""
        auth = ProxyAuth(username="user", password="pass", auth_type=ProxyAuthType.NTLM)
        assert auth.auth_type == ProxyAuthType.NTLM


class TestProxyConfig:
    """Tests for ProxyConfig dataclass."""
    
    def test_basic_config(self):
        """Test basic configuration."""
        config = ProxyConfig(host="127.0.0.1", port=1080)
        assert config.host == "127.0.0.1"
        assert config.port == 1080
        assert config.proxy_type == ProxyType.SOCKS5
        assert config.auth is None
        assert config.status == ProxyStatus.UNKNOWN
    
    def test_auto_name_generation(self):
        """Test automatic name generation."""
        config = ProxyConfig(host="proxy.example.com", port=8080, proxy_type=ProxyType.HTTP)
        assert config.name == "http://proxy.example.com:8080"
    
    def test_custom_name(self):
        """Test custom name."""
        config = ProxyConfig(host="127.0.0.1", port=9050, name="My Tor Proxy")
        assert config.name == "My Tor Proxy"
    
    def test_url_property_without_auth(self):
        """Test URL property without authentication."""
        config = ProxyConfig(host="127.0.0.1", port=1080)
        assert config.url == "socks5://127.0.0.1:1080"
    
    def test_url_property_with_auth(self):
        """Test URL property with authentication."""
        auth = ProxyAuth(username="user", password="pass")
        config = ProxyConfig(host="proxy.com", port=8080, proxy_type=ProxyType.HTTP, auth=auth)
        assert config.url == "http://user:pass@proxy.com:8080"
    
    def test_from_url_socks5(self):
        """Test creating config from SOCKS5 URL."""
        config = ProxyConfig.from_url("socks5://127.0.0.1:9050")
        assert config.host == "127.0.0.1"
        assert config.port == 9050
        assert config.proxy_type == ProxyType.SOCKS5
        assert config.auth is None
    
    def test_from_url_with_auth(self):
        """Test creating config from URL with authentication."""
        config = ProxyConfig.from_url("http://admin:secret@proxy.example.com:8080")
        assert config.host == "proxy.example.com"
        assert config.port == 8080
        assert config.proxy_type == ProxyType.HTTP
        assert config.auth is not None
        assert config.auth.username == "admin"
        assert config.auth.password == "secret"
    
    def test_from_url_socks4(self):
        """Test creating config from SOCKS4 URL."""
        config = ProxyConfig.from_url("socks4://10.0.0.1:1080")
        assert config.proxy_type == ProxyType.SOCKS4
    
    def test_from_url_socks4a(self):
        """Test creating config from SOCKS4a URL."""
        config = ProxyConfig.from_url("socks4a://10.0.0.1:1080")
        assert config.proxy_type == ProxyType.SOCKS4A
    
    def test_from_url_https(self):
        """Test creating config from HTTPS proxy URL."""
        config = ProxyConfig.from_url("https://secure.proxy.com:443")
        assert config.proxy_type == ProxyType.HTTPS
    
    def test_from_url_default_port_socks5(self):
        """Test default port for SOCKS5."""
        config = ProxyConfig.from_url("socks5://127.0.0.1")
        assert config.port == 1080
    
    def test_from_url_default_port_http(self):
        """Test default port for HTTP."""
        config = ProxyConfig.from_url("http://proxy.com")
        assert config.port == 8080
    
    def test_from_url_invalid_scheme(self):
        """Test invalid proxy scheme."""
        with pytest.raises(ValueError, match="Unsupported proxy type"):
            ProxyConfig.from_url("ftp://invalid.com:21")
    
    def test_from_url_custom_timeout(self):
        """Test custom timeout."""
        config = ProxyConfig.from_url("socks5://127.0.0.1:9050", timeout=30.0)
        assert config.timeout == 30.0
    
    def test_health_tracking_defaults(self):
        """Test health tracking defaults."""
        config = ProxyConfig(host="127.0.0.1", port=1080)
        assert config.last_check is None
        assert config.latency_ms is None
        assert config.consecutive_failures == 0
        assert config.total_requests == 0
        assert config.failed_requests == 0


class TestProxyChain:
    """Tests for ProxyChain dataclass."""
    
    def test_empty_chain(self):
        """Test empty chain."""
        chain = ProxyChain()
        assert len(chain) == 0
        assert list(chain) == []
    
    def test_add_proxy(self):
        """Test adding proxies."""
        chain = ProxyChain()
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy2 = ProxyConfig(host="proxy2.com", port=1080)
        
        chain.add_proxy(proxy1)
        chain.add_proxy(proxy2)
        
        assert len(chain) == 2
    
    def test_remove_proxy(self):
        """Test removing proxies."""
        chain = ProxyChain()
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy2 = ProxyConfig(host="proxy2.com", port=1080)
        
        chain.add_proxy(proxy1)
        chain.add_proxy(proxy2)
        chain.remove_proxy(0)
        
        assert len(chain) == 1
    
    def test_remove_invalid_index(self):
        """Test removing from invalid index."""
        chain = ProxyChain()
        chain.remove_proxy(5)  # Should not raise
        assert len(chain) == 0
    
    def test_iteration(self):
        """Test iterating over chain."""
        chain = ProxyChain()
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy2 = ProxyConfig(host="proxy2.com", port=1080)
        
        chain.add_proxy(proxy1)
        chain.add_proxy(proxy2)
        
        proxies = list(chain)
        assert len(proxies) == 2
        assert proxies[0] == proxy1
        assert proxies[1] == proxy2
    
    def test_custom_name(self):
        """Test custom chain name."""
        chain = ProxyChain(name="My Chain")
        assert chain.name == "My Chain"


class TestProxyPool:
    """Tests for ProxyPool dataclass."""
    
    def test_empty_pool(self):
        """Test empty pool."""
        pool = ProxyPool()
        assert len(pool) == 0
    
    def test_add_proxy(self):
        """Test adding proxies to pool."""
        pool = ProxyPool()
        proxy = ProxyConfig(host="proxy.com", port=1080)
        pool.add_proxy(proxy)
        assert len(pool) == 1
    
    def test_remove_proxy(self):
        """Test removing proxies from pool."""
        pool = ProxyPool()
        proxy = ProxyConfig(host="proxy.com", port=1080)
        pool.add_proxy(proxy)
        pool.remove_proxy(proxy)
        assert len(pool) == 0
    
    def test_get_healthy_proxies(self):
        """Test getting healthy proxies."""
        pool = ProxyPool()
        healthy = ProxyConfig(host="healthy.com", port=1080)
        healthy.status = ProxyStatus.HEALTHY
        
        unhealthy = ProxyConfig(host="unhealthy.com", port=1080)
        unhealthy.status = ProxyStatus.UNHEALTHY
        
        unknown = ProxyConfig(host="unknown.com", port=1080)
        unknown.status = ProxyStatus.UNKNOWN
        
        pool.add_proxy(healthy)
        pool.add_proxy(unhealthy)
        pool.add_proxy(unknown)
        
        result = pool.get_healthy_proxies()
        assert len(result) == 2
        assert healthy in result
        assert unknown in result
        assert unhealthy not in result
    
    def test_get_next_proxy_round_robin(self):
        """Test round robin rotation."""
        pool = ProxyPool(rotation_strategy="round_robin")
        
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy1.status = ProxyStatus.HEALTHY
        proxy2 = ProxyConfig(host="proxy2.com", port=1080)
        proxy2.status = ProxyStatus.HEALTHY
        
        pool.add_proxy(proxy1)
        pool.add_proxy(proxy2)
        
        # Round robin should cycle
        first = pool.get_next_proxy()
        second = pool.get_next_proxy()
        third = pool.get_next_proxy()
        
        assert first == proxy1
        assert second == proxy2
        assert third == proxy1
    
    def test_get_next_proxy_random(self):
        """Test random rotation."""
        pool = ProxyPool(rotation_strategy="random")
        
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy1.status = ProxyStatus.HEALTHY
        
        pool.add_proxy(proxy1)
        
        result = pool.get_next_proxy()
        assert result == proxy1
    
    def test_get_next_proxy_least_used(self):
        """Test least used rotation."""
        pool = ProxyPool(rotation_strategy="least_used")
        
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy1.status = ProxyStatus.HEALTHY
        proxy1.total_requests = 10
        
        proxy2 = ProxyConfig(host="proxy2.com", port=1080)
        proxy2.status = ProxyStatus.HEALTHY
        proxy2.total_requests = 5
        
        pool.add_proxy(proxy1)
        pool.add_proxy(proxy2)
        
        result = pool.get_next_proxy()
        assert result == proxy2  # proxy2 has fewer requests
    
    def test_get_next_proxy_fastest(self):
        """Test fastest rotation."""
        pool = ProxyPool(rotation_strategy="fastest")
        
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy1.status = ProxyStatus.HEALTHY
        proxy1.latency_ms = 200
        
        proxy2 = ProxyConfig(host="proxy2.com", port=1080)
        proxy2.status = ProxyStatus.HEALTHY
        proxy2.latency_ms = 50
        
        pool.add_proxy(proxy1)
        pool.add_proxy(proxy2)
        
        result = pool.get_next_proxy()
        assert result == proxy2  # proxy2 is faster
    
    def test_get_next_proxy_no_healthy(self):
        """Test when no healthy proxies available."""
        pool = ProxyPool()
        
        proxy = ProxyConfig(host="proxy.com", port=1080)
        proxy.status = ProxyStatus.UNHEALTHY
        pool.add_proxy(proxy)
        
        result = pool.get_next_proxy()
        assert result is None
    
    def test_mark_failure(self):
        """Test marking proxy failure."""
        pool = ProxyPool(max_consecutive_failures=3)
        proxy = ProxyConfig(host="proxy.com", port=1080)
        proxy.status = ProxyStatus.HEALTHY
        pool.add_proxy(proxy)
        
        pool.mark_failure(proxy)
        assert proxy.consecutive_failures == 1
        assert proxy.failed_requests == 1
        assert proxy.status == ProxyStatus.HEALTHY  # Not unhealthy yet
        
        pool.mark_failure(proxy)
        pool.mark_failure(proxy)
        
        assert proxy.consecutive_failures == 3
        assert proxy.status == ProxyStatus.UNHEALTHY  # Now unhealthy
    
    def test_mark_success(self):
        """Test marking proxy success."""
        pool = ProxyPool()
        proxy = ProxyConfig(host="proxy.com", port=1080)
        proxy.consecutive_failures = 2
        pool.add_proxy(proxy)
        
        pool.mark_success(proxy, latency_ms=100)
        
        assert proxy.consecutive_failures == 0
        assert proxy.total_requests == 1
        assert proxy.status == ProxyStatus.HEALTHY
        assert proxy.latency_ms == 100


class TestProxyConnector:
    """Tests for ProxyConnector class."""
    
    def test_init_with_single_proxy(self):
        """Test initialization with single proxy."""
        proxy = ProxyConfig(host="proxy.com", port=1080)
        connector = ProxyConnector(proxy=proxy)
        assert connector.proxy == proxy
        assert connector.proxy_chain is None
        assert connector.proxy_pool is None
    
    def test_init_with_chain(self):
        """Test initialization with proxy chain."""
        chain = ProxyChain()
        chain.add_proxy(ProxyConfig(host="proxy1.com", port=1080))
        connector = ProxyConnector(proxy_chain=chain)
        assert connector.proxy_chain == chain
    
    def test_init_with_pool(self):
        """Test initialization with proxy pool."""
        pool = ProxyPool()
        pool.add_proxy(ProxyConfig(host="proxy.com", port=1080))
        connector = ProxyConnector(proxy_pool=pool)
        assert connector.proxy_pool == pool
    
    @pytest.mark.asyncio
    async def test_connect_no_proxy(self):
        """Test connect without proxy configured."""
        connector = ProxyConnector()
        with pytest.raises(ProxyConnectionError, match="No proxy configured"):
            await connector.connect("target.com", 80)
    
    @pytest.mark.asyncio
    async def test_connect_no_healthy_proxies(self):
        """Test connect with no healthy proxies in pool."""
        pool = ProxyPool()
        proxy = ProxyConfig(host="proxy.com", port=1080)
        proxy.status = ProxyStatus.UNHEALTHY
        pool.add_proxy(proxy)
        
        connector = ProxyConnector(proxy_pool=pool)
        with pytest.raises(ProxyConnectionError, match="No healthy proxies"):
            await connector.connect("target.com", 80)
    
    def test_get_current_proxy(self):
        """Test getting current proxy."""
        connector = ProxyConnector()
        assert connector.get_current_proxy() is None


class TestProxyConnectorSOCKS5:
    """Tests for SOCKS5 handshake in ProxyConnector."""
    
    @pytest.mark.asyncio
    async def test_socks5_connect_success(self):
        """Test successful SOCKS5 connection."""
        proxy = ProxyConfig(host="127.0.0.1", port=1080)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            # SOCKS5 greeting response (no auth)
            # Connect response (success)
            mock_reader.read = AsyncMock(side_effect=[
                bytes([0x05, 0x00]),  # Greeting response
                bytes([0x05, 0x00, 0x00, 0x01]),  # Connect response header
                bytes([127, 0, 0, 1, 0, 80]),  # Bound address
            ])
            
            reader, writer = await connector.connect("target.com", 80)
            
            assert reader == mock_reader
            assert writer == mock_writer
    
    @pytest.mark.asyncio
    async def test_socks5_connect_with_auth(self):
        """Test SOCKS5 connection with authentication."""
        auth = ProxyAuth(username="user", password="pass")
        proxy = ProxyConfig(host="127.0.0.1", port=1080, auth=auth)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            mock_reader.read = AsyncMock(side_effect=[
                bytes([0x05, 0x02]),  # Greeting response (auth required)
                bytes([0x01, 0x00]),  # Auth success
                bytes([0x05, 0x00, 0x00, 0x01]),  # Connect response
                bytes([127, 0, 0, 1, 0, 80]),  # Bound address
            ])
            
            reader, writer = await connector.connect("target.com", 80)
            
            assert reader == mock_reader
    
    @pytest.mark.asyncio
    async def test_socks5_auth_failure(self):
        """Test SOCKS5 authentication failure."""
        auth = ProxyAuth(username="user", password="wrong")
        proxy = ProxyConfig(host="127.0.0.1", port=1080, auth=auth)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            mock_reader.read = AsyncMock(side_effect=[
                bytes([0x05, 0x02]),  # Auth required
                bytes([0x01, 0x01]),  # Auth failed
            ])
            
            with pytest.raises(ProxyConnectionError):
                await connector.connect("target.com", 80)


class TestProxyConnectorSOCKS4:
    """Tests for SOCKS4 handshake in ProxyConnector."""
    
    @pytest.mark.asyncio
    async def test_socks4_connect_success(self):
        """Test successful SOCKS4 connection."""
        proxy = ProxyConfig(host="127.0.0.1", port=1080, proxy_type=ProxyType.SOCKS4)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            with patch('socket.gethostbyname', return_value='93.184.216.34'):
                mock_reader = AsyncMock()
                mock_writer = MagicMock()
                mock_writer.drain = AsyncMock()
                mock_conn.return_value = (mock_reader, mock_writer)
                
                # SOCKS4 success response
                mock_reader.read = AsyncMock(return_value=bytes([0x00, 0x5A, 0, 0, 0, 0, 0, 0]))
                
                reader, writer = await connector.connect("example.com", 80)
                
                assert reader == mock_reader
    
    @pytest.mark.asyncio
    async def test_socks4a_connect_success(self):
        """Test successful SOCKS4a connection with domain."""
        proxy = ProxyConfig(host="127.0.0.1", port=1080, proxy_type=ProxyType.SOCKS4A)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            mock_reader.read = AsyncMock(return_value=bytes([0x00, 0x5A, 0, 0, 0, 0, 0, 0]))
            
            reader, writer = await connector.connect("example.com", 80)
            
            assert reader == mock_reader


class TestProxyConnectorHTTP:
    """Tests for HTTP CONNECT in ProxyConnector."""
    
    @pytest.mark.asyncio
    async def test_http_connect_success(self):
        """Test successful HTTP CONNECT."""
        proxy = ProxyConfig(host="proxy.com", port=8080, proxy_type=ProxyType.HTTP)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            mock_reader.readline = AsyncMock(side_effect=[
                b"HTTP/1.1 200 Connection established\r\n",
                b"\r\n",
            ])
            
            reader, writer = await connector.connect("target.com", 443)
            
            assert reader == mock_reader
    
    @pytest.mark.asyncio
    async def test_http_connect_with_auth(self):
        """Test HTTP CONNECT with authentication."""
        auth = ProxyAuth(username="admin", password="secret")
        proxy = ProxyConfig(host="proxy.com", port=8080, proxy_type=ProxyType.HTTP, auth=auth)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            mock_reader.readline = AsyncMock(side_effect=[
                b"HTTP/1.1 200 Connection established\r\n",
                b"\r\n",
            ])
            
            reader, writer = await connector.connect("target.com", 443)
            
            # Check that auth header was included
            call_args = mock_writer.write.call_args[0][0]
            assert b"Proxy-Authorization: Basic" in call_args
    
    @pytest.mark.asyncio
    async def test_http_connect_407_error(self):
        """Test HTTP CONNECT 407 Proxy Authentication Required."""
        proxy = ProxyConfig(host="proxy.com", port=8080, proxy_type=ProxyType.HTTP)
        connector = ProxyConnector(proxy=proxy, timeout=5.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            mock_reader.readline = AsyncMock(side_effect=[
                b"HTTP/1.1 407 Proxy Authentication Required\r\n",
                b"\r\n",
            ])
            
            with pytest.raises(ProxyConnectionError):
                await connector.connect("target.com", 443)


class TestProxyHealthChecker:
    """Tests for ProxyHealthChecker class."""
    
    def test_init_defaults(self):
        """Test default initialization."""
        checker = ProxyHealthChecker()
        assert checker.test_host == "www.google.com"
        assert checker.test_port == 80
        assert checker.timeout == 10.0
    
    def test_init_custom(self):
        """Test custom initialization."""
        checker = ProxyHealthChecker(
            test_host="example.com",
            test_port=443,
            timeout=5.0
        )
        assert checker.test_host == "example.com"
        assert checker.test_port == 443
        assert checker.timeout == 5.0
    
    @pytest.mark.asyncio
    async def test_check_proxy_healthy(self):
        """Test checking a healthy proxy."""
        checker = ProxyHealthChecker(timeout=1.0)
        proxy = ProxyConfig(host="127.0.0.1", port=1080)
        
        with patch.object(ProxyConnector, 'connect', new_callable=AsyncMock) as mock_connect:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            status = await checker.check_proxy(proxy)
            
            assert status == ProxyStatus.HEALTHY
            assert proxy.status == ProxyStatus.HEALTHY
            assert proxy.latency_ms is not None
    
    @pytest.mark.asyncio
    async def test_check_proxy_timeout(self):
        """Test checking a timed out proxy."""
        checker = ProxyHealthChecker(timeout=0.1)
        proxy = ProxyConfig(host="127.0.0.1", port=1080)
        
        with patch.object(ProxyConnector, 'connect', new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = asyncio.TimeoutError()
            
            status = await checker.check_proxy(proxy)
            
            assert status == ProxyStatus.TIMEOUT
            assert proxy.status == ProxyStatus.TIMEOUT
    
    @pytest.mark.asyncio
    async def test_check_proxy_unhealthy(self):
        """Test checking an unhealthy proxy."""
        checker = ProxyHealthChecker(timeout=1.0)
        proxy = ProxyConfig(host="127.0.0.1", port=1080)
        
        with patch.object(ProxyConnector, 'connect', new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = ConnectionRefusedError()
            
            status = await checker.check_proxy(proxy)
            
            assert status == ProxyStatus.UNHEALTHY
            assert proxy.status == ProxyStatus.UNHEALTHY
    
    @pytest.mark.asyncio
    async def test_check_pool(self):
        """Test checking entire pool."""
        checker = ProxyHealthChecker(timeout=1.0)
        pool = ProxyPool()
        
        proxy1 = ProxyConfig(host="proxy1.com", port=1080)
        proxy2 = ProxyConfig(host="proxy2.com", port=1080)
        pool.add_proxy(proxy1)
        pool.add_proxy(proxy2)
        
        with patch.object(checker, 'check_proxy', new_callable=AsyncMock) as mock_check:
            mock_check.side_effect = [ProxyStatus.HEALTHY, ProxyStatus.UNHEALTHY]
            
            results = await checker.check_pool(pool)
            
            assert len(results) == 2


class TestLoadProxiesFromFile:
    """Tests for load_proxies_from_file function."""
    
    def test_load_valid_file(self):
        """Test loading valid proxy file."""
        content = """
# Comment line
socks5://127.0.0.1:9050
http://proxy.example.com:8080
socks4://10.0.0.1:1080

# Another comment
https://secure.proxy.com:443
"""
        with patch("builtins.open", mock_open(read_data=content)):
            with patch.object(Path, 'exists', return_value=True):
                proxies = load_proxies_from_file("proxies.txt")
                
                assert len(proxies) == 4
                assert proxies[0].proxy_type == ProxyType.SOCKS5
                assert proxies[1].proxy_type == ProxyType.HTTP
                assert proxies[2].proxy_type == ProxyType.SOCKS4
                assert proxies[3].proxy_type == ProxyType.HTTPS
    
    def test_load_file_not_found(self):
        """Test loading non-existent file."""
        with patch.object(Path, 'exists', return_value=False):
            with pytest.raises(FileNotFoundError):
                load_proxies_from_file("nonexistent.txt")
    
    def test_load_with_auth(self):
        """Test loading proxies with authentication."""
        content = "http://user:pass@proxy.com:8080\n"
        
        with patch("builtins.open", mock_open(read_data=content)):
            with patch.object(Path, 'exists', return_value=True):
                proxies = load_proxies_from_file("proxies.txt")
                
                assert len(proxies) == 1
                assert proxies[0].auth is not None
                assert proxies[0].auth.username == "user"
                assert proxies[0].auth.password == "pass"
    
    def test_load_skips_invalid(self):
        """Test that invalid proxy URLs are skipped."""
        content = """
socks5://valid.proxy.com:1080
invalid://bad.proxy.com:1234
http://another-valid.com:8080
"""
        with patch("builtins.open", mock_open(read_data=content)):
            with patch.object(Path, 'exists', return_value=True):
                proxies = load_proxies_from_file("proxies.txt")
                
                assert len(proxies) == 2


class TestCreateProxyPool:
    """Tests for create_proxy_pool function."""
    
    def test_create_empty_pool(self):
        """Test creating empty pool."""
        pool = create_proxy_pool([])
        assert len(pool) == 0
    
    def test_create_with_proxies(self):
        """Test creating pool with proxies."""
        proxies = [
            ProxyConfig(host="proxy1.com", port=1080),
            ProxyConfig(host="proxy2.com", port=1080),
        ]
        pool = create_proxy_pool(proxies)
        assert len(pool) == 2
    
    def test_create_with_rotation_strategy(self):
        """Test creating pool with specific rotation strategy."""
        proxies = [ProxyConfig(host="proxy.com", port=1080)]
        pool = create_proxy_pool(proxies, rotation_strategy="random")
        assert pool.rotation_strategy == "random"


class TestCreateTorProxy:
    """Tests for create_tor_proxy function."""
    
    def test_default_tor_config(self):
        """Test default Tor configuration."""
        proxy = create_tor_proxy()
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 9050
        assert proxy.proxy_type == ProxyType.SOCKS5
        assert proxy.name == "Tor"
        assert proxy.timeout == 30.0
    
    def test_custom_tor_config(self):
        """Test custom Tor configuration."""
        proxy = create_tor_proxy(host="192.168.1.100", port=9150)
        assert proxy.host == "192.168.1.100"
        assert proxy.port == 9150


class TestSyncProxyConnection:
    """Tests for synchronous proxy connection functions."""
    
    def test_connect_through_proxy_sync_socks5(self):
        """Test synchronous SOCKS5 connection."""
        proxy = ProxyConfig(host="127.0.0.1", port=1080)
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # SOCKS5 responses: greeting, connect header, bound address (IPv4 + port)
            mock_socket.recv.side_effect = [
                bytes([0x05, 0x00]),  # Greeting response (no auth)
                bytes([0x05, 0x00, 0x00, 0x01]),  # Connect response header (success, IPv4)
                bytes([127, 0, 0, 1, 0, 80]),  # Bound address (4 bytes IP + 2 bytes port)
            ]
            
            sock = connect_through_proxy_sync(proxy, "target.com", 80)
            
            assert sock == mock_socket
            mock_socket.connect.assert_called_once()
    
    def test_connect_through_proxy_sync_connection_error(self):
        """Test synchronous connection failure."""
        proxy = ProxyConfig(host="127.0.0.1", port=1080)
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = ConnectionRefusedError()
            
            with pytest.raises(ProxyConnectionError):
                connect_through_proxy_sync(proxy, "target.com", 80)


class TestExceptions:
    """Tests for proxy exceptions."""
    
    def test_socks4_error(self):
        """Test SOCKS4Error exception."""
        error = SOCKS4Error("Connection failed")
        assert str(error) == "Connection failed"
    
    def test_socks5_error(self):
        """Test SOCKS5Error exception."""
        error = SOCKS5Error("Authentication failed")
        assert str(error) == "Authentication failed"
    
    def test_http_proxy_error(self):
        """Test HTTPProxyError exception."""
        error = HTTPProxyError("407 Proxy Auth Required")
        assert str(error) == "407 Proxy Auth Required"
    
    def test_proxy_connection_error(self):
        """Test ProxyConnectionError exception."""
        error = ProxyConnectionError("No proxy available")
        assert str(error) == "No proxy available"
