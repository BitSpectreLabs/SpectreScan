"""
Comprehensive unit tests for SpectreScan async scanner module
by BitSpectreLabs

Tests for spectrescan.core.async_scan module to increase coverage.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from spectrescan.core.async_scan import AsyncScanner
from spectrescan.core.utils import ScanResult


class TestAsyncScannerInit:
    """Tests for AsyncScanner initialization."""
    
    def test_default_values(self):
        """Test default initialization values."""
        scanner = AsyncScanner()
        assert scanner.timeout >= 1.0
        assert scanner.max_concurrent >= 100
        assert scanner.rate_limit is None
    
    def test_custom_timeout(self):
        """Test custom timeout."""
        scanner = AsyncScanner(timeout=5.0)
        assert scanner.timeout == 5.0
    
    def test_custom_max_concurrent(self):
        """Test custom max concurrent connections."""
        scanner = AsyncScanner(max_concurrent=500)
        assert scanner.max_concurrent == 500
    
    def test_with_rate_limit(self):
        """Test with rate limiting enabled."""
        scanner = AsyncScanner(rate_limit=100)
        assert scanner.rate_limit == 100
    
    def test_low_timeout(self):
        """Test with low timeout value."""
        scanner = AsyncScanner(timeout=0.1)
        assert scanner.timeout == 0.1
    
    def test_high_concurrency(self):
        """Test with high concurrency value."""
        scanner = AsyncScanner(max_concurrent=2000)
        assert scanner.max_concurrent == 2000


class TestAsyncScannerScanPort:
    """Tests for AsyncScanner.scan_port method."""
    
    @pytest.mark.asyncio
    async def test_scan_port_open(self):
        """Test scanning an open port (mocked)."""
        scanner = AsyncScanner(timeout=1.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            result_tuple = await scanner.scan_port("192.168.1.1", 80)
            
            # scan_port returns (ScanResult, banner_info) tuple
            result = result_tuple[0]
            assert isinstance(result, ScanResult)
            assert result.state == "open"
            assert result.port == 80
            assert result.host == "192.168.1.1"
    
    @pytest.mark.asyncio
    async def test_scan_port_closed(self):
        """Test scanning a closed port (mocked)."""
        scanner = AsyncScanner(timeout=1.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError()
            
            result_tuple = await scanner.scan_port("192.168.1.1", 81)
            
            result = result_tuple[0]
            assert isinstance(result, ScanResult)
            assert result.state == "closed"
    
    @pytest.mark.asyncio
    async def test_scan_port_filtered(self):
        """Test scanning a filtered port (timeout)."""
        scanner = AsyncScanner(timeout=0.1)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError()
            
            result_tuple = await scanner.scan_port("192.168.1.1", 82)
            
            result = result_tuple[0]
            assert isinstance(result, ScanResult)
            assert result.state in ["filtered", "closed"]
    
    @pytest.mark.asyncio
    async def test_scan_port_connection_error(self):
        """Test scanning a port with connection error."""
        scanner = AsyncScanner(timeout=1.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = OSError("Connection error")
            
            result_tuple = await scanner.scan_port("192.168.1.1", 83)
            
            result = result_tuple[0]
            assert isinstance(result, ScanResult)
            assert result.state in ["filtered", "closed"]


class TestAsyncScannerScanPorts:
    """Tests for AsyncScanner.scan_ports method."""
    
    @pytest.mark.asyncio
    async def test_scan_multiple_ports(self):
        """Test scanning multiple ports."""
        scanner = AsyncScanner(timeout=1.0)
        
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(
                host=host,
                port=port,
                state="open" if port == 80 else "closed",
                protocol="tcp"
            ), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            results = await scanner.scan_ports("192.168.1.1", [80, 443, 22])
            
            assert len(results) == 3
            assert all(isinstance(r, ScanResult) for r in results)
    
    @pytest.mark.asyncio
    async def test_scan_empty_ports(self):
        """Test scanning empty port list."""
        scanner = AsyncScanner(timeout=1.0)
        
        results = await scanner.scan_ports("192.168.1.1", [])
        assert results == []
    
    @pytest.mark.asyncio
    async def test_scan_single_port(self):
        """Test scanning single port via scan_ports."""
        scanner = AsyncScanner(timeout=1.0)
        
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(host=host, port=port, state="open", protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            results = await scanner.scan_ports("192.168.1.1", [80])
            
            assert len(results) == 1
            assert results[0].port == 80
    
    @pytest.mark.asyncio
    async def test_scan_with_callback(self):
        """Test scanning with callback function."""
        scanner = AsyncScanner(timeout=1.0)
        callback_results = []
        
        def callback(result):
            callback_results.append(result)
        
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(host=host, port=port, state="open", protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            await scanner.scan_ports("192.168.1.1", [80, 443], callback=callback)
            
            assert len(callback_results) == 2


class TestAsyncScannerRateLimiting:
    """Tests for rate limiting functionality."""
    
    @pytest.mark.asyncio
    async def test_with_rate_limit(self):
        """Test scanning with rate limiting."""
        scanner = AsyncScanner(rate_limit=100, timeout=1.0)
        
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(host=host, port=port, state="open", protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            results = await scanner.scan_ports("192.168.1.1", [80, 443])
            
            assert len(results) == 2
    
    @pytest.mark.asyncio
    async def test_without_rate_limit(self):
        """Test scanning without rate limiting."""
        scanner = AsyncScanner(rate_limit=None, timeout=1.0)
        
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(host=host, port=port, state="open", protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            results = await scanner.scan_ports("192.168.1.1", [80, 443])
            
            assert len(results) == 2


class TestAsyncScannerConcurrency:
    """Tests for concurrency handling."""
    
    @pytest.mark.asyncio
    async def test_respects_max_concurrent(self):
        """Test that scanner has max concurrent setting."""
        scanner = AsyncScanner(max_concurrent=5, timeout=1.0)
        
        # Verify max_concurrent is set
        assert scanner.max_concurrent == 5
        
        # Test scanning with mocked scan_port
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(host=host, port=port, state="open", protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            results = await scanner.scan_ports("192.168.1.1", list(range(1, 11)))
        
        assert len(results) == 10


class TestAsyncScannerEdgeCases:
    """Tests for edge cases."""
    
    @pytest.mark.asyncio
    async def test_scan_port_with_ipv4(self):
        """Test scanning with IPv4 address."""
        scanner = AsyncScanner(timeout=1.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            result_tuple = await scanner.scan_port("10.0.0.1", 80)
            result = result_tuple[0]
            assert result.host == "10.0.0.1"
    
    @pytest.mark.asyncio
    async def test_scan_well_known_ports(self):
        """Test scanning well-known ports."""
        scanner = AsyncScanner(timeout=1.0)
        ports = [21, 22, 80, 443]
        
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(host=host, port=port, state="open", protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            results = await scanner.scan_ports("192.168.1.1", ports)
            
            assert len(results) == len(ports)
            result_ports = [r.port for r in results]
            for port in ports:
                assert port in result_ports


class TestAsyncScannerProtocol:
    """Tests for protocol handling."""
    
    @pytest.mark.asyncio
    async def test_tcp_result_protocol(self):
        """Test that TCP scan results have correct protocol."""
        scanner = AsyncScanner(timeout=1.0)
        
        with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (mock_reader, mock_writer)
            
            result_tuple = await scanner.scan_port("192.168.1.1", 80)
            result = result_tuple[0]
            assert result.protocol == "tcp"


class TestAsyncScannerPerformance:
    """Tests for performance aspects."""
    
    @pytest.mark.asyncio
    async def test_scan_100_ports(self):
        """Test scanning 100 ports."""
        scanner = AsyncScanner(timeout=1.0, max_concurrent=50)
        
        async def mock_scan_port(host, port, grab_banner=False):
            return ScanResult(host=host, port=port, state="closed", protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=mock_scan_port):
            results = await scanner.scan_ports("192.168.1.1", list(range(1, 101)))
            
            assert len(results) == 100
    
    @pytest.mark.asyncio
    async def test_scan_preserves_port_info(self):
        """Test that scan preserves port information."""
        scanner = AsyncScanner(timeout=1.0)
        
        async def port_specific_scan(host, port, grab_banner=False):
            state = "open" if port % 2 == 0 else "closed"
            return ScanResult(host=host, port=port, state=state, protocol="tcp"), None
        
        with patch.object(scanner, 'scan_port', side_effect=port_specific_scan):
            results = await scanner.scan_ports("192.168.1.1", [80, 443, 22])
            
            for result in results:
                assert result.host == "192.168.1.1"
                assert result.port in [80, 443, 22]


class TestAsyncScannerStats:
    """Tests for scanner statistics."""
    
    def test_stats_initialization(self):
        """Test that stats are initialized."""
        scanner = AsyncScanner()
        assert hasattr(scanner, 'stats')
        assert "ports_scanned" in scanner.stats
        assert "open_ports" in scanner.stats
        assert "closed_ports" in scanner.stats
    
    def test_get_stats(self):
        """Test getting scanner statistics."""
        scanner = AsyncScanner()
        stats = scanner.get_stats()
        assert isinstance(stats, dict)
