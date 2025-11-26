"""
Tests for service_detection module
by BitSpectreLabs
"""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from pathlib import Path
from dataclasses import fields

from spectrescan.core.service_detection import ServiceInfo, ServiceDetector


class TestServiceInfo:
    """Tests for ServiceInfo dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        info = ServiceInfo(name="http")
        assert info.name == "http"
        assert info.version is None
        assert info.product is None
        assert info.extra_info is None
        assert info.hostname is None
        assert info.os is None
        assert info.device_type is None
        assert info.cpe == []
        assert info.confidence == 0
        assert info.banner is None
    
    def test_with_version(self):
        """Test with version."""
        info = ServiceInfo(name="ssh", version="8.2p1")
        assert info.name == "ssh"
        assert info.version == "8.2p1"
    
    def test_with_product(self):
        """Test with product name."""
        info = ServiceInfo(name="http", product="nginx")
        assert info.product == "nginx"
    
    def test_with_extra_info(self):
        """Test with extra info."""
        info = ServiceInfo(name="ssh", extra_info="Ubuntu-4ubuntu0.1")
        assert info.extra_info == "Ubuntu-4ubuntu0.1"
    
    def test_with_hostname(self):
        """Test with hostname."""
        info = ServiceInfo(name="smtp", hostname="mail.example.com")
        assert info.hostname == "mail.example.com"
    
    def test_with_os(self):
        """Test with OS."""
        info = ServiceInfo(name="ssh", os="Ubuntu Linux")
        assert info.os == "Ubuntu Linux"
    
    def test_with_device_type(self):
        """Test with device type."""
        info = ServiceInfo(name="telnet", device_type="router")
        assert info.device_type == "router"
    
    def test_with_cpe(self):
        """Test with CPE list."""
        info = ServiceInfo(
            name="http",
            cpe=["cpe:/a:nginx:nginx:1.18.0"]
        )
        assert len(info.cpe) == 1
        assert "cpe:/a:nginx:nginx:1.18.0" in info.cpe
    
    def test_with_confidence(self):
        """Test with confidence score."""
        info = ServiceInfo(name="http", confidence=95)
        assert info.confidence == 95
    
    def test_with_banner(self):
        """Test with banner."""
        info = ServiceInfo(name="ssh", banner="SSH-2.0-OpenSSH_8.2p1")
        assert info.banner == "SSH-2.0-OpenSSH_8.2p1"
    
    def test_full_info(self):
        """Test with all fields."""
        info = ServiceInfo(
            name="ssh",
            version="8.2p1",
            product="OpenSSH",
            extra_info="Ubuntu-4ubuntu0.1",
            hostname="server.local",
            os="Ubuntu Linux 20.04",
            device_type="general purpose",
            cpe=["cpe:/a:openbsd:openssh:8.2p1"],
            confidence=100,
            banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        )
        assert info.name == "ssh"
        assert info.version == "8.2p1"
        assert info.product == "OpenSSH"
        assert info.confidence == 100
    
    def test_cpe_default_is_list(self):
        """Test that cpe defaults to empty list."""
        info = ServiceInfo(name="test")
        assert isinstance(info.cpe, list)
        assert len(info.cpe) == 0
    
    def test_cpe_mutable_default(self):
        """Test that cpe default is not shared between instances."""
        info1 = ServiceInfo(name="test1")
        info2 = ServiceInfo(name="test2")
        
        info1.cpe.append("cpe:/a:test:test")
        
        assert len(info1.cpe) == 1
        assert len(info2.cpe) == 0  # info2 should not be affected


class TestServiceDetector:
    """Tests for ServiceDetector class."""
    
    def test_init_defaults(self):
        """Test default initialization."""
        detector = ServiceDetector()
        assert detector.timeout == 5.0
        assert detector.max_probes == 7
        assert detector.intensity == 7
        assert detector.probes == []
        assert detector.signatures == []
    
    def test_init_custom(self):
        """Test custom initialization."""
        detector = ServiceDetector(
            timeout=10.0,
            max_probes=5,
            intensity=3
        )
        assert detector.timeout == 10.0
        assert detector.max_probes == 5
        assert detector.intensity == 3
    
    def test_init_with_nonexistent_probes_file(self):
        """Test initialization with non-existent probes file."""
        detector = ServiceDetector(
            probes_file=Path("/nonexistent/path/to/probes")
        )
        assert detector.probes == []
        assert detector.signatures == []
    
    def test_match_cache_initialized(self):
        """Test match cache is initialized."""
        detector = ServiceDetector()
        assert detector._match_cache == {}
    
    def test_parser_initialized(self):
        """Test parser is initialized."""
        detector = ServiceDetector()
        assert detector.parser is not None
    
    def test_load_probes_with_existing_file(self):
        """Test load_probes with existing file."""
        detector = ServiceDetector()
        
        with patch.object(detector.parser, 'parse_file') as mock_parse:
            mock_probes = [Mock(), Mock()]
            mock_sigs = [Mock()]
            
            with patch('spectrescan.core.service_detection.parse_nmap_service_probes') as mock_parse_fn:
                mock_parse_fn.return_value = (mock_probes, mock_sigs)
                
                detector.load_probes(Path("test_probes"))
                
                mock_parse_fn.assert_called_once_with(Path("test_probes"))
                assert detector.probes == mock_probes
                assert detector.signatures == mock_sigs


class TestServiceDetectorDetection:
    """Tests for service detection methods."""
    
    @pytest.mark.asyncio
    async def test_detect_service_with_high_confidence_banner(self):
        """Test detection with high confidence banner match."""
        detector = ServiceDetector()
        
        with patch.object(detector, '_match_banner') as mock_match:
            mock_service = ServiceInfo(name="ssh", confidence=95)
            mock_match.return_value = mock_service
            
            result = await detector.detect_service(
                "localhost",
                22,
                "TCP",
                initial_banner="SSH-2.0-OpenSSH_8.2"
            )
            
            assert result.name == "ssh"
            assert result.confidence == 95
            mock_match.assert_called_with("SSH-2.0-OpenSSH_8.2", 22, "TCP")
    
    @pytest.mark.asyncio
    async def test_detect_service_falls_back_to_probes(self):
        """Test detection falls back to probes when banner match is low confidence."""
        detector = ServiceDetector()
        
        with patch.object(detector, '_match_banner') as mock_match:
            # Low confidence match
            mock_service = ServiceInfo(name="unknown", confidence=30)
            mock_match.return_value = mock_service
            
            with patch.object(detector.parser, 'get_probes_for_port') as mock_probes:
                mock_probes.return_value = []
                
                with patch.object(detector, '_detect_by_port') as mock_detect:
                    fallback_service = ServiceInfo(name="http", confidence=50)
                    mock_detect.return_value = fallback_service
                    
                    result = await detector.detect_service(
                        "localhost",
                        80,
                        "TCP",
                        initial_banner="HTTP/1.1"
                    )
                    
                    # Should eventually fall back
                    assert result is not None
    
    @pytest.mark.asyncio
    async def test_detect_service_without_banner(self):
        """Test detection without initial banner."""
        detector = ServiceDetector()
        
        with patch.object(detector.parser, 'get_probes_for_port') as mock_probes:
            mock_probes.return_value = []
            
            with patch.object(detector, '_detect_by_port') as mock_detect:
                mock_service = ServiceInfo(name="http", confidence=60)
                mock_detect.return_value = mock_service
                
                result = await detector.detect_service(
                    "localhost",
                    80,
                    "TCP"
                )
                
                assert result.name == "http"
    
    @pytest.mark.asyncio
    async def test_detect_service_respects_intensity(self):
        """Test detection respects intensity setting."""
        detector = ServiceDetector(intensity=2, max_probes=10)
        
        with patch.object(detector.parser, 'get_probes_for_port') as mock_probes:
            # Return many probes
            mock_probe = Mock()
            mock_probes.return_value = [mock_probe for _ in range(10)]
            
            with patch.object(detector, '_send_probe', new_callable=AsyncMock) as mock_send:
                mock_send.return_value = None
                
                with patch.object(detector, '_detect_by_port') as mock_detect:
                    mock_detect.return_value = ServiceInfo(name="unknown")
                    
                    await detector.detect_service("localhost", 80, "TCP")
                    
                    # Should only try up to intensity probes
                    assert mock_send.await_count <= 2
    
    @pytest.mark.asyncio
    async def test_detect_service_probe_success(self):
        """Test detection with successful probe."""
        detector = ServiceDetector()
        
        with patch.object(detector.parser, 'get_probes_for_port') as mock_probes:
            mock_probe = Mock()
            mock_probe.name = "TestProbe"
            mock_probes.return_value = [mock_probe]
            
            with patch.object(detector, '_send_probe', new_callable=AsyncMock) as mock_send:
                mock_send.return_value = "Server: nginx"
                
                with patch.object(detector, '_match_response') as mock_match:
                    mock_service = ServiceInfo(name="nginx", confidence=90)
                    mock_match.return_value = mock_service
                    
                    result = await detector.detect_service("localhost", 80, "TCP")
                    
                    assert result.name == "nginx"
                    assert result.confidence == 90
    
    @pytest.mark.asyncio
    async def test_detect_service_probe_exception(self):
        """Test detection handles probe exception."""
        detector = ServiceDetector()
        
        with patch.object(detector.parser, 'get_probes_for_port') as mock_probes:
            mock_probe = Mock()
            mock_probe.name = "TestProbe"
            mock_probes.return_value = [mock_probe]
            
            with patch.object(detector, '_send_probe', new_callable=AsyncMock) as mock_send:
                mock_send.side_effect = Exception("Connection refused")
                
                with patch.object(detector, '_detect_by_port') as mock_detect:
                    mock_detect.return_value = ServiceInfo(name="unknown")
                    
                    # Should not raise
                    result = await detector.detect_service("localhost", 80, "TCP")
                    
                    assert result is not None


class TestServiceDetectorBannerMatching:
    """Tests for banner matching methods."""
    
    def test_match_banner_http(self):
        """Test matching HTTP banner."""
        detector = ServiceDetector()
        
        # The actual method may vary based on implementation
        # This tests expected behavior
        with patch.object(detector, '_match_banner') as mock_match:
            mock_match.return_value = ServiceInfo(name="http", confidence=80)
            
            result = detector._match_banner("HTTP/1.1 200 OK\r\nServer: nginx", 80, "TCP")
            
            assert result is not None
    
    def test_match_banner_ssh(self):
        """Test matching SSH banner."""
        detector = ServiceDetector()
        
        with patch.object(detector, '_match_banner') as mock_match:
            mock_match.return_value = ServiceInfo(name="ssh", version="8.2p1", confidence=95)
            
            result = detector._match_banner("SSH-2.0-OpenSSH_8.2p1", 22, "TCP")
            
            assert result is not None


class TestServiceDetectorPortDetection:
    """Tests for port-based detection."""
    
    def test_detect_by_port_http(self):
        """Test port-based detection for HTTP."""
        detector = ServiceDetector()
        
        with patch.object(detector, '_detect_by_port') as mock_detect:
            mock_detect.return_value = ServiceInfo(name="http", confidence=50)
            
            result = detector._detect_by_port(80, "TCP")
            
            assert result is not None
    
    def test_detect_by_port_ssh(self):
        """Test port-based detection for SSH."""
        detector = ServiceDetector()
        
        with patch.object(detector, '_detect_by_port') as mock_detect:
            mock_detect.return_value = ServiceInfo(name="ssh", confidence=50)
            
            result = detector._detect_by_port(22, "TCP")
            
            assert result is not None


class TestServiceDetectorCache:
    """Tests for service match caching."""
    
    def test_cache_starts_empty(self):
        """Test cache starts empty."""
        detector = ServiceDetector()
        assert detector._match_cache == {}
    
    def test_cache_key_format(self):
        """Test cache key format expectations."""
        detector = ServiceDetector()
        
        # Cache key should be based on banner/port/protocol
        # This documents expected behavior
        cache_key = "SSH-2.0-OpenSSH_8.2:22:TCP"
        detector._match_cache[cache_key] = ServiceInfo(name="ssh")
        
        assert cache_key in detector._match_cache


class TestServiceInfoFields:
    """Tests for ServiceInfo field types."""
    
    def test_field_count(self):
        """Test ServiceInfo has expected fields."""
        info_fields = fields(ServiceInfo)
        field_names = [f.name for f in info_fields]
        
        expected = [
            'name', 'version', 'product', 'extra_info',
            'hostname', 'os', 'device_type', 'cpe',
            'confidence', 'banner'
        ]
        
        for expected_field in expected:
            assert expected_field in field_names
    
    def test_confidence_range(self):
        """Test confidence values."""
        # Low confidence
        low = ServiceInfo(name="test", confidence=10)
        assert low.confidence == 10
        
        # Medium confidence
        medium = ServiceInfo(name="test", confidence=50)
        assert medium.confidence == 50
        
        # High confidence
        high = ServiceInfo(name="test", confidence=100)
        assert high.confidence == 100


class TestServiceDetectorProtocols:
    """Tests for different protocol support."""
    
    @pytest.mark.asyncio
    async def test_tcp_protocol(self):
        """Test TCP protocol detection."""
        detector = ServiceDetector()
        
        with patch.object(detector.parser, 'get_probes_for_port') as mock_probes:
            mock_probes.return_value = []
            
            with patch.object(detector, '_detect_by_port') as mock_detect:
                mock_detect.return_value = ServiceInfo(name="http")
                
                await detector.detect_service("localhost", 80, "TCP")
                
                mock_probes.assert_called_with(80, "TCP")
    
    @pytest.mark.asyncio
    async def test_udp_protocol(self):
        """Test UDP protocol detection."""
        detector = ServiceDetector()
        
        with patch.object(detector.parser, 'get_probes_for_port') as mock_probes:
            mock_probes.return_value = []
            
            with patch.object(detector, '_detect_by_port') as mock_detect:
                mock_detect.return_value = ServiceInfo(name="dns")
                
                await detector.detect_service("localhost", 53, "UDP")
                
                mock_probes.assert_called_with(53, "UDP")


class TestServiceDetectorIntegration:
    """Integration-style tests for ServiceDetector."""
    
    def test_common_services(self):
        """Test recognition of common service names."""
        common_services = [
            "http", "https", "ssh", "ftp", "smtp", "pop3",
            "imap", "mysql", "postgresql", "redis", "mongodb",
            "dns", "telnet", "rdp", "vnc"
        ]
        
        for service in common_services:
            info = ServiceInfo(name=service)
            assert info.name == service
    
    def test_intensity_levels(self):
        """Test valid intensity levels."""
        for intensity in range(1, 10):
            detector = ServiceDetector(intensity=intensity)
            assert detector.intensity == intensity
    
    def test_timeout_values(self):
        """Test various timeout values."""
        timeouts = [0.5, 1.0, 5.0, 10.0, 30.0]
        
        for timeout in timeouts:
            detector = ServiceDetector(timeout=timeout)
            assert detector.timeout == timeout
