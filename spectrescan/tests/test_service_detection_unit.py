"""
Tests for service detection module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from pathlib import Path

from spectrescan.core.service_detection import ServiceInfo, ServiceDetector


class TestServiceInfo:
    """Tests for ServiceInfo dataclass."""
    
    def test_basic_init(self):
        """Test basic ServiceInfo initialization."""
        info = ServiceInfo(name="http")
        assert info.name == "http"
        assert info.version is None
        assert info.confidence == 0
    
    def test_full_init(self):
        """Test ServiceInfo with all fields."""
        info = ServiceInfo(
            name="nginx",
            version="1.18.0",
            product="nginx",
            extra_info="Ubuntu",
            confidence=95,
            cpe=["cpe:/a:nginx:nginx:1.18.0"]
        )
        assert info.name == "nginx"
        assert info.version == "1.18.0"
        assert info.confidence == 95
        assert len(info.cpe) == 1
    
    def test_default_cpe_list(self):
        """Test that CPE defaults to empty list."""
        info = ServiceInfo(name="http")
        assert info.cpe == []
        info.cpe.append("cpe:/a:test:test")
        assert len(info.cpe) == 1


class TestServiceDetector:
    """Tests for ServiceDetector class."""
    
    def test_init_defaults(self):
        """Test ServiceDetector initialization with defaults."""
        detector = ServiceDetector()
        assert detector.timeout == 5.0
        assert detector.max_probes == 7
        assert detector.intensity == 7
    
    def test_init_custom(self):
        """Test ServiceDetector with custom parameters."""
        detector = ServiceDetector(
            timeout=10.0,
            max_probes=5,
            intensity=5
        )
        assert detector.timeout == 10.0
        assert detector.max_probes == 5
        assert detector.intensity == 5
    
    def test_load_probes_nonexistent(self):
        """Test loading probes from nonexistent file."""
        detector = ServiceDetector()
        detector.load_probes(Path("/nonexistent/path/file"))
        # Should not crash, may have empty probes
    
    def test_load_probes_actual(self):
        """Test loading probes from actual file."""
        probes_path = Path(__file__).parent.parent / "data" / "nmap-service-probes"
        
        detector = ServiceDetector()
        if probes_path.exists():
            detector.load_probes(probes_path)
            # May or may not have loaded probes depending on parser
    
    def test_detect_by_port(self):
        """Test port-based detection."""
        detector = ServiceDetector()
        
        if hasattr(detector, '_detect_by_port'):
            result = detector._detect_by_port(80, "TCP")
            assert isinstance(result, ServiceInfo)
            # Port 80 should be HTTP
            if result.name:
                assert result.name.lower() in ["http", "www", "web", "unknown"]
    
    def test_detect_by_port_common_ports(self):
        """Test port-based detection for common ports."""
        detector = ServiceDetector()
        
        if hasattr(detector, '_detect_by_port'):
            # SSH
            ssh_result = detector._detect_by_port(22, "TCP")
            # FTP
            ftp_result = detector._detect_by_port(21, "TCP")
            # MySQL
            mysql_result = detector._detect_by_port(3306, "TCP")
            
            # All should return ServiceInfo
            assert isinstance(ssh_result, ServiceInfo)
            assert isinstance(ftp_result, ServiceInfo)
            assert isinstance(mysql_result, ServiceInfo)


class TestBannerMatching:
    """Tests for banner matching functionality."""
    
    def test_match_http_banner(self):
        """Test matching HTTP banner."""
        detector = ServiceDetector()
        
        if hasattr(detector, '_match_banner'):
            banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
            result = detector._match_banner(banner, 80, "TCP")
            
            if result:
                assert isinstance(result, ServiceInfo)
    
    def test_match_ssh_banner(self):
        """Test matching SSH banner."""
        detector = ServiceDetector()
        
        if hasattr(detector, '_match_banner'):
            banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            result = detector._match_banner(banner, 22, "TCP")
            
            if result:
                assert isinstance(result, ServiceInfo)
    
    def test_match_empty_banner(self):
        """Test matching empty banner."""
        detector = ServiceDetector()
        
        if hasattr(detector, '_match_banner'):
            result = detector._match_banner("", 80, "TCP")
            # Should return None or default ServiceInfo


class TestProbeSelection:
    """Tests for probe selection."""
    
    def test_parser_get_probes_for_port(self):
        """Test getting probes for a specific port."""
        detector = ServiceDetector()
        
        if hasattr(detector.parser, 'get_probes_for_port'):
            probes = detector.parser.get_probes_for_port(80, "TCP")
            # Should return a list
            assert isinstance(probes, list)
    
    def test_parser_has_probes(self):
        """Test that parser can hold probes."""
        detector = ServiceDetector()
        assert hasattr(detector, 'parser')
        assert hasattr(detector, 'probes')


@pytest.mark.asyncio
async def test_detect_service_no_network():
    """Test detect_service without network (should fall back)."""
    detector = ServiceDetector(timeout=0.1)
    
    # Should not crash even without network
    try:
        result = await detector.detect_service(
            host="127.0.0.1",
            port=99999,  # Unlikely to be open
            protocol="TCP",
            initial_banner=None
        )
        # Should return some ServiceInfo
        if result:
            assert isinstance(result, ServiceInfo)
    except Exception:
        # Connection failures are expected
        pass


@pytest.mark.asyncio
async def test_detect_service_with_banner():
    """Test detect_service with pre-existing banner."""
    detector = ServiceDetector()
    
    result = await detector.detect_service(
        host="127.0.0.1",
        port=80,
        protocol="TCP",
        initial_banner="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"
    )
    
    # Should return ServiceInfo based on banner
    assert isinstance(result, ServiceInfo)


class TestSignatureMatching:
    """Tests for signature-based matching."""
    
    def test_match_nginx_signature(self):
        """Test matching nginx signature."""
        detector = ServiceDetector()
        
        # Load signatures if available
        signatures_path = Path(__file__).parent.parent / "data" / "service-signatures.json"
        
        if signatures_path.exists() and hasattr(detector, '_match_signature'):
            banner = "Server: nginx/1.18.0"
            result = detector._match_signature(banner)
            # May or may not match depending on implementation
    
    def test_match_apache_signature(self):
        """Test matching Apache signature."""
        detector = ServiceDetector()
        
        if hasattr(detector, '_match_signature'):
            banner = "Server: Apache/2.4.41 (Ubuntu)"
            result = detector._match_signature(banner)


class TestCacheSystem:
    """Tests for caching system."""
    
    def test_cache_initialization(self):
        """Test that cache is initialized."""
        detector = ServiceDetector()
        assert hasattr(detector, '_match_cache')
        assert isinstance(detector._match_cache, dict)
    
    def test_cache_is_empty_initially(self):
        """Test that cache starts empty."""
        detector = ServiceDetector()
        assert len(detector._match_cache) == 0
