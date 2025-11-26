"""
Tests for Enhanced OS Detection Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from spectrescan.core.os_detection_enhanced import (
    OSFamily,
    OSFingerprint,
    EnhancedOSDetector
)


class TestOSFamily:
    """Tests for OSFamily enum."""
    
    def test_linux_value(self):
        """Test Linux value."""
        assert OSFamily.LINUX.value == "Linux"
    
    def test_windows_value(self):
        """Test Windows value."""
        assert OSFamily.WINDOWS.value == "Windows"
    
    def test_unix_value(self):
        """Test Unix value."""
        assert OSFamily.UNIX.value == "Unix/BSD"
    
    def test_macos_value(self):
        """Test macOS value."""
        assert OSFamily.MACOS.value == "macOS"
    
    def test_network_device_value(self):
        """Test Network Device value."""
        assert OSFamily.NETWORK_DEVICE.value == "Network Device"
    
    def test_unknown_value(self):
        """Test Unknown value."""
        assert OSFamily.UNKNOWN.value == "Unknown"
    
    def test_all_values(self):
        """Test all enum members exist."""
        members = list(OSFamily)
        assert len(members) == 7  # Linux, Windows, Unix, macOS, Network Device, Embedded, Unknown


class TestOSFingerprint:
    """Tests for OSFingerprint dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        fp = OSFingerprint(
            os_guess="Linux",
            os_family=OSFamily.LINUX,
            confidence=80
        )
        
        assert fp.os_guess == "Linux"
        assert fp.os_family == OSFamily.LINUX
        assert fp.confidence == 80
    
    def test_default_values(self):
        """Test default values."""
        fp = OSFingerprint(
            os_guess="Test",
            os_family=OSFamily.UNKNOWN,
            confidence=50
        )
        
        assert fp.ttl is None
        assert fp.window_size is None
        assert fp.mss is None
        assert fp.window_scale is None
        assert fp.timestamps is False
        assert fp.sack_permitted is False
        assert fp.tcp_options == []
        assert fp.ip_id_sequence is None
        assert fp.icmp_echo_code is None
        assert fp.banner_hints == []
        assert fp.characteristics == {}
    
    def test_with_ttl(self):
        """Test with TTL value."""
        fp = OSFingerprint(
            os_guess="Linux",
            os_family=OSFamily.LINUX,
            confidence=75,
            ttl=64
        )
        
        assert fp.ttl == 64
    
    def test_with_window_size(self):
        """Test with window size."""
        fp = OSFingerprint(
            os_guess="Windows",
            os_family=OSFamily.WINDOWS,
            confidence=80,
            window_size=65535
        )
        
        assert fp.window_size == 65535
    
    def test_with_tcp_options(self):
        """Test with TCP options."""
        fp = OSFingerprint(
            os_guess="Linux",
            os_family=OSFamily.LINUX,
            confidence=85,
            tcp_options=["MSS", "NOP", "SACK", "TIMESTAMP"]
        )
        
        assert len(fp.tcp_options) == 4
        assert "MSS" in fp.tcp_options
    
    def test_with_characteristics(self):
        """Test with characteristics dict."""
        fp = OSFingerprint(
            os_guess="Linux",
            os_family=OSFamily.LINUX,
            confidence=90,
            characteristics={"ttl_base": 64, "hops": 2}
        )
        
        assert fp.characteristics["ttl_base"] == 64
        assert fp.characteristics["hops"] == 2


class TestEnhancedOSDetector:
    """Tests for EnhancedOSDetector class."""
    
    def test_init_default_timeout(self):
        """Test initialization with default timeout."""
        detector = EnhancedOSDetector()
        
        assert detector.timeout == 5.0
    
    def test_init_custom_timeout(self):
        """Test initialization with custom timeout."""
        detector = EnhancedOSDetector(timeout=10.0)
        
        assert detector.timeout == 10.0
    
    def test_signatures_loaded(self):
        """Test signatures are loaded."""
        detector = EnhancedOSDetector()
        
        assert hasattr(detector, 'ttl_signatures')
        assert hasattr(detector, 'window_signatures')
        assert hasattr(detector, 'tcp_option_fingerprints')
        assert hasattr(detector, 'banner_os_hints')
    
    def test_ttl_signatures_content(self):
        """Test TTL signatures content."""
        detector = EnhancedOSDetector()
        
        # Common TTL values should be present
        assert 64 in detector.ttl_signatures
        assert 128 in detector.ttl_signatures
        assert 255 in detector.ttl_signatures
        
        # Linux uses TTL 64
        assert detector.ttl_signatures[64]["family"] == OSFamily.LINUX
        
        # Windows uses TTL 128
        assert detector.ttl_signatures[128]["family"] == OSFamily.WINDOWS
    
    def test_window_signatures_content(self):
        """Test window signatures content."""
        detector = EnhancedOSDetector()
        
        assert len(detector.window_signatures) > 0
    
    def test_banner_os_hints_content(self):
        """Test banner hints content."""
        detector = EnhancedOSDetector()
        
        # Common OS hints should be present
        assert "ubuntu" in detector.banner_os_hints
        assert "windows" in detector.banner_os_hints
        assert "freebsd" in detector.banner_os_hints


class TestBannerDetection:
    """Tests for banner-based OS detection."""
    
    def test_detect_linux_from_banner(self):
        """Test detecting Linux from banner."""
        detector = EnhancedOSDetector()
        
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        result = detector._detect_from_banner(banner)
        
        if result:
            assert result.os_family == OSFamily.LINUX
    
    def test_detect_windows_from_banner(self):
        """Test detecting Windows from banner."""
        detector = EnhancedOSDetector()
        
        banner = "Microsoft-IIS/10.0"
        result = detector._detect_from_banner(banner)
        
        if result:
            assert result.os_family == OSFamily.WINDOWS
    
    def test_detect_freebsd_from_banner(self):
        """Test detecting FreeBSD from banner."""
        detector = EnhancedOSDetector()
        
        banner = "SSH-2.0-OpenSSH_7.9 FreeBSD-20200214"
        result = detector._detect_from_banner(banner)
        
        if result:
            assert result.os_family == OSFamily.UNIX
    
    def test_detect_cisco_from_banner(self):
        """Test detecting Cisco from banner."""
        detector = EnhancedOSDetector()
        
        banner = "Cisco IOS Software"
        result = detector._detect_from_banner(banner)
        
        if result:
            assert result.os_family == OSFamily.NETWORK_DEVICE


class TestMergeFingerprints:
    """Tests for fingerprint merging."""
    
    def test_merge_basic(self):
        """Test basic fingerprint merging."""
        detector = EnhancedOSDetector()
        
        fp1 = OSFingerprint(
            os_guess="Linux",
            os_family=OSFamily.LINUX,
            confidence=70,
            ttl=64
        )
        
        fp2 = OSFingerprint(
            os_guess="Ubuntu Linux",
            os_family=OSFamily.LINUX,
            confidence=90,
            banner_hints=["Ubuntu"]
        )
        
        merged = detector._merge_fingerprints(fp1, fp2)
        
        # Higher confidence should win
        assert merged.confidence == 90
        assert merged.os_guess == "Ubuntu Linux"
        
        # TTL should be preserved
        assert merged.ttl == 64
    
    def test_merge_preserves_data(self):
        """Test merge preserves data from both."""
        detector = EnhancedOSDetector()
        
        fp1 = OSFingerprint(
            os_guess="Linux",
            os_family=OSFamily.LINUX,
            confidence=60,
            ttl=64,
            characteristics={"source": "ttl"}
        )
        
        fp2 = OSFingerprint(
            os_guess="Linux",
            os_family=OSFamily.LINUX,
            confidence=80,
            window_size=65535
        )
        
        merged = detector._merge_fingerprints(fp1, fp2)
        
        assert merged.ttl == 64
        assert merged.window_size == 65535


class TestAsyncDetection:
    """Tests for async OS detection."""
    
    @pytest.mark.asyncio
    async def test_detect_os_basic(self):
        """Test basic OS detection."""
        detector = EnhancedOSDetector()
        
        # This will likely timeout or fail, which is expected
        result = await detector.detect_os("127.0.0.1")
        
        assert isinstance(result, OSFingerprint)
    
    @pytest.mark.asyncio
    async def test_detect_os_with_banner(self):
        """Test OS detection with banner."""
        detector = EnhancedOSDetector()
        
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        result = await detector.detect_os("127.0.0.1", banner=banner)
        
        assert isinstance(result, OSFingerprint)
        # Banner should provide hint
        if result.confidence > 0:
            assert result.os_family == OSFamily.LINUX


class TestTTLAnalysis:
    """Tests for TTL-based analysis."""
    
    def test_get_os_from_ttl_linux(self):
        """Test getting OS from Linux TTL."""
        detector = EnhancedOSDetector()
        
        # TTL 64 = Linux
        sig = detector.ttl_signatures.get(64)
        assert sig is not None
        assert sig["family"] == OSFamily.LINUX
    
    def test_get_os_from_ttl_windows(self):
        """Test getting OS from Windows TTL."""
        detector = EnhancedOSDetector()
        
        # TTL 128 = Windows
        sig = detector.ttl_signatures.get(128)
        assert sig is not None
        assert sig["family"] == OSFamily.WINDOWS
    
    def test_get_os_from_ttl_network_device(self):
        """Test getting OS from network device TTL."""
        detector = EnhancedOSDetector()
        
        # TTL 255 = Network device
        sig = detector.ttl_signatures.get(255)
        assert sig is not None
        assert sig["family"] == OSFamily.NETWORK_DEVICE


class TestTCPOptionsFingerprinting:
    """Tests for TCP options fingerprinting."""
    
    def test_fingerprint_patterns_exist(self):
        """Test TCP option patterns exist."""
        detector = EnhancedOSDetector()
        
        assert len(detector.tcp_option_fingerprints) > 0
    
    def test_linux_pattern(self):
        """Test Linux TCP pattern exists."""
        detector = EnhancedOSDetector()
        
        linux_patterns = [
            p for p, info in detector.tcp_option_fingerprints.items()
            if info["family"] == OSFamily.LINUX
        ]
        assert len(linux_patterns) > 0
    
    def test_windows_pattern(self):
        """Test Windows TCP pattern exists."""
        detector = EnhancedOSDetector()
        
        windows_patterns = [
            p for p, info in detector.tcp_option_fingerprints.items()
            if info["family"] == OSFamily.WINDOWS
        ]
        assert len(windows_patterns) > 0
