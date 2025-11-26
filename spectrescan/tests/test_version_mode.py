"""
Tests for version detection mode.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from spectrescan.core.version_mode import (
    VersionScanner,
    VersionScanResult,
    format_version_result,
)


class TestVersionScanner:
    """Tests for VersionScanner class."""
    
    def test_default_init(self):
        """Test default initialization."""
        scanner = VersionScanner()
        assert scanner.intensity == 7
        assert scanner.timeout > 0
    
    def test_custom_intensity(self):
        """Test custom intensity levels."""
        for intensity in [0, 1, 5, 7, 9]:
            scanner = VersionScanner(intensity=intensity)
            assert scanner.intensity == intensity
    
    def test_intensity_clamping(self):
        """Test intensity clamping to valid range."""
        # Very high intensity should be clamped to 9
        scanner = VersionScanner(intensity=100)
        assert scanner.intensity == 9
        
        # Negative intensity should be clamped to 0
        scanner = VersionScanner(intensity=-5)
        assert scanner.intensity == 0
    
    def test_intensity_0_disables_detection(self):
        """Test intensity 0 disables version detection."""
        scanner = VersionScanner(intensity=0)
        assert scanner.enable_banner_grabbing is False
        assert scanner.max_probes == 0
    
    def test_intensity_1_light_mode(self):
        """Test intensity 1 is light mode."""
        scanner = VersionScanner(intensity=1)
        assert scanner.max_probes == 1
    
    def test_intensity_7_all_probes(self):
        """Test intensity 7 uses all standard probes."""
        scanner = VersionScanner(intensity=7)
        assert scanner.max_probes == 7
    
    def test_intensity_9_insane_mode(self):
        """Test intensity 9 is insane mode."""
        scanner = VersionScanner(intensity=9)
        assert scanner.max_probes == 15
        assert scanner.timeout == pytest.approx(30.0, rel=0.1)
    
    def test_get_intensity_description(self):
        """Test getting intensity description."""
        scanner = VersionScanner(intensity=7)
        desc = scanner.get_intensity_description()
        assert isinstance(desc, str)
        assert "All" in desc
    
    def test_get_settings_summary(self):
        """Test getting settings summary."""
        scanner = VersionScanner(intensity=5)
        summary = scanner.get_settings_summary()
        assert isinstance(summary, dict)
        assert "intensity" in summary
        assert "timeout" in summary
        assert "max_probes" in summary
        assert summary["intensity"] == 5


class TestVersionScanResult:
    """Tests for VersionScanResult dataclass."""
    
    def test_full_creation(self):
        """Test creating full VersionScanResult."""
        result = VersionScanResult(
            host="192.168.1.1",
            port=80,
            protocol="TCP",
            state="open",
            service="http",
            version="1.18.0",
            product="nginx",
            extra_info="Ubuntu",
            hostname="server.local",
            os="Linux",
            device_type="general purpose",
            cpe=["cpe:/a:nginx:nginx:1.18.0"],
            confidence=95,
            method="probe",
            detection_time=0.5
        )
        
        assert result.host == "192.168.1.1"
        assert result.port == 80
        assert result.protocol == "TCP"
        assert result.state == "open"
        assert result.service == "http"
        assert result.version == "1.18.0"
        assert result.product == "nginx"
        assert result.confidence == 95
        assert result.method == "probe"
    
    def test_minimal_creation(self):
        """Test creating minimal VersionScanResult."""
        result = VersionScanResult(
            host="192.168.1.1",
            port=80,
            protocol="TCP",
            state="open",
            service=None,
            version=None,
            product=None,
            extra_info=None,
            hostname=None,
            os=None,
            device_type=None,
            cpe=[],
            confidence=0,
            method="unknown",
            detection_time=0.1
        )
        
        assert result.host == "192.168.1.1"
        assert result.service is None
        assert result.confidence == 0


class TestFormatVersionResult:
    """Tests for format_version_result function."""
    
    def test_format_basic(self):
        """Test basic formatting."""
        result = VersionScanResult(
            host="192.168.1.1",
            port=80,
            protocol="TCP",
            state="open",
            service="http",
            version="1.18.0",
            product="nginx",
            extra_info=None,
            hostname=None,
            os=None,
            device_type=None,
            cpe=[],
            confidence=95,
            method="probe",
            detection_time=0.5
        )
        
        formatted = format_version_result(result)
        assert "80" in formatted
        assert "TCP" in formatted
    
    def test_format_verbose(self):
        """Test verbose formatting."""
        result = VersionScanResult(
            host="192.168.1.1",
            port=22,
            protocol="TCP",
            state="open",
            service="ssh",
            version="8.2p1",
            product="OpenSSH",
            extra_info="protocol 2.0",
            hostname="server.local",
            os="Linux",
            device_type=None,
            cpe=["cpe:/a:openbsd:openssh:8.2p1"],
            confidence=95,
            method="probe",
            detection_time=0.3
        )
        
        formatted = format_version_result(result, verbose=True)
        assert "22" in formatted
        assert "confidence" in formatted.lower() or "95" in formatted


class TestVersionScannerIntensitySettings:
    """Test intensity-based settings adjustment."""
    
    def test_intensity_2_settings(self):
        """Test intensity 2 settings."""
        scanner = VersionScanner(intensity=2)
        assert scanner.max_probes == 2
    
    def test_intensity_4_settings(self):
        """Test intensity 4 settings."""
        scanner = VersionScanner(intensity=4)
        assert scanner.max_probes == 5
    
    def test_intensity_8_settings(self):
        """Test intensity 8 settings."""
        scanner = VersionScanner(intensity=8)
        assert scanner.max_probes == 10
    
    def test_all_intensity_descriptions(self):
        """Test all intensity descriptions are valid."""
        for intensity in range(10):
            scanner = VersionScanner(intensity=intensity)
            desc = scanner.get_intensity_description()
            assert isinstance(desc, str)
            assert len(desc) > 0
