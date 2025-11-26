"""
Tests for version detection mode.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import asyncio
from spectrescan.core.version_mode import (
    VersionScanner,
    VersionScanResult,
    VersionIntensity
)


class MockServiceDetector:
    """Mock service detector for testing."""
    
    async def detect_service(self, host, port, banner=None):
        """Mock service detection."""
        if port == 80:
            return "http", "nginx", "1.18.0", 95
        elif port == 22:
            return "ssh", "OpenSSH", "8.2p1", 90
        elif port == 3306:
            return "mysql", "MySQL", "8.0.25", 85
        return None, None, None, 0


@pytest.mark.asyncio
async def test_version_scanner_basic():
    """Test basic version scanning."""
    scanner = VersionScanner(intensity=VersionIntensity.NORMAL)
    scanner.service_detector = MockServiceDetector()
    
    results = await scanner.scan_version(
        host="127.0.0.1",
        ports=[80, 22, 3306]
    )
    
    assert len(results) == 3
    assert all(isinstance(r, VersionScanResult) for r in results)
    
    # Check HTTP result
    http_result = next(r for r in results if r.port == 80)
    assert http_result.service == "http"
    assert http_result.product == "nginx"
    assert http_result.version == "1.18.0"
    assert http_result.confidence >= 90


@pytest.mark.asyncio
async def test_intensity_levels():
    """Test different intensity levels."""
    # Light intensity
    scanner_light = VersionScanner(intensity=VersionIntensity.LIGHT)
    assert scanner_light.timeout == 2.0
    assert scanner_light.max_concurrent == 10
    
    # Normal intensity
    scanner_normal = VersionScanner(intensity=VersionIntensity.NORMAL)
    assert scanner_normal.timeout == 5.0
    assert scanner_normal.max_concurrent == 50
    
    # Insane intensity
    scanner_insane = VersionScanner(intensity=VersionIntensity.INSANE)
    assert scanner_insane.timeout == 300.0
    assert scanner_insane.max_concurrent == 1


@pytest.mark.asyncio
async def test_version_result_dataclass():
    """Test VersionScanResult dataclass."""
    result = VersionScanResult(
        host="192.168.1.1",
        port=80,
        service="http",
        version="1.2.3",
        product="nginx",
        confidence=95,
        method="probe",
        detection_time=0.5
    )
    
    assert result.host == "192.168.1.1"
    assert result.port == 80
    assert result.service == "http"
    assert result.version == "1.2.3"
    assert result.product == "nginx"
    assert result.confidence == 95
    assert result.method == "probe"


def test_intensity_enum():
    """Test VersionIntensity enum."""
    assert VersionIntensity.DISABLED.value == 0
    assert VersionIntensity.LIGHT.value == 2
    assert VersionIntensity.NORMAL.value == 7
    assert VersionIntensity.INSANE.value == 9
    
    # Test enum comparison
    assert VersionIntensity.LIGHT < VersionIntensity.NORMAL
    assert VersionIntensity.NORMAL < VersionIntensity.INSANE
