"""
Comprehensive unit tests for SpectreScan presets module
by BitSpectreLabs

Tests for spectrescan.core.presets module to increase coverage.
"""

import pytest
from spectrescan.core.presets import (
    ScanPreset,
    ScanConfig,
    get_preset_config,
    get_timing_parameters,
)
from spectrescan.core.timing_engine import TimingLevel, TimingTemplate


class TestScanPreset:
    """Tests for ScanPreset enum."""
    
    def test_all_presets_exist(self):
        """Test all expected presets exist."""
        assert ScanPreset.QUICK.value == "quick"
        assert ScanPreset.TOP_PORTS.value == "top-ports"
        assert ScanPreset.FULL.value == "full"
        assert ScanPreset.STEALTH.value == "stealth"
        assert ScanPreset.SAFE.value == "safe"
        assert ScanPreset.AGGRESSIVE.value == "aggressive"
        assert ScanPreset.CUSTOM.value == "custom"
    
    def test_preset_count(self):
        """Test correct number of presets."""
        assert len(ScanPreset) == 7


class TestScanConfig:
    """Tests for ScanConfig dataclass."""
    
    def test_basic_config(self):
        """Test basic ScanConfig creation."""
        config = ScanConfig(
            name="Test Scan",
            description="Test description",
            ports=[80, 443],
            scan_types=["tcp"],
            threads=100,
            timeout=2.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=False,
            enable_banner_grabbing=True,
            randomize=False,
            timing_level=3
        )
        assert config.name == "Test Scan"
        assert config.ports == [80, 443]
        assert config.timeout == 2.0
    
    def test_config_with_rate_limit(self):
        """Test ScanConfig with rate limiting."""
        config = ScanConfig(
            name="Rate Limited",
            description="Rate limited scan",
            ports=[80],
            scan_types=["syn"],
            threads=10,
            timeout=5.0,
            rate_limit=50,
            enable_service_detection=False,
            enable_os_detection=False,
            enable_banner_grabbing=False,
            randomize=True,
            timing_level=1
        )
        assert config.rate_limit == 50
        assert config.randomize is True
    
    def test_config_str(self):
        """Test ScanConfig string representation."""
        config = ScanConfig(
            name="Test",
            description="A test scan",
            ports=[80],
            scan_types=["tcp"],
            threads=100,
            timeout=2.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=False
        )
        result = str(config)
        assert "Test" in result
        assert "A test scan" in result
    
    def test_config_timing_template_initialization(self):
        """Test that timing template is initialized."""
        config = ScanConfig(
            name="Test",
            description="Test",
            ports=[80],
            scan_types=["tcp"],
            threads=100,
            timeout=2.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=False,
            enable_banner_grabbing=True,
            randomize=False,
            timing_level=4  # Aggressive
        )
        assert config.timing_template is not None
        assert isinstance(config.timing_template, TimingTemplate)
    
    def test_config_multiple_scan_types(self):
        """Test ScanConfig with multiple scan types."""
        config = ScanConfig(
            name="Multi Scan",
            description="Multiple scan types",
            ports=[80, 443, 22],
            scan_types=["tcp", "syn", "udp"],
            threads=500,
            timeout=3.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=False
        )
        assert "tcp" in config.scan_types
        assert "syn" in config.scan_types
        assert "udp" in config.scan_types


class TestGetPresetConfig:
    """Tests for get_preset_config function."""
    
    def test_quick_preset(self):
        """Test QUICK preset configuration."""
        config = get_preset_config(ScanPreset.QUICK)
        assert config.name == "Quick Scan"
        assert len(config.ports) == 100
        assert "tcp" in config.scan_types
        assert config.enable_service_detection is True
        assert config.enable_os_detection is False
        assert config.enable_banner_grabbing is True
    
    def test_top_ports_preset(self):
        """Test TOP_PORTS preset configuration."""
        config = get_preset_config(ScanPreset.TOP_PORTS)
        assert config.name == "Top Ports"
        assert len(config.ports) == 1000
        assert config.enable_os_detection is True
        assert config.threads == 200
    
    def test_full_preset(self):
        """Test FULL preset configuration."""
        config = get_preset_config(ScanPreset.FULL)
        assert config.name == "Full Scan"
        assert len(config.ports) == 65535
        assert "tcp" in config.scan_types
        assert "udp" in config.scan_types
        assert config.threads == 500
    
    def test_stealth_preset(self):
        """Test STEALTH preset configuration."""
        config = get_preset_config(ScanPreset.STEALTH)
        assert config.name == "Stealth Scan"
        assert "syn" in config.scan_types
        assert config.rate_limit == 50
        assert config.randomize is True
        assert config.enable_service_detection is False
        assert config.enable_os_detection is False
        assert config.enable_banner_grabbing is False
    
    def test_safe_preset(self):
        """Test SAFE preset configuration."""
        config = get_preset_config(ScanPreset.SAFE)
        assert config.name == "Safe Scan"
        assert config.rate_limit == 20
        assert config.threads == 20
        assert config.timeout == 5.0
    
    def test_aggressive_preset(self):
        """Test AGGRESSIVE preset configuration."""
        config = get_preset_config(ScanPreset.AGGRESSIVE)
        assert config.name == "Aggressive Scan"
        assert len(config.ports) == 65535
        assert config.threads == 1000
        assert config.timeout == 1.0
        assert config.enable_service_detection is True
        assert config.enable_os_detection is True
        assert config.enable_banner_grabbing is True
    
    def test_custom_preset(self):
        """Test CUSTOM preset configuration."""
        config = get_preset_config(ScanPreset.CUSTOM)
        assert config.name == "Custom Scan"
        assert config.description == "User-defined configuration"
    
    def test_all_presets_have_configs(self):
        """Test all presets return valid configs."""
        for preset in ScanPreset:
            config = get_preset_config(preset)
            assert config is not None
            assert isinstance(config, ScanConfig)
            assert len(config.ports) > 0
            assert len(config.scan_types) > 0


class TestGetTimingParameters:
    """Tests for get_timing_parameters function."""
    
    def test_paranoid_timing(self):
        """Test T0 (Paranoid) timing parameters."""
        params = get_timing_parameters(0)
        assert params["name"] == "Paranoid"
        assert params["threads"] == 1
        assert params["timeout"] >= 10.0
        assert params["delay_between_probes"] > 0
    
    def test_sneaky_timing(self):
        """Test T1 (Sneaky) timing parameters."""
        params = get_timing_parameters(1)
        assert params["name"] == "Sneaky"
        assert params["threads"] < 20
    
    def test_polite_timing(self):
        """Test T2 (Polite) timing parameters."""
        params = get_timing_parameters(2)
        assert params["name"] == "Polite"
    
    def test_normal_timing(self):
        """Test T3 (Normal) timing parameters."""
        params = get_timing_parameters(3)
        assert params["name"] == "Normal"
        assert params["threads"] >= 100
    
    def test_aggressive_timing(self):
        """Test T4 (Aggressive) timing parameters."""
        params = get_timing_parameters(4)
        assert params["name"] == "Aggressive"
        assert params["threads"] >= 500
        assert params["timeout"] <= 2.0
    
    def test_insane_timing(self):
        """Test T5 (Insane) timing parameters."""
        params = get_timing_parameters(5)
        assert params["name"] == "Insane"
        assert params["threads"] >= 1000
        assert params["timeout"] <= 1.0
    
    def test_all_templates_have_params(self):
        """Test all timing templates have parameters."""
        for level in range(6):
            params = get_timing_parameters(level)
            assert "name" in params
            assert "timeout" in params
            assert "threads" in params


class TestPresetPortCoverage:
    """Tests for port coverage in presets."""
    
    def test_quick_has_common_ports(self):
        """Test QUICK preset includes common ports."""
        config = get_preset_config(ScanPreset.QUICK)
        assert 80 in config.ports  # HTTP
        assert 443 in config.ports  # HTTPS
        assert 22 in config.ports  # SSH
    
    def test_full_covers_all_ports(self):
        """Test FULL preset covers all ports."""
        config = get_preset_config(ScanPreset.FULL)
        assert config.ports[0] == 1
        assert config.ports[-1] == 65535
        assert len(set(config.ports)) == 65535


class TestPresetTimingLevels:
    """Tests for timing levels in presets."""
    
    def test_quick_is_aggressive(self):
        """Test QUICK preset uses aggressive timing."""
        config = get_preset_config(ScanPreset.QUICK)
        assert config.timing_level == 4  # Aggressive
    
    def test_stealth_is_sneaky(self):
        """Test STEALTH preset uses sneaky timing."""
        config = get_preset_config(ScanPreset.STEALTH)
        assert config.timing_level == 1  # Sneaky
    
    def test_safe_is_polite(self):
        """Test SAFE preset uses polite timing."""
        config = get_preset_config(ScanPreset.SAFE)
        assert config.timing_level == 2  # Polite
    
    def test_aggressive_is_insane(self):
        """Test AGGRESSIVE preset uses insane timing."""
        config = get_preset_config(ScanPreset.AGGRESSIVE)
        assert config.timing_level == 5  # Insane


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
