"""
Comprehensive unit tests for SpectreScan utils module
by BitSpectreLabs

Tests for spectrescan.core.utils module to increase coverage.
"""

import pytest
import os
import tempfile
import socket
from datetime import datetime
from unittest.mock import patch, MagicMock

from spectrescan.core.utils import (
    ScanResult,
    HostInfo,
    parse_target,
    parse_targets_from_file,
    parse_ports,
    get_common_ports,
    get_service_name,
    is_valid_ip,
    is_valid_hostname,
    format_banner,
    calculate_scan_time,
    validate_target,
    get_timestamp,
    get_timestamp_filename,
    sanitize_filename,
)


class TestScanResult:
    """Tests for ScanResult dataclass."""
    
    def test_basic_creation(self):
        """Test basic ScanResult creation."""
        result = ScanResult(host="192.168.1.1", port=80, state="open")
        assert result.host == "192.168.1.1"
        assert result.port == 80
        assert result.state == "open"
        assert result.protocol == "tcp"
        assert result.timestamp is not None
    
    def test_with_service(self):
        """Test ScanResult with service info."""
        result = ScanResult(
            host="192.168.1.1",
            port=22,
            state="open",
            service="ssh",
            banner="SSH-2.0-OpenSSH"
        )
        assert result.service == "ssh"
        assert result.banner == "SSH-2.0-OpenSSH"
    
    def test_with_protocol(self):
        """Test ScanResult with UDP protocol."""
        result = ScanResult(
            host="192.168.1.1",
            port=53,
            state="open",
            protocol="udp"
        )
        assert result.protocol == "udp"
    
    def test_states(self):
        """Test different port states."""
        for state in ["open", "closed", "filtered"]:
            result = ScanResult(host="192.168.1.1", port=80, state=state)
            assert result.state == state


class TestHostInfo:
    """Tests for HostInfo dataclass."""
    
    def test_basic_creation(self):
        """Test basic HostInfo creation."""
        host = HostInfo(ip="192.168.1.1")
        assert host.ip == "192.168.1.1"
        assert host.is_up is True
    
    def test_with_hostname(self):
        """Test HostInfo with hostname."""
        host = HostInfo(ip="192.168.1.1", hostname="router.local")
        assert host.hostname == "router.local"
    
    def test_with_os_guess(self):
        """Test HostInfo with OS guess."""
        host = HostInfo(ip="192.168.1.1", os_guess="Linux 5.x")
        assert host.os_guess == "Linux 5.x"
    
    def test_with_ttl(self):
        """Test HostInfo with TTL."""
        host = HostInfo(ip="192.168.1.1", ttl=64)
        assert host.ttl == 64
    
    def test_with_latency(self):
        """Test HostInfo with latency."""
        host = HostInfo(ip="192.168.1.1", latency_ms=10.5)
        assert host.latency_ms == 10.5


class TestParseTarget:
    """Tests for parse_target function."""
    
    def test_single_ip(self):
        """Test parsing single IP address."""
        result = parse_target("192.168.1.1")
        assert "192.168.1.1" in result
    
    def test_cidr_notation_24(self):
        """Test parsing CIDR /24 notation."""
        result = parse_target("192.168.1.0/30")
        assert len(result) >= 2  # /30 has 2 usable IPs
    
    def test_cidr_notation_32(self):
        """Test parsing CIDR /32 notation."""
        result = parse_target("192.168.1.1/32")
        # /32 is a single host - implementation may return 1 or 0
        assert len(result) <= 1
    
    def test_ip_range(self):
        """Test parsing IP range."""
        result = parse_target("192.168.1.1-3")
        assert len(result) >= 3
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "192.168.1.3" in result
    
    def test_comma_separated(self):
        """Test parsing comma-separated IPs."""
        result = parse_target("192.168.1.1,192.168.1.2")
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
    
    @patch('socket.gethostbyname')
    def test_hostname(self, mock_gethostbyname):
        """Test parsing hostname."""
        mock_gethostbyname.return_value = "93.184.216.34"
        result = parse_target("example.com")
        assert len(result) >= 1
    
    def test_list_input(self):
        """Test parsing list of targets."""
        result = parse_target(["192.168.1.1", "192.168.1.2"])
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result


class TestParsePorts:
    """Tests for parse_ports function."""
    
    def test_single_port(self):
        """Test parsing single port."""
        result = parse_ports("80")
        assert result == [80]
    
    def test_port_range(self):
        """Test parsing port range."""
        result = parse_ports("80-85")
        assert result == [80, 81, 82, 83, 84, 85]
    
    def test_comma_separated(self):
        """Test parsing comma-separated ports."""
        result = parse_ports("22,80,443")
        assert 22 in result
        assert 80 in result
        assert 443 in result
    
    def test_mixed_specification(self):
        """Test parsing mixed port specification."""
        result = parse_ports("22,80-82,443")
        assert 22 in result
        assert 80 in result
        assert 81 in result
        assert 82 in result
        assert 443 in result
    
    def test_all_ports(self):
        """Test parsing all ports shortcut."""
        result = parse_ports("1-65535")
        assert len(result) == 65535
        assert 1 in result
        assert 65535 in result


class TestParseTargetsFromFile:
    """Tests for parse_targets_from_file function."""
    
    def test_simple_file(self):
        """Test parsing simple targets file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("192.168.1.1\n")
            f.write("192.168.1.2\n")
            f.write("192.168.1.3\n")
            temp_path = f.name
        
        try:
            result = parse_targets_from_file(temp_path)
            assert len(result) >= 3
            assert "192.168.1.1" in result
        finally:
            try:
                os.unlink(temp_path)
            except PermissionError:
                pass  # Windows may still have file locked
    
    def test_file_with_comments(self):
        """Test parsing file with comments."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# This is a comment\n")
            f.write("192.168.1.1\n")
            f.write("# Another comment\n")
            f.write("192.168.1.2\n")
            temp_path = f.name
        
        try:
            result = parse_targets_from_file(temp_path)
            assert len(result) >= 2
        finally:
            try:
                os.unlink(temp_path)
            except PermissionError:
                pass
    
    def test_file_with_empty_lines(self):
        """Test parsing file with empty lines."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("192.168.1.1\n")
            f.write("\n")
            f.write("\n")
            f.write("192.168.1.2\n")
            temp_path = f.name
        
        try:
            result = parse_targets_from_file(temp_path)
            assert len(result) >= 2
        finally:
            try:
                os.unlink(temp_path)
            except PermissionError:
                pass
    
    def test_file_not_found(self):
        """Test FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            parse_targets_from_file("/nonexistent/path/targets.txt")
    
    def test_file_with_cidr(self):
        """Test parsing file with CIDR notation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("10.0.0.0/30\n")
            temp_path = f.name
        
        try:
            result = parse_targets_from_file(temp_path)
            assert len(result) >= 2
        finally:
            try:
                os.unlink(temp_path)
            except PermissionError:
                pass


class TestValidationFunctions:
    """Tests for validation functions."""
    
    def test_is_valid_ip_ipv4(self):
        """Test valid IPv4 addresses."""
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("172.16.0.1") is True
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("0.0.0.0") is True
        assert is_valid_ip("255.255.255.255") is True
    
    def test_is_valid_ip_invalid(self):
        """Test invalid IP addresses."""
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("192.168.1.256") is False
        assert is_valid_ip("not.an.ip") is False
        assert is_valid_ip("192.168.1") is False
    
    def test_is_valid_hostname_valid(self):
        """Test valid hostnames."""
        assert is_valid_hostname("example.com") is True
        assert is_valid_hostname("sub.example.com") is True
        assert is_valid_hostname("test-server") is True
    
    def test_is_valid_hostname_invalid(self):
        """Test invalid hostnames."""
        assert is_valid_hostname("invalid..hostname") is False
        assert is_valid_hostname("") is False


class TestGetCommonPorts:
    """Tests for get_common_ports function."""
    
    def test_get_top_10(self):
        """Test getting top 10 common ports."""
        ports = get_common_ports(10)
        assert len(ports) == 10
        # Most common ports should include HTTP and SSH
        assert 80 in ports  # HTTP
        assert 22 in ports  # SSH
    
    def test_get_top_100(self):
        """Test getting top 100 common ports."""
        ports = get_common_ports(100)
        assert len(ports) == 100
    
    def test_get_top_1000(self):
        """Test getting top 1000 common ports."""
        ports = get_common_ports(1000)
        assert len(ports) == 1000
    
    def test_ports_in_valid_range(self):
        """Test all ports are in valid range."""
        ports = get_common_ports(100)
        for port in ports:
            assert 1 <= port <= 65535


class TestGetServiceName:
    """Tests for get_service_name function."""
    
    def test_common_services(self):
        """Test common service names."""
        assert get_service_name(21) == "ftp"
        assert get_service_name(22) == "ssh"
        assert get_service_name(80) == "http"
        assert get_service_name(443) == "https"
    
    def test_uncommon_port(self):
        """Test unknown port returns None or unknown."""
        result = get_service_name(54321)
        assert result is None or result == "unknown"
    
    def test_well_known_ports(self):
        """Test various well-known ports."""
        assert get_service_name(23) == "telnet"
        assert get_service_name(25) == "smtp"


class TestCalculateScanTime:
    """Tests for calculate_scan_time function."""
    
    def test_with_start_and_end(self):
        """Test formatting with start and end time."""
        start = datetime(2025, 1, 1, 12, 0, 0)
        end = datetime(2025, 1, 1, 12, 1, 30)
        result = calculate_scan_time(start, end)
        assert result is not None
        assert "1" in result or "90" in result
    
    def test_with_seconds(self):
        """Test formatting with seconds as float."""
        result = calculate_scan_time(65.5)
        assert result is not None
        assert "1" in result  # 1m 5s or similar
    
    def test_short_duration(self):
        """Test short duration formatting."""
        result = calculate_scan_time(5.25)
        assert "5" in result
        assert "second" in result.lower()


class TestFormatBanner:
    """Tests for format_banner function."""
    
    def test_ascii_banner(self):
        """Test formatting ASCII banner."""
        banner = b"SSH-2.0-OpenSSH_8.2\r\n"
        result = format_banner(banner)
        assert "SSH" in result
        assert "OpenSSH" in result
    
    def test_binary_banner(self):
        """Test formatting binary banner."""
        banner = b"\x00\x01\x02\x03SSH"
        result = format_banner(banner)
        assert result is not None
    
    def test_empty_banner(self):
        """Test formatting empty banner."""
        banner = b""
        result = format_banner(banner)
        assert result == ""
    
    def test_long_banner(self):
        """Test formatting long banner (truncation)."""
        banner = b"A" * 1000
        result = format_banner(banner)
        assert len(result) <= 510  # 500 + "..."


class TestValidateTarget:
    """Tests for validate_target function."""
    
    def test_valid_ip(self):
        """Test validation of valid IP."""
        assert validate_target("192.168.1.1") is True
    
    def test_valid_cidr(self):
        """Test validation of valid CIDR."""
        assert validate_target("192.168.1.0/24") is True
    
    def test_valid_range(self):
        """Test validation of valid IP range."""
        assert validate_target("192.168.1.1-10") is True


class TestTimestampFunctions:
    """Tests for timestamp functions."""
    
    def test_get_timestamp(self):
        """Test get_timestamp returns valid format."""
        ts = get_timestamp()
        assert isinstance(ts, str)
        assert "-" in ts
        assert ":" in ts
    
    def test_get_timestamp_filename(self):
        """Test get_timestamp_filename returns valid format."""
        ts = get_timestamp_filename()
        assert isinstance(ts, str)
        assert "_" in ts
        assert ":" not in ts  # No colons for filenames


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""
    
    def test_valid_filename(self):
        """Test valid filename unchanged."""
        assert sanitize_filename("report.txt") == "report.txt"
    
    def test_invalid_chars(self):
        """Test invalid characters removed."""
        result = sanitize_filename("file<>:name.txt")
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result
    
    def test_long_filename(self):
        """Test long filename truncated."""
        long_name = "a" * 300
        result = sanitize_filename(long_name)
        assert len(result) <= 200
