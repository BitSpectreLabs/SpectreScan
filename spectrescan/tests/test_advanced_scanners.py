"""
Tests for advanced scanners (SYN and UDP).

Author: BitSpectreLabs
License: MIT
"""

import pytest
import socket
from unittest.mock import patch, MagicMock

from spectrescan.core.syn_scan import SynScanner
from spectrescan.core.udp_scan import UdpScanner
from spectrescan.core.utils import ScanResult


class TestSynScannerInit:
    """Tests for SynScanner initialization."""
    
    def test_default_timeout(self):
        """Test default timeout value."""
        scanner = SynScanner()
        assert scanner.timeout == 2.0
    
    def test_custom_timeout(self):
        """Test custom timeout value."""
        scanner = SynScanner(timeout=5.0)
        assert scanner.timeout == 5.0
    
    def test_use_scapy_flag(self):
        """Test use_scapy flag."""
        scanner = SynScanner(use_scapy=True)
        assert scanner.use_scapy is True
        
        scanner = SynScanner(use_scapy=False)
        assert scanner.use_scapy is False
    
    def test_scapy_available_attribute(self):
        """Test scapy_available attribute exists."""
        scanner = SynScanner()
        assert hasattr(scanner, 'scapy_available')


class TestSynScannerScanPort:
    """Tests for SynScanner.scan_port method."""
    
    @patch('socket.socket')
    def test_fallback_connect_scan_open(self, mock_socket_class):
        """Test fallback connect scan for open port."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock
        
        scanner = SynScanner(use_scapy=False)
        result = scanner.scan_port("192.168.1.1", 80)
        
        assert isinstance(result, ScanResult)
        assert result.port == 80
        assert result.host == "192.168.1.1"
    
    @patch('socket.socket')
    def test_fallback_connect_scan_closed(self, mock_socket_class):
        """Test fallback connect scan for closed port."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket_class.return_value = mock_sock
        
        scanner = SynScanner(use_scapy=False)
        result = scanner.scan_port("192.168.1.1", 81)
        
        assert isinstance(result, ScanResult)
        assert result.state in ["closed", "filtered"]


class TestSynScannerScanPorts:
    """Tests for SynScanner.scan_ports method."""
    
    def test_scan_multiple_ports(self):
        """Test scanning multiple ports."""
        scanner = SynScanner(use_scapy=False)
        
        with patch.object(scanner, 'scan_port') as mock_scan:
            mock_scan.return_value = ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                protocol="tcp"
            )
            
            results = scanner.scan_ports("192.168.1.1", [80, 443, 22])
            
            assert len(results) == 3
            assert mock_scan.call_count == 3
    
    def test_scan_with_callback(self):
        """Test scanning with callback."""
        scanner = SynScanner(use_scapy=False)
        callback_results = []
        
        def callback(result):
            callback_results.append(result)
        
        with patch.object(scanner, 'scan_port') as mock_scan:
            mock_scan.return_value = ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                protocol="tcp"
            )
            
            scanner.scan_ports("192.168.1.1", [80, 443], callback=callback)
            
            assert len(callback_results) == 2
    
    def test_scan_empty_ports(self):
        """Test scanning empty port list."""
        scanner = SynScanner(use_scapy=False)
        
        results = scanner.scan_ports("192.168.1.1", [])
        
        assert results == []


class TestUdpScannerInit:
    """Tests for UdpScanner initialization."""
    
    def test_default_timeout(self):
        """Test default timeout value."""
        scanner = UdpScanner()
        assert scanner.timeout == 3.0
    
    def test_custom_timeout(self):
        """Test custom timeout value."""
        scanner = UdpScanner(timeout=5.0)
        assert scanner.timeout == 5.0


class TestUdpScannerProbes:
    """Tests for UDP probe generation."""
    
    def test_dns_probe(self):
        """Test DNS probe generation."""
        scanner = UdpScanner()
        probe = scanner._get_udp_probe(53)
        
        assert probe is not None
        assert isinstance(probe, bytes)
    
    def test_snmp_probe(self):
        """Test SNMP probe generation."""
        scanner = UdpScanner()
        probe = scanner._get_udp_probe(161)
        
        assert probe is not None
        assert isinstance(probe, bytes)
    
    def test_ntp_probe(self):
        """Test NTP probe generation."""
        scanner = UdpScanner()
        probe = scanner._get_udp_probe(123)
        
        assert probe is not None
        assert isinstance(probe, bytes)
    
    def test_generic_probe(self):
        """Test generic probe for unknown port."""
        scanner = UdpScanner()
        probe = scanner._get_udp_probe(54321)
        
        assert probe is not None


class TestUdpScannerScanPort:
    """Tests for UdpScanner.scan_port method."""
    
    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket_class):
        """Test scanning open UDP port (receives response)."""
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b"response", ("192.168.1.1", 53))
        mock_socket_class.return_value = mock_sock
        
        scanner = UdpScanner(timeout=1.0)
        result = scanner.scan_port("192.168.1.1", 53)
        
        assert isinstance(result, ScanResult)
        assert result.protocol == "udp"
        assert result.state == "open"
    
    @patch('socket.socket')
    def test_scan_port_timeout(self, mock_socket_class):
        """Test scanning UDP port with timeout."""
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout()
        mock_socket_class.return_value = mock_sock
        
        scanner = UdpScanner(timeout=1.0)
        result = scanner.scan_port("192.168.1.1", 53)
        
        assert isinstance(result, ScanResult)
        assert result.protocol == "udp"
        # Timeout means open|filtered
        assert result.state == "open|filtered"
    
    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket_class):
        """Test scanning closed UDP port."""
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_sock
        
        scanner = UdpScanner(timeout=1.0)
        result = scanner.scan_port("192.168.1.1", 53)
        
        assert isinstance(result, ScanResult)
        assert result.protocol == "udp"


class TestUdpScannerScanPorts:
    """Tests for UdpScanner.scan_ports method."""
    
    def test_scan_multiple_ports(self):
        """Test scanning multiple UDP ports."""
        scanner = UdpScanner(timeout=1.0)
        
        with patch.object(scanner, 'scan_port') as mock_scan:
            mock_scan.return_value = ScanResult(
                host="192.168.1.1",
                port=53,
                state="open",
                protocol="udp"
            )
            
            results = scanner.scan_ports("192.168.1.1", [53, 161, 123])
            
            assert len(results) == 3
            assert mock_scan.call_count == 3
    
    def test_scan_with_callback(self):
        """Test UDP scanning with callback."""
        scanner = UdpScanner(timeout=1.0)
        callback_results = []
        
        def callback(result):
            callback_results.append(result)
        
        with patch.object(scanner, 'scan_port') as mock_scan:
            mock_scan.return_value = ScanResult(
                host="192.168.1.1",
                port=53,
                state="open",
                protocol="udp"
            )
            
            scanner.scan_ports("192.168.1.1", [53, 161], callback=callback)
            
            assert len(callback_results) == 2
    
    def test_scan_empty_ports(self):
        """Test scanning empty UDP port list."""
        scanner = UdpScanner(timeout=1.0)
        
        results = scanner.scan_ports("192.168.1.1", [])
        
        assert results == []


class TestSynScannerScapyDetection:
    """Tests for Scapy detection and fallback."""
    
    def test_scapy_detection(self):
        """Test that scanner detects scapy availability."""
        scanner = SynScanner(use_scapy=True)
        # scapy_available will be True or False depending on environment
        assert isinstance(scanner.scapy_available, bool)
    
    def test_no_scapy(self):
        """Test scanner works without scapy."""
        scanner = SynScanner(use_scapy=False)
        assert scanner.scapy_available is False


class TestSynScannerFallback:
    """Tests for SynScanner fallback connect scan."""
    
    @patch('socket.socket')
    def test_timeout_returns_filtered(self, mock_socket_class):
        """Test that timeout returns filtered state."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout()
        mock_socket_class.return_value = mock_sock
        
        scanner = SynScanner(use_scapy=False, timeout=1.0)
        result = scanner._fallback_connect_scan("192.168.1.1", 80)
        
        assert result.state == "filtered"
    
    @patch('socket.socket')
    def test_socket_error_returns_filtered(self, mock_socket_class):
        """Test that socket error returns filtered state."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.error("Network unreachable")
        mock_socket_class.return_value = mock_sock
        
        scanner = SynScanner(use_scapy=False, timeout=1.0)
        result = scanner._fallback_connect_scan("192.168.1.1", 80)
        
        assert result.state == "filtered"


class TestSynScannerHelpers:
    """Tests for SYN scanner helper functions."""
    
    def test_is_scapy_available(self):
        """Test scapy availability check."""
        from spectrescan.core.syn_scan import is_scapy_available
        result = is_scapy_available()
        assert isinstance(result, bool)
    
    def test_get_syn_scan_warning(self):
        """Test SYN scan warning message."""
        from spectrescan.core.syn_scan import get_syn_scan_warning
        warning = get_syn_scan_warning()
        assert isinstance(warning, str)
    
    def test_requires_root(self):
        """Test requires_root method."""
        scanner = SynScanner(use_scapy=False)
        result = scanner.requires_root()
        assert isinstance(result, bool)


class TestUdpScannerCommonPorts:
    """Tests for UDP common ports scanning."""
    
    def test_scan_common_udp_ports(self):
        """Test scanning common UDP ports."""
        scanner = UdpScanner(timeout=1.0)
        
        with patch.object(scanner, 'scan_port') as mock_scan:
            mock_scan.return_value = ScanResult(
                host="192.168.1.1",
                port=53,
                state="open",
                protocol="udp"
            )
            
            results = scanner.scan_common_udp_ports("192.168.1.1")
            
            # Should scan multiple common UDP ports
            assert len(results) >= 10
            assert mock_scan.call_count >= 10


class TestUdpScannerHelpers:
    """Tests for UDP scanner helper functions."""
    
    def test_get_udp_scan_warning(self):
        """Test UDP scan warning message."""
        from spectrescan.core.udp_scan import get_udp_scan_warning
        warning = get_udp_scan_warning()
        assert isinstance(warning, str)
        assert "UDP scanning" in warning
        assert "limitations" in warning


class TestUdpScannerProbeDetails:
    """Tests for UDP probe details."""
    
    def test_probe_dict_coverage(self):
        """Test that known ports have specific probes."""
        scanner = UdpScanner()
        
        # These ports should have specific probes
        known_ports = [53, 67, 68, 69, 123, 137, 161, 500, 514, 520, 1900]
        
        for port in known_ports:
            probe = scanner._get_udp_probe(port)
            assert probe is not None
            assert len(probe) > 0
    
    def test_unknown_port_returns_empty(self):
        """Test that unknown ports return empty probe."""
        scanner = UdpScanner()
        probe = scanner._get_udp_probe(65535)
        assert probe == b''
