"""
Comprehensive unit tests for SpectreScan OS detection module
by BitSpectreLabs

Tests for spectrescan.core.os_detect module to increase coverage.
"""

import pytest
from unittest.mock import patch, MagicMock
import socket

from spectrescan.core.os_detect import (
    OSDetector,
    OSFingerprint,
    TTL_SIGNATURES,
    WINDOW_SIGNATURES,
    format_os_detection,
    requires_privileges,
)


class TestOSFingerprint:
    """Tests for OSFingerprint dataclass."""
    
    def test_basic_fingerprint(self):
        """Test basic OSFingerprint creation."""
        fp = OSFingerprint(
            os_guess="Linux 4.x",
            confidence=85
        )
        assert fp.os_guess == "Linux 4.x"
        assert fp.confidence == 85
    
    def test_fingerprint_with_all_fields(self):
        """Test OSFingerprint with all fields."""
        fp = OSFingerprint(
            ttl=64,
            window_size=5840,
            df_flag=True,
            tcp_options="MSS,SACK,Timestamp",
            os_guess="Linux",
            confidence=90
        )
        assert fp.ttl == 64
        assert fp.window_size == 5840
        assert fp.df_flag is True
        assert fp.tcp_options == "MSS,SACK,Timestamp"
        assert fp.os_guess == "Linux"
        assert fp.confidence == 90
    
    def test_fingerprint_unknown_os(self):
        """Test OSFingerprint for unknown OS."""
        fp = OSFingerprint(
            os_guess="Unknown",
            confidence=0
        )
        assert fp.os_guess == "Unknown"
        assert fp.confidence == 0
    
    def test_fingerprint_defaults(self):
        """Test OSFingerprint default values."""
        fp = OSFingerprint()
        assert fp.ttl is None
        assert fp.window_size is None
        assert fp.df_flag is None
        assert fp.tcp_options is None
        assert fp.os_guess is None
        assert fp.confidence == 0


class TestOSDetectorInit:
    """Tests for OSDetector initialization."""
    
    def test_default_timeout(self):
        """Test default timeout."""
        detector = OSDetector()
        assert detector.timeout == 2.0
    
    def test_custom_timeout(self):
        """Test custom timeout."""
        detector = OSDetector(timeout=5.0)
        assert detector.timeout == 5.0


class TestTTLSignatures:
    """Tests for TTL signature dictionary."""
    
    def test_linux_signature_exists(self):
        """Test Linux TTL signature exists."""
        assert (64, 64) in TTL_SIGNATURES
    
    def test_windows_signature_exists(self):
        """Test Windows TTL signature exists."""
        assert (128, 128) in TTL_SIGNATURES
    
    def test_cisco_signature_exists(self):
        """Test Cisco TTL signature exists."""
        assert (255, 255) in TTL_SIGNATURES


class TestWindowSignatures:
    """Tests for Window size signatures."""
    
    def test_linux_window_exists(self):
        """Test Linux window signature exists."""
        assert 5840 in WINDOW_SIGNATURES
    
    def test_windows_window_exists(self):
        """Test Windows window signature exists."""
        assert 8192 in WINDOW_SIGNATURES


class TestOSDetectorDetection:
    """Tests for OS detection functionality."""
    
    @patch('socket.socket')
    def test_detect_os_basic(self, mock_socket_class):
        """Test basic OS detection."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.return_value = None
        mock_socket.getsockopt.return_value = 64
        
        detector = OSDetector()
        result = detector.detect_os("192.168.1.1")
        assert isinstance(result, OSFingerprint)
    
    @patch('socket.socket')
    def test_detect_os_with_open_port(self, mock_socket_class):
        """Test OS detection with open port."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.return_value = None
        mock_socket.getsockopt.return_value = 64  # Return valid TTL
        
        detector = OSDetector()
        result = detector.detect_os("192.168.1.1", open_port=80)
        assert isinstance(result, OSFingerprint)
    
    @patch('socket.socket')
    def test_detect_os_connection_refused(self, mock_socket_class):
        """Test OS detection when connection refused."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.side_effect = ConnectionRefusedError()
        
        detector = OSDetector()
        result = detector.detect_os("192.168.1.1")
        assert result is not None
        assert isinstance(result, OSFingerprint)


class TestOSDetectorBannerEnhancement:
    """Tests for banner-based OS enhancement."""
    
    def test_enhance_with_linux_banner(self):
        """Test enhancing fingerprint with Linux banner."""
        detector = OSDetector()
        fp = OSFingerprint(os_guess=None, confidence=0)
        banner = "SSH-2.0-OpenSSH_8.2 Ubuntu-4ubuntu0.1"
        
        enhanced = detector.enhance_with_banner(fp, banner)
        assert enhanced is not None
        assert isinstance(enhanced, OSFingerprint)
    
    def test_enhance_with_windows_banner(self):
        """Test enhancing fingerprint with Windows banner."""
        detector = OSDetector()
        fp = OSFingerprint(os_guess=None, confidence=0)
        banner = "Microsoft-IIS/10.0"
        
        enhanced = detector.enhance_with_banner(fp, banner)
        assert enhanced is not None
    
    def test_enhance_with_no_banner(self):
        """Test enhancing fingerprint with no banner."""
        detector = OSDetector()
        fp = OSFingerprint(os_guess="Linux", confidence=50)
        
        enhanced = detector.enhance_with_banner(fp, None)
        assert enhanced.os_guess == "Linux"
    
    def test_enhance_with_empty_banner(self):
        """Test enhancing fingerprint with empty banner."""
        detector = OSDetector()
        fp = OSFingerprint(os_guess=None, confidence=0)
        
        enhanced = detector.enhance_with_banner(fp, "")
        assert enhanced is not None


class TestFormatOSDetection:
    """Tests for format_os_detection function."""
    
    def test_format_with_os_guess(self):
        """Test formatting with OS guess."""
        fp = OSFingerprint(os_guess="Linux 4.x", confidence=85, ttl=64)
        result = format_os_detection(fp)
        assert "Linux" in result
    
    def test_format_with_no_guess(self):
        """Test formatting with no OS guess."""
        fp = OSFingerprint(confidence=0)
        result = format_os_detection(fp)
        assert result is not None
    
    def test_format_includes_ttl(self):
        """Test formatting includes TTL."""
        fp = OSFingerprint(ttl=64, os_guess="Linux")
        result = format_os_detection(fp)
        assert "64" in result or "TTL" in result


class TestRequiresPrivileges:
    """Tests for requires_privileges function."""
    
    def test_returns_bool(self):
        """Test function returns boolean."""
        result = requires_privileges()
        assert isinstance(result, bool)


class TestOSDetectorEdgeCases:
    """Tests for edge cases in OS detection."""
    
    @patch('socket.socket')
    def test_unreachable_host(self, mock_socket_class):
        """Test detection with unreachable host."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.side_effect = socket.timeout()
        
        detector = OSDetector()
        result = detector.detect_os("192.168.1.1")
        assert result is not None
        assert isinstance(result, OSFingerprint)


class TestOSFingerprintDetails:
    """Tests for OSFingerprint details."""
    
    def test_fingerprint_with_tcp_options(self):
        """Test fingerprint with TCP options."""
        fp = OSFingerprint(
            os_guess="Linux",
            confidence=90,
            tcp_options="MSS,SACK,Timestamp,NOP,WindowScale"
        )
        assert "MSS" in fp.tcp_options
    
    def test_fingerprint_with_df_flag(self):
        """Test fingerprint with DF flag."""
        fp = OSFingerprint(
            os_guess="Linux",
            confidence=80,
            df_flag=True
        )
        assert fp.df_flag is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
