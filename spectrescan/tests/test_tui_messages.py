"""
Tests for TUI message-based updates
by BitSpectreLabs
"""

import pytest
from spectrescan.tui.app import (
    ScanResultMessage,
    ScanCompleteMessage,
    ScanErrorMessage,
)
from spectrescan.core.utils import ScanResult
from datetime import datetime


class TestTUIMessages:
    """Test suite for TUI message classes."""
    
    def test_scan_result_message_creation(self):
        """Test ScanResultMessage can be created with a ScanResult."""
        result = ScanResult(
            host="192.168.1.1",
            port=80,
            state="open",
            service="http",
            banner="HTTP/1.1 200 OK",
            protocol="tcp",
            timestamp=datetime.now()
        )
        message = ScanResultMessage(result)
        
        assert message.result == result
        assert message.result.host == "192.168.1.1"
        assert message.result.port == 80
        assert message.result.state == "open"
    
    def test_scan_complete_message_creation(self):
        """Test ScanCompleteMessage can be created with a summary dict."""
        summary = {
            "total_ports": 1000,
            "open_ports": 5,
            "closed_ports": 100,
            "filtered_ports": 895,
            "scan_duration": "10.5s",
            "scan_duration_seconds": 10.5
        }
        message = ScanCompleteMessage(summary)
        
        assert message.summary == summary
        assert message.summary["open_ports"] == 5
        assert message.summary["total_ports"] == 1000
    
    def test_scan_error_message_creation(self):
        """Test ScanErrorMessage can be created with an error string."""
        error = "Connection timeout"
        message = ScanErrorMessage(error)
        
        assert message.error == error
        assert "timeout" in message.error.lower()
    
    def test_scan_result_message_with_minimal_result(self):
        """Test ScanResultMessage with minimal ScanResult fields."""
        result = ScanResult(
            host="10.0.0.1",
            port=22,
            state="closed",
            protocol="tcp"
        )
        message = ScanResultMessage(result)
        
        assert message.result.host == "10.0.0.1"
        assert message.result.service is None
        assert message.result.banner is None
    
    def test_scan_complete_message_with_empty_summary(self):
        """Test ScanCompleteMessage with minimal summary."""
        summary = {}
        message = ScanCompleteMessage(summary)
        
        assert message.summary == {}
    
    def test_scan_error_message_with_empty_error(self):
        """Test ScanErrorMessage with empty error string."""
        message = ScanErrorMessage("")
        
        assert message.error == ""


class TestTUIMessageInheritance:
    """Test that TUI messages inherit from Textual Message."""
    
    def test_scan_result_message_is_message(self):
        """Test ScanResultMessage inherits from Message."""
        from textual.message import Message
        result = ScanResult(host="test", port=80, state="open", protocol="tcp")
        message = ScanResultMessage(result)
        
        assert isinstance(message, Message)
    
    def test_scan_complete_message_is_message(self):
        """Test ScanCompleteMessage inherits from Message."""
        from textual.message import Message
        message = ScanCompleteMessage({})
        
        assert isinstance(message, Message)
    
    def test_scan_error_message_is_message(self):
        """Test ScanErrorMessage inherits from Message."""
        from textual.message import Message
        message = ScanErrorMessage("error")
        
        assert isinstance(message, Message)
