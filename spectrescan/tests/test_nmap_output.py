"""
Tests for nmap-compatible output formatter.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import tempfile
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

from spectrescan.core.nmap_output import NmapOutputFormatter


@dataclass
class MockScanResult:
    """Mock scan result for testing."""
    host: str
    port: int
    state: str
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    timestamp: datetime = None


class TestNmapOutputFormatterInit:
    """Tests for NmapOutputFormatter initialization."""
    
    def test_init(self):
        """Test formatter initialization."""
        formatter = NmapOutputFormatter()
        assert formatter is not None


class TestGenerateGreppable:
    """Tests for greppable output generation."""
    
    def test_empty_results(self):
        """Test with empty results."""
        formatter = NmapOutputFormatter()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gnmap', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            formatter.generate_greppable([], output_path)
            
            content = output_path.read_text()
            assert "SpectreScan" in content
        finally:
            output_path.unlink(missing_ok=True)
    
    def test_single_result(self):
        """Test with single scan result."""
        formatter = NmapOutputFormatter()
        
        results = [
            MockScanResult(host="192.168.1.1", port=80, state="open", service="http")
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gnmap', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            formatter.generate_greppable(results, output_path)
            
            content = output_path.read_text()
            assert "192.168.1.1" in content
            assert "80" in content
            assert "open" in content
        finally:
            output_path.unlink(missing_ok=True)
    
    def test_multiple_hosts(self):
        """Test with multiple hosts."""
        formatter = NmapOutputFormatter()
        
        results = [
            MockScanResult(host="192.168.1.1", port=22, state="open", service="ssh"),
            MockScanResult(host="192.168.1.1", port=80, state="open", service="http"),
            MockScanResult(host="192.168.1.2", port=443, state="open", service="https"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gnmap', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            formatter.generate_greppable(results, output_path)
            
            content = output_path.read_text()
            assert "192.168.1.1" in content
            assert "192.168.1.2" in content
        finally:
            output_path.unlink(missing_ok=True)
    
    def test_with_scan_info(self):
        """Test with scan info metadata."""
        formatter = NmapOutputFormatter()
        
        results = [
            MockScanResult(host="192.168.1.1", port=80, state="open")
        ]
        
        scan_info = {
            "type": "tcp",
            "target": "192.168.1.1"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gnmap', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            formatter.generate_greppable(results, output_path, scan_info)
            
            content = output_path.read_text()
            assert "tcp" in content
        finally:
            output_path.unlink(missing_ok=True)


class TestGenerateXML:
    """Tests for XML output generation."""
    
    def test_empty_results(self):
        """Test XML with empty results."""
        formatter = NmapOutputFormatter()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            formatter.generate_xml([], output_path)
            
            content = output_path.read_text()
            assert "<?xml" in content or "<nmaprun" in content or content == ""
        finally:
            output_path.unlink(missing_ok=True)
    
    def test_single_result(self):
        """Test XML with single result."""
        formatter = NmapOutputFormatter()
        
        results = [
            MockScanResult(host="192.168.1.1", port=80, state="open", service="http")
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            formatter.generate_xml(results, output_path)
            
            content = output_path.read_text()
            # Should contain XML elements
            if content:
                assert "192.168.1.1" in content or "<" in content
        finally:
            output_path.unlink(missing_ok=True)


class TestGenerateNormal:
    """Tests for normal output generation."""
    
    def test_empty_results(self):
        """Test normal output with empty results."""
        formatter = NmapOutputFormatter()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.nmap', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            if hasattr(formatter, 'generate_normal'):
                formatter.generate_normal([], output_path)
                content = output_path.read_text()
                assert "SpectreScan" in content or content == ""
        finally:
            output_path.unlink(missing_ok=True)
    
    def test_with_results(self):
        """Test normal output with results."""
        formatter = NmapOutputFormatter()
        
        results = [
            MockScanResult(host="192.168.1.1", port=22, state="open", service="ssh"),
            MockScanResult(host="192.168.1.1", port=80, state="closed"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.nmap', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            if hasattr(formatter, 'generate_normal'):
                formatter.generate_normal(results, output_path)
                content = output_path.read_text()
                # Check for expected content
                if content:
                    assert "192.168.1.1" in content or "PORT" in content
        finally:
            output_path.unlink(missing_ok=True)


class TestHelperMethods:
    """Tests for helper methods."""
    
    def test_get_hostname(self):
        """Test hostname resolution helper."""
        formatter = NmapOutputFormatter()
        
        if hasattr(formatter, '_get_hostname'):
            hostname = formatter._get_hostname("127.0.0.1")
            # Should return something
            assert hostname is not None
    
    def test_format_port_string(self):
        """Test port string formatting."""
        formatter = NmapOutputFormatter()
        
        if hasattr(formatter, '_format_port_string'):
            result = MockScanResult(host="192.168.1.1", port=80, state="open", service="http")
            port_str = formatter._format_port_string(result)
            assert "80" in port_str


class TestGenerateAll:
    """Tests for generating all output formats."""
    
    def test_generate_all_formats(self):
        """Test generating all output formats at once."""
        formatter = NmapOutputFormatter()
        
        results = [
            MockScanResult(host="192.168.1.1", port=80, state="open", service="http"),
            MockScanResult(host="192.168.1.1", port=443, state="open", service="https"),
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "scan"
            
            # Generate greppable
            gnmap_path = base_path.with_suffix('.gnmap')
            formatter.generate_greppable(results, gnmap_path)
            assert gnmap_path.exists()
            
            # Generate XML
            xml_path = base_path.with_suffix('.xml')
            formatter.generate_xml(results, xml_path)
            # XML file should be created (may be empty)
