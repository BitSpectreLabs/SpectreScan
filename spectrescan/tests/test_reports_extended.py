"""
Comprehensive unit tests for SpectreScan reports module
by BitSpectreLabs

Tests for spectrescan.reports module to increase coverage.
"""

import pytest
import json
import csv
import xml.etree.ElementTree as ET
import tempfile
import os
from pathlib import Path
from datetime import datetime

from spectrescan.core.utils import ScanResult, HostInfo
from spectrescan.reports import (
    generate_json_report,
    generate_csv_report,
    generate_xml_report,
)


class TestGenerateJSONReport:
    """Tests for generate_json_report function."""
    
    @pytest.fixture
    def sample_results(self):
        """Create sample scan results."""
        return [
            ScanResult(host="192.168.1.1", port=22, state="open", service="ssh", 
                      banner="SSH-2.0-OpenSSH_8.2"),
            ScanResult(host="192.168.1.1", port=80, state="open", service="http",
                      banner="Apache/2.4.41"),
            ScanResult(host="192.168.1.1", port=443, state="closed"),
        ]
    
    @pytest.fixture
    def sample_summary(self):
        """Create sample scan summary."""
        return {
            "total_ports": 100,
            "open_ports": 2,
            "closed_ports": 98,
            "filtered_ports": 0,
            "scan_duration": 10.5,
        }
    
    def test_creates_valid_json(self, sample_results):
        """Test JSON report is valid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report(sample_results, output_path)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert data is not None
            assert "scan_info" in data
            assert "results" in data
        finally:
            os.unlink(output_path)
    
    def test_contains_scan_info(self, sample_results):
        """Test JSON report contains scan info."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report(sample_results, output_path)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert data["scan_info"]["tool"] == "SpectreScan"
            assert data["scan_info"]["vendor"] == "BitSpectreLabs"
            assert "timestamp" in data["scan_info"]
        finally:
            os.unlink(output_path)
    
    def test_contains_all_results(self, sample_results):
        """Test JSON report contains all results."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report(sample_results, output_path)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert len(data["results"]) == 3
        finally:
            os.unlink(output_path)
    
    def test_result_structure(self, sample_results):
        """Test JSON result structure is correct."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report(sample_results, output_path)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            result = data["results"][0]
            assert "host" in result
            assert "port" in result
            assert "protocol" in result
            assert "state" in result
            assert "service" in result
            assert "banner" in result
        finally:
            os.unlink(output_path)
    
    def test_with_summary(self, sample_results, sample_summary):
        """Test JSON report with summary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report(sample_results, output_path, summary=sample_summary)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert "summary" in data
            assert data["summary"]["total_ports"] == 100
            assert data["summary"]["open_ports"] == 2
        finally:
            os.unlink(output_path)
    
    def test_empty_results(self):
        """Test JSON report with empty results."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report([], output_path)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert len(data["results"]) == 0
        finally:
            os.unlink(output_path)
    
    def test_unicode_in_banner(self):
        """Test JSON report handles unicode in banner."""
        results = [
            ScanResult(host="192.168.1.1", port=80, state="open",
                      banner="Server: Nginx с юникодом")
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report(results, output_path)
            
            with open(output_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            assert "юникод" in data["results"][0]["banner"]
        finally:
            os.unlink(output_path)


class TestGenerateCSVReport:
    """Tests for generate_csv_report function."""
    
    @pytest.fixture
    def sample_results(self):
        """Create sample scan results."""
        return [
            ScanResult(host="192.168.1.1", port=22, state="open", service="ssh"),
            ScanResult(host="192.168.1.1", port=80, state="open", service="http"),
            ScanResult(host="192.168.1.1", port=443, state="closed"),
        ]
    
    def test_creates_valid_csv(self, sample_results):
        """Test CSV report is valid CSV."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_csv_report(sample_results, output_path)
            
            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)
            
            assert len(rows) == 4  # Header + 3 results
        finally:
            os.unlink(output_path)
    
    def test_has_header(self, sample_results):
        """Test CSV report has header row."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_csv_report(sample_results, output_path)
            
            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                header = next(reader)
            
            assert "Host" in header
            assert "Port" in header
            assert "Protocol" in header
            assert "State" in header
            assert "Service" in header
            assert "Banner" in header
        finally:
            os.unlink(output_path)
    
    def test_data_values(self, sample_results):
        """Test CSV data values are correct."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_csv_report(sample_results, output_path)
            
            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                first_row = next(reader)
            
            assert first_row[0] == "192.168.1.1"
            assert first_row[1] == "22"
            assert first_row[3] == "open"
            assert first_row[4] == "ssh"
        finally:
            os.unlink(output_path)
    
    def test_empty_results(self):
        """Test CSV report with empty results."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_csv_report([], output_path)
            
            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)
            
            assert len(rows) == 1  # Only header
        finally:
            os.unlink(output_path)
    
    def test_handles_none_values(self):
        """Test CSV report handles None values."""
        results = [
            ScanResult(host="192.168.1.1", port=443, state="closed", 
                      service=None, banner=None)
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_csv_report(results, output_path)
            
            with open(output_path, 'r') as f:
                content = f.read()
            
            assert content is not None
        finally:
            os.unlink(output_path)


class TestGenerateXMLReport:
    """Tests for generate_xml_report function."""
    
    @pytest.fixture
    def sample_results(self):
        """Create sample scan results."""
        return [
            ScanResult(host="192.168.1.1", port=22, state="open", service="ssh"),
            ScanResult(host="192.168.1.1", port=80, state="open", service="http"),
        ]
    
    @pytest.fixture
    def sample_summary(self):
        """Create sample scan summary."""
        return {
            "total_ports": 100,
            "open_ports": 2,
        }
    
    def test_creates_valid_xml(self, sample_results):
        """Test XML report is valid XML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_xml_report(sample_results, output_path)
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            
            assert root.tag == "spectrescan_report"
        finally:
            os.unlink(output_path)
    
    def test_has_metadata(self, sample_results):
        """Test XML report has metadata."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_xml_report(sample_results, output_path)
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            metadata = root.find("metadata")
            
            assert metadata is not None
            assert metadata.find("tool").text == "SpectreScan"
            assert metadata.find("vendor").text == "BitSpectreLabs"
        finally:
            os.unlink(output_path)
    
    def test_has_results(self, sample_results):
        """Test XML report has results."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_xml_report(sample_results, output_path)
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            results = root.find("results")
            
            assert results is not None
            assert len(results.findall("result")) == 2
        finally:
            os.unlink(output_path)
    
    def test_result_structure(self, sample_results):
        """Test XML result structure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_xml_report(sample_results, output_path)
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            result = root.find("results/result")
            
            assert result.find("host") is not None
            assert result.find("port") is not None
            assert result.find("protocol") is not None
            assert result.find("state") is not None
            assert result.find("service") is not None
        finally:
            os.unlink(output_path)
    
    def test_with_summary(self, sample_results, sample_summary):
        """Test XML report with summary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_xml_report(sample_results, output_path, summary=sample_summary)
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            summary = root.find("summary")
            
            assert summary is not None
            assert summary.find("total_ports").text == "100"
            assert summary.find("open_ports").text == "2"
        finally:
            os.unlink(output_path)
    
    def test_empty_results(self):
        """Test XML report with empty results."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_xml_report([], output_path)
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            results = root.find("results")
            
            assert len(results.findall("result")) == 0
        finally:
            os.unlink(output_path)


class TestReportIntegration:
    """Integration tests for report generation."""
    
    @pytest.fixture
    def large_results(self):
        """Create large set of scan results."""
        results = []
        for i in range(100):
            results.append(ScanResult(
                host=f"192.168.1.{i % 255}",
                port=i + 1,
                state="open" if i % 3 == 0 else "closed",
                service=f"service_{i}" if i % 3 == 0 else None
            ))
        return results
    
    def test_large_json_report(self, large_results):
        """Test JSON report with large dataset."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_json_report(large_results, output_path)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert len(data["results"]) == 100
        finally:
            os.unlink(output_path)
    
    def test_large_csv_report(self, large_results):
        """Test CSV report with large dataset."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_csv_report(large_results, output_path)
            
            with open(output_path, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)
            
            assert len(rows) == 101  # Header + 100 results
        finally:
            os.unlink(output_path)
    
    def test_large_xml_report(self, large_results):
        """Test XML report with large dataset."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_path = Path(f.name)
        
        try:
            generate_xml_report(large_results, output_path)
            
            tree = ET.parse(output_path)
            root = tree.getroot()
            results = root.find("results")
            
            assert len(results.findall("result")) == 100
        finally:
            os.unlink(output_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
