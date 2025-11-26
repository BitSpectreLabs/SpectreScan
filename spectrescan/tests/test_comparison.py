"""
Tests for Scan Comparison Feature
by BitSpectreLabs
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime
from spectrescan.core.comparison import ScanComparer, ScanComparison, PortDifference
from spectrescan.core.history import HistoryManager
from spectrescan.core.utils import ScanResult


class TestPortDifference:
    """Test PortDifference dataclass."""
    
    def test_create_port_difference(self):
        """Test creating a port difference."""
        diff = PortDifference(
            port=80,
            protocol="tcp",
            old_state="closed",
            new_state="open",
            service_old=None,
            service_new="http"
        )
        
        assert diff.port == 80
        assert diff.protocol == "tcp"
        assert diff.old_state == "closed"
        assert diff.new_state == "open"
        assert diff.service_new == "http"


class TestScanComparison:
    """Test ScanComparison dataclass."""
    
    def test_create_scan_comparison(self):
        """Test creating a scan comparison."""
        comparison = ScanComparison(
            scan1_id="abc123",
            scan2_id="def456",
            scan1_target="192.168.1.1",
            scan2_target="192.168.1.1",
            scan1_timestamp=datetime.now().isoformat(),
            scan2_timestamp=datetime.now().isoformat(),
            newly_opened=[],
            newly_closed=[],
            newly_filtered=[],
            service_changed=[],
            total_changes=0,
            scan1_open_count=5,
            scan2_open_count=7,
            open_diff=2
        )
        
        assert comparison.scan1_id == "abc123"
        assert comparison.scan2_id == "def456"
        assert comparison.total_changes == 0
        assert comparison.open_diff == 2


class TestScanComparer:
    """Test ScanComparer class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for history."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def comparer(self, temp_dir):
        """Create ScanComparer with temp history."""
        comparer = ScanComparer()
        comparer.history_manager = HistoryManager(temp_dir)
        return comparer
    
    @pytest.fixture
    def sample_scans(self, comparer):
        """Create sample scan history entries."""
        # Add first scan
        entry1 = comparer.history_manager.add_entry(
            target="192.168.1.1",
            ports=[80, 443, 22],
            scan_type="tcp",
            duration=5.0,
            open_ports=2,
            closed_ports=1,
            filtered_ports=0,
            config={'threads': 50}
        )
        
        # Add second scan
        entry2 = comparer.history_manager.add_entry(
            target="192.168.1.1",
            ports=[80, 443, 22],
            scan_type="tcp",
            duration=5.5,
            open_ports=3,
            closed_ports=0,
            filtered_ports=0,
            config={'threads': 50}
        )
        
        return entry1, entry2
    
    def test_comparer_initialization(self, comparer):
        """Test ScanComparer initialization."""
        assert comparer.history_manager is not None
    
    def test_compare_nonexistent_scan(self, comparer):
        """Test comparing non-existent scans raises error."""
        with pytest.raises(ValueError, match="not found in history"):
            comparer.compare_scans("nonexistent1", "nonexistent2")
    
    def test_compare_different_targets(self, comparer):
        """Test comparing scans with different targets raises error."""
        # Add scans for different targets
        entry1 = comparer.history_manager.add_entry(
            target="192.168.1.1",
            ports=[80],
            scan_type="tcp",
            duration=1.0,
            open_ports=1,
            closed_ports=0,
            filtered_ports=0,
            config={}
        )
        
        entry2 = comparer.history_manager.add_entry(
            target="192.168.1.2",
            ports=[80],
            scan_type="tcp",
            duration=1.0,
            open_ports=1,
            closed_ports=0,
            filtered_ports=0,
            config={}
        )
        
        with pytest.raises(ValueError, match="different targets"):
            comparer.compare_scans(entry1.id, entry2.id)
    
    def test_compare_scans_basic(self, comparer, sample_scans):
        """Test basic scan comparison."""
        entry1, entry2 = sample_scans
        
        comparison = comparer.compare_scans(entry1.id, entry2.id)
        
        assert comparison.scan1_id == entry1.id
        assert comparison.scan2_id == entry2.id
        assert comparison.scan1_target == "192.168.1.1"
        assert comparison.scan2_target == "192.168.1.1"
        assert comparison.scan1_open_count == 2
        assert comparison.scan2_open_count == 3
        assert comparison.open_diff == 1
    
    def test_compare_scans_with_results(self, comparer, sample_scans):
        """Test comparison with provided results."""
        entry1, entry2 = sample_scans
        
        # Create sample results
        results1 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            ),
            ScanResult(
                host="192.168.1.1",
                port=443,
                state="closed",
                service=None,
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        results2 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            ),
            ScanResult(
                host="192.168.1.1",
                port=443,
                state="open",
                service="https",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        comparison = comparer.compare_scans(
            entry1.id,
            entry2.id,
            results1=results1,
            results2=results2
        )
        
        # Should detect port 443 newly opened
        assert len(comparison.newly_opened) == 1
        assert comparison.newly_opened[0].port == 443
        assert comparison.newly_opened[0].old_state == "closed"
        assert comparison.newly_opened[0].new_state == "open"
    
    def test_format_comparison_text(self, comparer):
        """Test formatting comparison as text."""
        comparison = ScanComparison(
            scan1_id="abc123",
            scan2_id="def456",
            scan1_target="192.168.1.1",
            scan2_target="192.168.1.1",
            scan1_timestamp="2025-01-01T12:00:00",
            scan2_timestamp="2025-01-01T13:00:00",
            newly_opened=[
                PortDifference(80, "tcp", "closed", "open", None, "http")
            ],
            newly_closed=[],
            newly_filtered=[],
            service_changed=[],
            total_changes=1,
            scan1_open_count=5,
            scan2_open_count=6,
            open_diff=1
        )
        
        text = comparer.format_comparison_text(comparison)
        
        assert "SCAN COMPARISON REPORT" in text
        assert "abc123" in text
        assert "def456" in text
        assert "192.168.1.1" in text
        assert "NEWLY OPENED PORTS" in text
        assert "80/tcp" in text
    
    def test_compare_by_target_insufficient_scans(self, comparer):
        """Test comparing by target with insufficient scans."""
        # Add only one scan
        comparer.history_manager.add_entry(
            target="192.168.1.1",
            ports=[80],
            scan_type="tcp",
            duration=1.0,
            open_ports=1,
            closed_ports=0,
            filtered_ports=0,
            config={}
        )
        
        result = comparer.compare_by_target("192.168.1.1")
        assert result is None
    
    def test_compare_by_target_success(self, comparer, sample_scans):
        """Test comparing by target successfully."""
        comparison = comparer.compare_by_target("192.168.1.1")
        
        assert comparison is not None
        assert comparison.scan1_target == "192.168.1.1"
        assert comparison.scan2_target == "192.168.1.1"
    
    def test_detect_newly_closed_ports(self, comparer, sample_scans):
        """Test detecting newly closed ports."""
        entry1, entry2 = sample_scans
        
        results1 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        results2 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="closed",
                service=None,
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        comparison = comparer.compare_scans(
            entry1.id,
            entry2.id,
            results1=results1,
            results2=results2
        )
        
        assert len(comparison.newly_closed) == 1
        assert comparison.newly_closed[0].port == 80
    
    def test_detect_filtered_ports(self, comparer, sample_scans):
        """Test detecting newly filtered ports."""
        entry1, entry2 = sample_scans
        
        results1 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        results2 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="filtered",
                service=None,
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        comparison = comparer.compare_scans(
            entry1.id,
            entry2.id,
            results1=results1,
            results2=results2
        )
        
        assert len(comparison.newly_filtered) == 1
        assert comparison.newly_filtered[0].port == 80
    
    def test_detect_service_changes(self, comparer, sample_scans):
        """Test detecting service changes."""
        entry1, entry2 = sample_scans
        
        results1 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        results2 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="https",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        comparison = comparer.compare_scans(
            entry1.id,
            entry2.id,
            results1=results1,
            results2=results2
        )
        
        assert len(comparison.service_changed) == 1
        assert comparison.service_changed[0].port == 80
        assert comparison.service_changed[0].service_old == "http"
        assert comparison.service_changed[0].service_new == "https"
    
    def test_no_changes_detected(self, comparer, sample_scans):
        """Test when no changes are detected."""
        entry1, entry2 = sample_scans
        
        # Same results for both scans
        results1 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        results2 = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        comparison = comparer.compare_scans(
            entry1.id,
            entry2.id,
            results1=results1,
            results2=results2
        )
        
        assert comparison.total_changes == 0
        assert len(comparison.newly_opened) == 0
        assert len(comparison.newly_closed) == 0
        assert len(comparison.service_changed) == 0
    
    def test_format_text_no_changes(self, comparer):
        """Test formatting text when no changes detected."""
        comparison = ScanComparison(
            scan1_id="abc123",
            scan2_id="def456",
            scan1_target="192.168.1.1",
            scan2_target="192.168.1.1",
            scan1_timestamp="2025-01-01T12:00:00",
            scan2_timestamp="2025-01-01T13:00:00",
            newly_opened=[],
            newly_closed=[],
            newly_filtered=[],
            service_changed=[],
            total_changes=0,
            scan1_open_count=5,
            scan2_open_count=5,
            open_diff=0
        )
        
        text = comparer.format_comparison_text(comparison)
        
        assert "No changes detected" in text
