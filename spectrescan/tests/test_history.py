"""
Tests for Scan History Management
by BitSpectreLabs
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from spectrescan.core.history import ScanHistoryEntry, HistoryManager


class TestScanHistoryEntry:
    """Test ScanHistoryEntry dataclass."""
    
    def test_create_entry(self):
        """Test creating a history entry."""
        entry = ScanHistoryEntry(
            id="test123",
            target="192.168.1.1",
            ports=[80, 443, 22],
            scan_type="tcp",
            timestamp=datetime.now().isoformat(),
            duration=5.25,
            open_ports=2,
            closed_ports=1,
            filtered_ports=0,
            total_ports=3,
            config={'threads': 50}
        )
        
        assert entry.id == "test123"
        assert entry.target == "192.168.1.1"
        assert len(entry.ports) == 3
        assert entry.open_ports == 2
        assert entry.duration == 5.25
    
    def test_entry_to_dict(self):
        """Test converting entry to dictionary."""
        entry = ScanHistoryEntry(
            id="test123",
            target="example.com",
            ports=[80, 443],
            scan_type="tcp",
            timestamp=datetime.now().isoformat(),
            duration=3.5,
            open_ports=2,
            closed_ports=0,
            filtered_ports=0,
            total_ports=2,
            config={'threads': 50},
            results_file="/path/to/results.json"
        )
        
        data = entry.to_dict()
        
        assert isinstance(data, dict)
        assert data['id'] == "test123"
        assert data['target'] == "example.com"
        assert data['results_file'] == "/path/to/results.json"
    
    def test_entry_from_dict(self):
        """Test creating entry from dictionary."""
        data = {
            'id': "test123",
            'target': "192.168.1.1",
            'ports': [80, 443],
            'scan_type': "tcp",
            'timestamp': datetime.now().isoformat(),
            'duration': 2.5,
            'open_ports': 1,
            'closed_ports': 1,
            'filtered_ports': 0,
            'total_ports': 2,
            'config': {'threads': 50},
            'results_file': None
        }
        
        entry = ScanHistoryEntry.from_dict(data)
        
        assert entry.id == "test123"
        assert entry.target == "192.168.1.1"
        assert entry.open_ports == 1


class TestHistoryManager:
    """Test HistoryManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for history."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create HistoryManager with temp directory."""
        return HistoryManager(temp_dir)
    
    def test_manager_initialization(self, temp_dir):
        """Test HistoryManager initialization."""
        manager = HistoryManager(temp_dir)
        
        assert manager.history_dir == temp_dir
        assert manager.history_file.exists()
    
    def test_add_entry(self, manager):
        """Test adding a history entry."""
        entry = manager.add_entry(
            target="192.168.1.1",
            ports=[80, 443, 22],
            scan_type="tcp",
            duration=5.5,
            open_ports=2,
            closed_ports=1,
            filtered_ports=0,
            config={'threads': 50}
        )
        
        assert entry.id is not None
        assert entry.target == "192.168.1.1"
        assert entry.total_ports == 3
        assert entry.timestamp is not None
    
    def test_add_entry_with_results_file(self, manager):
        """Test adding entry with results file path."""
        entry = manager.add_entry(
            target="example.com",
            ports=[80, 443],
            scan_type="syn",
            duration=3.0,
            open_ports=2,
            closed_ports=0,
            filtered_ports=0,
            config={'threads': 100},
            results_file="/path/to/scan_results.json"
        )
        
        assert entry.results_file == "/path/to/scan_results.json"
    
    def test_get_entry(self, manager):
        """Test getting a history entry by ID."""
        entry = manager.add_entry(
            target="192.168.1.1",
            ports=[80],
            scan_type="tcp",
            duration=1.0,
            open_ports=1,
            closed_ports=0,
            filtered_ports=0,
            config={}
        )
        
        retrieved = manager.get_entry(entry.id)
        
        assert retrieved is not None
        assert retrieved.id == entry.id
        assert retrieved.target == entry.target
    
    def test_get_nonexistent_entry(self, manager):
        """Test getting non-existent entry returns None."""
        result = manager.get_entry("nonexistent123")
        assert result is None
    
    def test_list_entries(self, manager):
        """Test listing history entries."""
        # Add multiple entries
        manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.2", [443], "syn", 2.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.3", [22], "tcp", 1.5, 1, 0, 0, {})
        
        entries = manager.list_entries()
        
        assert len(entries) == 3
        # Most recent should be first
        assert entries[0].target == "192.168.1.3"
    
    def test_list_entries_with_limit(self, manager):
        """Test listing entries with limit."""
        for i in range(5):
            manager.add_entry(f"192.168.1.{i}", [80], "tcp", 1.0, 1, 0, 0, {})
        
        entries = manager.list_entries(limit=3)
        assert len(entries) == 3
    
    def test_list_entries_with_target_filter(self, manager):
        """Test listing entries with target filter."""
        manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        manager.add_entry("example.com", [443], "tcp", 2.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.2", [22], "tcp", 1.5, 1, 0, 0, {})
        
        entries = manager.list_entries(target_filter="192.168")
        
        assert len(entries) == 2
        assert all("192.168" in e.target for e in entries)
    
    def test_list_entries_with_scan_type_filter(self, manager):
        """Test listing entries with scan type filter."""
        manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.2", [443], "syn", 2.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.3", [22], "tcp", 1.5, 1, 0, 0, {})
        
        entries = manager.list_entries(scan_type_filter="tcp")
        
        assert len(entries) == 2
        assert all(e.scan_type == "tcp" for e in entries)
    
    def test_delete_entry(self, manager):
        """Test deleting a history entry."""
        entry = manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        
        result = manager.delete_entry(entry.id)
        
        assert result is True
        assert manager.get_entry(entry.id) is None
    
    def test_delete_nonexistent_entry(self, manager):
        """Test deleting non-existent entry returns False."""
        result = manager.delete_entry("nonexistent123")
        assert result is False
    
    def test_clear_history(self, manager):
        """Test clearing all history."""
        # Add some entries
        manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.2", [443], "tcp", 2.0, 1, 0, 0, {})
        
        manager.clear_history()
        
        entries = manager.list_entries()
        assert len(entries) == 0
    
    def test_search_history_by_target(self, manager):
        """Test searching history by target."""
        manager.add_entry("example.com", [80], "tcp", 1.0, 1, 0, 0, {})
        manager.add_entry("test.com", [443], "tcp", 2.0, 1, 0, 0, {})
        manager.add_entry("example.org", [22], "tcp", 1.5, 1, 0, 0, {})
        
        results = manager.search_history("example")
        
        assert len(results) == 2
        assert all("example" in e.target for e in results)
    
    def test_search_history_case_insensitive(self, manager):
        """Test that search is case insensitive."""
        manager.add_entry("Example.com", [80], "tcp", 1.0, 1, 0, 0, {})
        
        results = manager.search_history("EXAMPLE")
        assert len(results) == 1
    
    def test_search_history_in_config(self, manager):
        """Test searching in config field."""
        manager.add_entry(
            "192.168.1.1", [80], "tcp", 1.0, 1, 0, 0,
            {'threads': 50, 'timeout': 1.0}
        )
        manager.add_entry(
            "192.168.1.2", [443], "tcp", 2.0, 1, 0, 0,
            {'threads': 100, 'timeout': 2.0}
        )
        
        results = manager.search_history("threads", search_target=False, search_config=True)
        assert len(results) == 2
    
    def test_get_statistics_empty(self, manager):
        """Test getting statistics with no history."""
        stats = manager.get_statistics()
        
        assert stats['total_scans'] == 0
        assert stats['total_ports_scanned'] == 0
        assert stats['total_open_ports'] == 0
        assert stats['total_duration'] == 0
        assert stats['scan_types'] == {}
        assert stats['most_scanned_target'] is None
    
    def test_get_statistics(self, manager):
        """Test getting statistics."""
        # Add multiple entries
        manager.add_entry("192.168.1.1", [80, 443, 22], "tcp", 5.0, 2, 1, 0, {})
        manager.add_entry("192.168.1.1", [80, 443], "syn", 3.0, 1, 1, 0, {})
        manager.add_entry("example.com", [80], "tcp", 2.0, 1, 0, 0, {})
        
        stats = manager.get_statistics()
        
        assert stats['total_scans'] == 3
        assert stats['total_ports_scanned'] == 6  # 3 + 2 + 1
        assert stats['total_open_ports'] == 4  # 2 + 1 + 1
        assert stats['total_duration'] == 10.0
        assert stats['scan_types'] == {'tcp': 2, 'syn': 1}
        assert stats['most_scanned_target'] == "192.168.1.1"
    
    def test_generate_unique_ids(self, manager):
        """Test that generated IDs are unique."""
        entry1 = manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        entry2 = manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        
        assert entry1.id != entry2.id
    
    def test_persistence(self, temp_dir):
        """Test that history persists across manager instances."""
        # Create manager and add entry
        manager1 = HistoryManager(temp_dir)
        entry = manager1.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        
        # Create new manager with same directory
        manager2 = HistoryManager(temp_dir)
        retrieved = manager2.get_entry(entry.id)
        
        assert retrieved is not None
        assert retrieved.id == entry.id
    
    def test_history_ordering(self, manager):
        """Test that history maintains chronological order."""
        entries = []
        for i in range(5):
            entry = manager.add_entry(
                f"192.168.1.{i}", [80], "tcp", 1.0, 1, 0, 0, {}
            )
            entries.append(entry)
        
        listed = manager.list_entries()
        
        # Should be in reverse chronological order
        assert listed[0].id == entries[-1].id
        assert listed[-1].id == entries[0].id
    
    def test_combined_filters(self, manager):
        """Test combining multiple filters."""
        manager.add_entry("192.168.1.1", [80], "tcp", 1.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.2", [443], "syn", 2.0, 1, 0, 0, {})
        manager.add_entry("192.168.1.3", [22], "tcp", 1.5, 1, 0, 0, {})
        manager.add_entry("example.com", [80], "tcp", 2.5, 1, 0, 0, {})
        
        entries = manager.list_entries(
            limit=2,
            target_filter="192.168",
            scan_type_filter="tcp"
        )
        
        assert len(entries) == 2
        assert all("192.168" in e.target for e in entries)
        assert all(e.scan_type == "tcp" for e in entries)
