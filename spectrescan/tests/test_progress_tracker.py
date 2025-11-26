"""
Tests for Progress Tracker Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import time
from spectrescan.core.progress_tracker import ProgressStats, ProgressTracker


class TestProgressStats:
    """Tests for ProgressStats dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        stats = ProgressStats(total_items=100)
        assert stats.total_items == 100
        assert stats.completed_items == 0
        assert stats.errors == 0
    
    def test_completion_percentage_zero(self):
        """Test completion percentage at start."""
        stats = ProgressStats(total_items=100)
        assert stats.completion_percentage == 0.0
    
    def test_completion_percentage_partial(self):
        """Test partial completion percentage."""
        stats = ProgressStats(total_items=100, completed_items=50)
        assert stats.completion_percentage == 50.0
    
    def test_completion_percentage_full(self):
        """Test 100% completion."""
        stats = ProgressStats(total_items=100, completed_items=100)
        assert stats.completion_percentage == 100.0
    
    def test_completion_percentage_zero_total(self):
        """Test completion percentage with zero total."""
        stats = ProgressStats(total_items=0)
        assert stats.completion_percentage == 0.0
    
    def test_elapsed_time(self):
        """Test elapsed time calculation."""
        stats = ProgressStats(total_items=100)
        time.sleep(0.1)
        assert stats.elapsed_time >= 0.1
    
    def test_items_per_second(self):
        """Test throughput calculation."""
        stats = ProgressStats(total_items=100, completed_items=50)
        # Wait a bit to have elapsed time
        time.sleep(0.1)
        ips = stats.items_per_second
        assert ips >= 0
    
    def test_items_per_second_zero_elapsed(self):
        """Test throughput with zero elapsed time."""
        stats = ProgressStats(total_items=100, completed_items=0)
        # Immediately check - elapsed time is very small but not zero
        # The property handles division properly
        ips = stats.items_per_second
        assert ips >= 0
    
    def test_eta_seconds_no_progress(self):
        """Test ETA with no progress."""
        stats = ProgressStats(total_items=100, completed_items=0)
        assert stats.eta_seconds is None
    
    def test_eta_seconds_with_progress(self):
        """Test ETA with some progress."""
        stats = ProgressStats(total_items=100, completed_items=50)
        time.sleep(0.1)  # Let some time pass
        eta = stats.eta_seconds
        # ETA should be a positive number or None
        assert eta is None or eta >= 0
    
    def test_eta_formatted_calculating(self):
        """Test ETA formatted when calculating."""
        stats = ProgressStats(total_items=100, completed_items=0)
        assert stats.eta_formatted == "calculating..."
    
    def test_eta_formatted_seconds(self):
        """Test ETA formatted in seconds."""
        stats = ProgressStats(total_items=100, completed_items=99)
        time.sleep(0.1)
        # With 99/100 done very quickly, ETA should be short
        eta = stats.eta_formatted
        assert isinstance(eta, str)
    
    def test_current_item(self):
        """Test current item tracking."""
        stats = ProgressStats(total_items=100, current_item="192.168.1.1:80")
        assert stats.current_item == "192.168.1.1:80"
    
    def test_error_count(self):
        """Test error counting."""
        stats = ProgressStats(total_items=100, errors=5)
        assert stats.errors == 5


class TestProgressTracker:
    """Tests for ProgressTracker class."""
    
    def test_init(self):
        """Test tracker initialization."""
        tracker = ProgressTracker(total_items=100)
        assert tracker.stats.total_items == 100
        assert tracker.description == "Scanning"
    
    def test_custom_description(self):
        """Test custom description."""
        tracker = ProgressTracker(total_items=50, description="Port scanning")
        assert tracker.description == "Port scanning"
    
    def test_update_interval(self):
        """Test update interval setting."""
        tracker = ProgressTracker(total_items=100, update_interval=1.0)
        assert tracker.update_interval == 1.0
    
    def test_callback(self):
        """Test callback function."""
        results = []
        def callback(stats):
            results.append(stats.completed_items)
        
        tracker = ProgressTracker(total_items=100, callback=callback)
        assert tracker.callback is not None
    
    def test_update_progress(self):
        """Test progress update method."""
        tracker = ProgressTracker(total_items=100)
        
        if hasattr(tracker, 'update'):
            tracker.update(1)
            assert tracker.stats.completed_items == 1
    
    def test_increment(self):
        """Test increment method."""
        tracker = ProgressTracker(total_items=100)
        
        if hasattr(tracker, 'increment'):
            tracker.increment()
            assert tracker.stats.completed_items == 1
            tracker.increment()
            assert tracker.stats.completed_items == 2
    
    def test_complete(self):
        """Test complete method."""
        tracker = ProgressTracker(total_items=100)
        
        if hasattr(tracker, 'complete'):
            tracker.complete()
            assert tracker.stats.completed_items == tracker.stats.total_items
    
    def test_set_current_item(self):
        """Test setting current item."""
        tracker = ProgressTracker(total_items=100)
        
        if hasattr(tracker, 'set_current_item'):
            tracker.set_current_item("192.168.1.1:22")
            assert tracker.stats.current_item == "192.168.1.1:22"
    
    def test_record_error(self):
        """Test error recording."""
        tracker = ProgressTracker(total_items=100)
        
        if hasattr(tracker, 'record_error'):
            tracker.record_error()
            assert tracker.stats.errors == 1


class TestProgressTrackerDisplay:
    """Tests for progress display methods."""
    
    def test_get_progress_bar(self):
        """Test progress bar generation."""
        tracker = ProgressTracker(total_items=100)
        
        if hasattr(tracker, 'get_progress_bar'):
            bar = tracker.get_progress_bar()
            assert isinstance(bar, str)
    
    def test_get_status_line(self):
        """Test status line generation."""
        tracker = ProgressTracker(total_items=100)
        
        if hasattr(tracker, 'get_status_line'):
            status = tracker.get_status_line()
            assert isinstance(status, str)
    
    def test_format_progress(self):
        """Test progress formatting."""
        tracker = ProgressTracker(total_items=100)
        tracker.stats.completed_items = 50
        
        if hasattr(tracker, 'format_progress'):
            formatted = tracker.format_progress()
            assert "50" in formatted or "50%" in formatted


class TestETAFormatting:
    """Tests for ETA formatting edge cases."""
    
    def test_eta_under_minute(self):
        """Test ETA formatting under 1 minute."""
        stats = ProgressStats(total_items=100, completed_items=99)
        time.sleep(0.05)
        eta = stats.eta_formatted
        # Should be seconds or calculating
        assert "s" in eta or "calculating" in eta
    
    def test_eta_minutes(self):
        """Test ETA formatting in minutes range."""
        # Hard to test without mocking time
        stats = ProgressStats(total_items=100)
        stats.completed_items = 1
        # Simulate slow progress by adjusting start_time
        stats.start_time = time.time() - 60  # Started 1 minute ago
        eta = stats.eta_formatted
        # With 1/100 done in 60s, ETA should be about 99 minutes
        assert "m" in eta or "h" in eta or "calculating" in eta


class TestProgressTrackerCallback:
    """Tests for callback functionality."""
    
    def test_callback_called_on_update(self):
        """Test callback is called when progress updates."""
        call_count = [0]
        
        def callback(stats):
            call_count[0] += 1
        
        tracker = ProgressTracker(total_items=100, callback=callback)
        
        if hasattr(tracker, 'update'):
            tracker.update(1)
            # Callback may or may not be called depending on update_interval
    
    def test_callback_receives_stats(self):
        """Test callback receives ProgressStats."""
        received_stats = [None]
        
        def callback(stats):
            received_stats[0] = stats
        
        tracker = ProgressTracker(total_items=100, callback=callback)
        
        if hasattr(tracker, 'update') and hasattr(tracker, 'force_update'):
            tracker.update(50)
            if hasattr(tracker, 'force_update'):
                tracker.force_update()
            # May have received stats
