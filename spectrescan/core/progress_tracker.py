"""
Real-time Progress Enhancement
ETA calculation, throughput stats, completion percentage, live updates.

Author: BitSpectreLabs
License: MIT
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class ProgressStats:
    """Real-time progress statistics."""
    total_items: int
    completed_items: int = 0
    start_time: float = field(default_factory=time.time)
    current_item: Optional[str] = None
    errors: int = 0
    
    @property
    def completion_percentage(self) -> float:
        """Calculate completion percentage."""
        if self.total_items == 0:
            return 0.0
        return (self.completed_items / self.total_items) * 100.0
    
    @property
    def elapsed_time(self) -> float:
        """Calculate elapsed time in seconds."""
        return time.time() - self.start_time
    
    @property
    def items_per_second(self) -> float:
        """Calculate throughput (items/second)."""
        if self.elapsed_time == 0:
            return 0.0
        return self.completed_items / self.elapsed_time
    
    @property
    def eta_seconds(self) -> Optional[float]:
        """Estimate time to completion in seconds."""
        if self.completed_items == 0 or self.items_per_second == 0:
            return None
        
        remaining = self.total_items - self.completed_items
        return remaining / self.items_per_second
    
    @property
    def eta_formatted(self) -> str:
        """Get formatted ETA string."""
        eta = self.eta_seconds
        if eta is None:
            return "calculating..."
        
        if eta < 60:
            return f"{int(eta)}s"
        elif eta < 3600:
            minutes = int(eta / 60)
            seconds = int(eta % 60)
            return f"{minutes}m {seconds}s"
        else:
            hours = int(eta / 3600)
            minutes = int((eta % 3600) / 60)
            return f"{hours}h {minutes}m"


class ProgressTracker:
    """
    Track and display real-time progress for scans.
    Provides ETA, throughput, and completion percentage.
    """
    
    def __init__(
        self,
        total_items: int,
        description: str = "Scanning",
        update_interval: float = 0.5,
        callback: Optional[Callable[[ProgressStats], None]] = None
    ):
        """
        Initialize progress tracker.
        
        Args:
            total_items: Total number of items to process
            description: Description of the operation
            update_interval: Update display interval in seconds
            callback: Optional callback for progress updates
        """
        self.stats = ProgressStats(total_items=total_items)
        self.description = description
        self.update_interval = update_interval
        self.callback = callback
        self.last_update = 0.0
        self.is_active = True
    
    def update(self, increment: int = 1, current_item: Optional[str] = None) -> None:
        """
        Update progress.
        
        Args:
            increment: Number of items completed
            current_item: Description of current item
        """
        self.stats.completed_items += increment
        if current_item:
            self.stats.current_item = current_item
        
        # Check if we should update display
        now = time.time()
        if now - self.last_update >= self.update_interval:
            self._display_progress()
            self.last_update = now
            
            # Call callback if provided
            if self.callback:
                self.callback(self.stats)
    
    def increment_errors(self) -> None:
        """Increment error count."""
        self.stats.errors += 1
    
    def _display_progress(self) -> None:
        """Display progress to console."""
        if not self.is_active:
            return
        
        # Build progress bar
        bar_width = 40
        filled = int(bar_width * self.stats.completion_percentage / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        # Build stats line
        stats_parts = [
            f"{self.stats.completion_percentage:.1f}%",
            f"{self.stats.completed_items}/{self.stats.total_items}",
            f"{self.stats.items_per_second:.1f} items/s",
            f"ETA: {self.stats.eta_formatted}"
        ]
        
        if self.stats.errors > 0:
            stats_parts.append(f"errors: {self.stats.errors}")
        
        stats = " | ".join(stats_parts)
        
        # Current item
        item_str = ""
        if self.stats.current_item:
            item_str = f" [{self.stats.current_item}]"
        
        # Print progress line (overwrite previous)
        progress_line = f"\r{self.description}: {bar} {stats}{item_str}"
        print(progress_line, end='', flush=True)
    
    def finish(self) -> None:
        """Finish progress tracking and display final stats."""
        self.is_active = False
        self._display_progress()
        print()  # New line
        
        # Print summary
        total_time = self.stats.elapsed_time
        avg_rate = self.stats.items_per_second
        
        print(f"\nCompleted in {self._format_duration(total_time)}")
        print(f"Average rate: {avg_rate:.2f} items/second")
        
        if self.stats.errors > 0:
            print(f"Errors encountered: {self.stats.errors}")
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = seconds % 60
            return f"{minutes}m {secs:.1f}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            secs = seconds % 60
            return f"{hours}h {minutes}m {secs:.0f}s"
    
    def get_summary(self) -> dict:
        """Get progress summary as dictionary."""
        return {
            "total": self.stats.total_items,
            "completed": self.stats.completed_items,
            "percentage": self.stats.completion_percentage,
            "elapsed_time": self.stats.elapsed_time,
            "items_per_second": self.stats.items_per_second,
            "eta_seconds": self.stats.eta_seconds,
            "errors": self.stats.errors
        }


class MultiProgressTracker:
    """
    Track multiple concurrent operations.
    Useful for scanning multiple hosts simultaneously.
    """
    
    def __init__(self):
        """Initialize multi-progress tracker."""
        self.trackers: dict[str, ProgressTracker] = {}
        self.start_time = time.time()
    
    def add_tracker(
        self,
        name: str,
        total_items: int,
        description: Optional[str] = None
    ) -> ProgressTracker:
        """
        Add a new progress tracker.
        
        Args:
            name: Unique name for tracker
            total_items: Total items to track
            description: Optional description
        
        Returns:
            ProgressTracker instance
        """
        desc = description or name
        tracker = ProgressTracker(total_items, desc)
        self.trackers[name] = tracker
        return tracker
    
    def get_tracker(self, name: str) -> Optional[ProgressTracker]:
        """Get tracker by name."""
        return self.trackers.get(name)
    
    def get_overall_stats(self) -> dict:
        """Get overall statistics for all trackers."""
        total_items = sum(t.stats.total_items for t in self.trackers.values())
        completed_items = sum(t.stats.completed_items for t in self.trackers.values())
        total_errors = sum(t.stats.errors for t in self.trackers.values())
        
        completion_pct = (completed_items / total_items * 100) if total_items > 0 else 0
        elapsed = time.time() - self.start_time
        rate = completed_items / elapsed if elapsed > 0 else 0
        
        return {
            "total_items": total_items,
            "completed_items": completed_items,
            "completion_percentage": completion_pct,
            "elapsed_time": elapsed,
            "overall_rate": rate,
            "total_errors": total_errors,
            "active_trackers": len(self.trackers)
        }
    
    def display_summary(self) -> None:
        """Display summary of all trackers."""
        print("\n" + "=" * 60)
        print("PROGRESS SUMMARY")
        print("=" * 60)
        
        for name, tracker in self.trackers.items():
            stats = tracker.stats
            print(f"\n{name}:")
            print(f"  Completed: {stats.completed_items}/{stats.total_items} ({stats.completion_percentage:.1f}%)")
            print(f"  Rate: {stats.items_per_second:.2f} items/s")
            print(f"  Errors: {stats.errors}")
        
        overall = self.get_overall_stats()
        print(f"\nOverall:")
        print(f"  Total completed: {overall['completed_items']}/{overall['total_items']}")
        print(f"  Completion: {overall['completion_percentage']:.1f}%")
        print(f"  Average rate: {overall['overall_rate']:.2f} items/s")
        print(f"  Total time: {overall['elapsed_time']:.2f}s")
        print(f"  Total errors: {overall['total_errors']}")


def create_progress_bar(
    total: int,
    current: int,
    width: int = 40,
    filled_char: str = "█",
    empty_char: str = "░"
) -> str:
    """
    Create a simple progress bar string.
    
    Args:
        total: Total items
        current: Current items completed
        width: Width of progress bar
        filled_char: Character for filled portion
        empty_char: Character for empty portion
    
    Returns:
        Progress bar string
    """
    if total == 0:
        return empty_char * width
    
    percentage = current / total
    filled = int(width * percentage)
    
    return filled_char * filled + empty_char * (width - filled)
