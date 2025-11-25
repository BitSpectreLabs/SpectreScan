"""
Progress widget for TUI
by BitSpectreLabs
"""

from textual.widgets import ProgressBar, Static
from textual.containers import Container
from textual.app import ComposeResult


class ProgressWidget(Container):
    """Widget to display scan progress."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total_ports = 0
        self.scanned_ports = 0
        self.open_ports = 0
        self.closed_ports = 0
        self.filtered_ports = 0
    
    def compose(self) -> ComposeResult:
        """Compose progress widget."""
        yield Static("Scan Progress:", id="progress-label")
        yield ProgressBar(total=100, show_eta=True, id="progress-bar")
        yield Static("", id="progress-stats")
    
    def set_total(self, total: int) -> None:
        """
        Set total number of ports to scan.
        
        Args:
            total: Total port count
        """
        self.total_ports = total
        self.scanned_ports = 0
        progress_bar = self.query_one("#progress-bar", ProgressBar)
        progress_bar.update(total=total)
    
    def update_progress(self, state: str) -> None:
        """
        Update progress with scan result.
        
        Args:
            state: Port state (open/closed/filtered)
        """
        self.scanned_ports += 1
        
        if state == "open":
            self.open_ports += 1
        elif state == "closed":
            self.closed_ports += 1
        else:
            self.filtered_ports += 1
        
        # Update progress bar
        progress_bar = self.query_one("#progress-bar", ProgressBar)
        progress_bar.update(progress=self.scanned_ports)
        
        # Update stats
        percentage = (self.scanned_ports / self.total_ports * 100) if self.total_ports > 0 else 0
        stats_text = (
            f"Progress: {self.scanned_ports}/{self.total_ports} ({percentage:.1f}%) | "
            f"[green]Open: {self.open_ports}[/green] | "
            f"Closed: {self.closed_ports} | "
            f"[yellow]Filtered: {self.filtered_ports}[/yellow]"
        )
        
        stats = self.query_one("#progress-stats", Static)
        stats.update(stats_text)
    
    def reset(self) -> None:
        """Reset progress counters."""
        self.scanned_ports = 0
        self.open_ports = 0
        self.closed_ports = 0
        self.filtered_ports = 0
        
        progress_bar = self.query_one("#progress-bar", ProgressBar)
        progress_bar.update(progress=0)
        
        stats = self.query_one("#progress-stats", Static)
        stats.update("")
