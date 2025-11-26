"""
Results table widget for TUI
by BitSpectreLabs
"""

from textual.widgets import DataTable
from textual.app import ComposeResult
from spectrescan.core.utils import ScanResult
from rich.text import Text


class ResultsTable(DataTable):
    """Widget to display scan results in a table."""
    
    DEFAULT_CSS = """
    ResultsTable {
        height: 100%;
        width: 100%;
    }
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.show_header = True
        self._results_count = 0
        self._columns_added = False
        
    def on_mount(self) -> None:
        """Initialize table columns."""
        if not self._columns_added:
            self.add_columns("Host", "Port", "Protocol", "State", "Service", "Banner")
            self._columns_added = True
            self.refresh()
    
    def add_result(self, result: ScanResult) -> None:
        """
        Add scan result to table.
        
        Args:
            result: ScanResult object
        """
        service = result.service or "unknown"
        banner = result.banner[:40] + "..." if result.banner and len(result.banner) > 40 else (result.banner or "")
        
        # Color code based on state using Rich Text for proper rendering
        if result.state == "open":
            state_text = Text(result.state, style="green bold")
        elif result.state == "closed":
            state_text = Text(result.state, style="red")
        else:
            state_text = Text(result.state, style="yellow")
        
        self._results_count += 1
        self.add_row(
            result.host,
            str(result.port),
            result.protocol,
            state_text,
            service,
            banner
        )
        # Force refresh and scroll to show new content
        self.refresh()
        # Move cursor to last row to ensure visibility
        if self.row_count > 0:
            self.move_cursor(row=self.row_count - 1)
    
    def clear_results(self) -> None:
        """Clear all results from table."""
        self.clear()
        self._results_count = 0
        self._columns_added = False
        # Re-add columns after clearing
        self.add_columns("Host", "Port", "Protocol", "State", "Service", "Banner")
        self._columns_added = True
        self.refresh()
    
    @property
    def results_count(self) -> int:
        """Get the number of results in the table."""
        return self._results_count
    
    def filter_open_only(self) -> None:
        """Filter to show only open ports."""
        # This would require storing results and re-rendering
        # For now, this is a placeholder
        pass
