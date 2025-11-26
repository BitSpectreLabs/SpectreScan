"""
Results table widget for TUI
by BitSpectreLabs
"""

from textual.widgets import DataTable
from textual.app import ComposeResult
from spectrescan.core.utils import ScanResult


class ResultsTable(DataTable):
    """Widget to display scan results in a table."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        
    def on_mount(self) -> None:
        """Initialize table columns."""
        self.add_columns("Host", "Port", "Protocol", "State", "Service", "Banner")
        self.zebra_stripes = True
    
    def add_result(self, result: ScanResult) -> None:
        """
        Add scan result to table.
        
        Args:
            result: ScanResult object
        """
        service = result.service or "unknown"
        banner = result.banner[:40] + "..." if result.banner and len(result.banner) > 40 else (result.banner or "")
        
        # Color code based on state
        state_str = result.state
        if result.state == "open":
            state_str = f"[green]{result.state}[/green]"
        elif result.state == "closed":
            state_str = f"[red]{result.state}[/red]"
        else:
            state_str = f"[yellow]{result.state}[/yellow]"
        
        self.add_row(
            result.host,
            str(result.port),
            result.protocol,
            state_str,
            service,
            banner
        )
    
    def clear_results(self) -> None:
        """Clear all results from table."""
        self.clear()
        # Columns are already added in on_mount, just need to clear rows
    
    def filter_open_only(self) -> None:
        """Filter to show only open ports."""
        # This would require storing results and re-rendering
        # For now, this is a placeholder
        pass
