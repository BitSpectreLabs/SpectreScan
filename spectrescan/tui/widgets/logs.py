"""
Logs widget for TUI
by BitSpectreLabs
"""

from textual.widgets import RichLog
from textual.containers import Container
from datetime import datetime


class LogsWidget(RichLog):
    """Widget to display scan logs."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_lines = 1000
        self.auto_scroll = True
    
    def log_info(self, message: str) -> None:
        """
        Log info message.
        
        Args:
            message: Log message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.write(f"[dim]{timestamp}[/dim] [blue]INFO[/blue] {message}")
    
    def log_success(self, message: str) -> None:
        """
        Log success message.
        
        Args:
            message: Log message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.write(f"[dim]{timestamp}[/dim] [green]✓[/green] {message}")
    
    def log_error(self, message: str) -> None:
        """
        Log error message.
        
        Args:
            message: Log message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.write(f"[dim]{timestamp}[/dim] [red]ERROR[/red] {message}")
    
    def log_warning(self, message: str) -> None:
        """
        Log warning message.
        
        Args:
            message: Log message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.write(f"[dim]{timestamp}[/dim] [yellow]WARN[/yellow] {message}")
    
    def log_port(self, host: str, port: int, state: str, service: str = None) -> None:
        """
        Log port scan result.
        
        Args:
            host: Target host
            port: Port number
            state: Port state
            service: Service name
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        service_str = f" [{service}]" if service else ""
        
        if state == "open":
            self.write(f"[dim]{timestamp}[/dim] [green]✓[/green] {host}:{port} - {state}{service_str}")
        elif state == "closed":
            self.write(f"[dim]{timestamp}[/dim] [red]✗[/red] {host}:{port} - {state}")
        else:
            self.write(f"[dim]{timestamp}[/dim] [yellow]?[/yellow] {host}:{port} - {state}")
    
    def clear_logs(self) -> None:
        """Clear all logs."""
        self.clear()
