"""
SpectreScan TUI - Textual User Interface
by BitSpectreLabs
"""

import asyncio
from typing import Optional, List
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Input, Button, Static, TabbedContent, TabPane
from textual.binding import Binding
from textual.message import Message
from textual import work
from textual.worker import Worker, get_current_worker
from spectrescan.core.scanner import PortScanner
from spectrescan.core.presets import ScanPreset, get_preset_config
from spectrescan.core.utils import parse_ports, parse_targets_from_file, ScanResult
from spectrescan.core.history import HistoryManager
from pathlib import Path
from spectrescan.tui.widgets.results_table import ResultsTable
from spectrescan.tui.widgets.progress import ProgressWidget
from spectrescan.tui.widgets.logs import LogsWidget


# Custom messages for thread-safe UI updates
class ScanResultMessage(Message):
    """Message sent when a scan result is available."""
    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__()


class ScanCompleteMessage(Message):
    """Message sent when scan completes."""
    def __init__(self, summary: dict) -> None:
        self.summary = summary
        super().__init__()


class ScanErrorMessage(Message):
    """Message sent when scan has an error."""
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


LOGO = r"""
 ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
 ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
 ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
 ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
 ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
                                                            
  ███████╗ ██████╗ █████╗ ███╗   ██╗                      
  ██╔════╝██╔════╝██╔══██╗████╗  ██║                      
  ███████╗██║     ███████║██╔██╗ ██║                      
  ╚════██║██║     ██╔══██║██║╚██╗██║                      
  ███████║╚██████╗██║  ██║██║ ╚████║                      
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                      
                                                            
       Professional Port Scanner by BitSpectreLabs
"""


class SpectreScanTUI(App):
    """SpectreScan TUI application."""
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    #main-container {
        height: 100%;
        width: 100%;
        overflow: auto;
    }
    
    #logo {
        height: auto;
        width: 100%;
        content-align: center middle;
        color: $accent;
        margin: 1;
    }
    
    #input-container {
        height: auto;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }
    
    #scan-button {
        width: 20;
        margin-left: 1;
    }
    
    #stop-button {
        width: 20;
        margin-left: 1;
    }
    
    #import-button {
        width: 20;
        margin-left: 1;
    }
    
    #results-container {
        height: 1fr;
        min-height: 10;
    }
    
    TabbedContent {
        height: 1fr;
    }
    
    ContentSwitcher {
        height: 1fr;
    }
    
    TabPane {
        height: 1fr;
        padding: 0;
    }
    
    #results-tab {
        height: 1fr;
    }
    
    ResultsTable {
        height: 1fr;
        width: 100%;
    }
    
    DataTable {
        height: 1fr;
    }
    
    #logs-tab {
        height: 1fr;
    }
    
    LogsWidget {
        height: 1fr;
        width: 100%;
    }
    
    #stats-tab {
        height: 1fr;
    }
    
    LogsWidget {
        height: 100%;
        width: 100%;
    }
    
    #stats-display {
        height: 100%;
        width: 100%;
        padding: 2;
    }
    
    #progress {
        height: auto;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }
    
    #progress-label {
        margin-bottom: 1;
    }
    
    #progress-stats {
        margin-top: 1;
    }
    
    #status-bar {
        height: 3;
        background: $panel;
        padding: 1;
        border: solid $primary;
    }
    
    Footer {
        background: $panel;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("s", "start_scan", "Start Scan", show=True),
        Binding("x", "stop_scan", "Stop Scan", show=True),
        Binding("c", "clear", "Clear Results", show=True),
        Binding("d", "toggle_dark", "Toggle Theme", show=True),
        Binding("p", "open_profiles", "Profiles", show=True),
        Binding("h", "open_history", "History", show=True),
    ]
    
    def __init__(self, target: Optional[str] = None, ports: Optional[str] = None):
        super().__init__()
        self.title = "SpectreScan - Professional Port Scanner"
        self.sub_title = "by BitSpectreLabs"
        
        self.target = target or ""
        self.ports = ports or "1-1000"
        self.scanner: Optional[PortScanner] = None
        self.scanning = False
        self.scan_task = None
        self.current_target_index = 0
        self.total_targets = 0
        self._port_list: List[int] = []
        self._scan_config = None
        
        # Initialize history manager
        self.history_manager = HistoryManager()
    
    def compose(self) -> ComposeResult:
        """Compose TUI layout."""
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            # Input container
            with Horizontal(id="input-container"):
                yield Input(placeholder="Target (IP/hostname/CIDR)", value=self.target, id="target-input")
                yield Input(placeholder="Ports (e.g., 1-1000, 80,443)", value=self.ports, id="ports-input")
                yield Button("📁 Import", id="import-button", variant="primary")
                yield Button("Start Scan", id="scan-button", variant="success")
                yield Button("Stop", id="stop-button", variant="error")
            
            # Tabbed content area
            with TabbedContent(id="results-container"):
                with TabPane("Results", id="results-tab"):
                    yield ResultsTable(id="results-table")
                
                with TabPane("Logs", id="logs-tab"):
                    yield LogsWidget(id="logs")
                
                with TabPane("Stats", id="stats-tab"):
                    yield Static("Scan statistics will appear here", id="stats-display")
            
            # Progress and status
            yield ProgressWidget(id="progress")
            
            with Container(id="status-bar"):
                yield Static("Ready to scan", id="status-text")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Handle mount event."""
        # Ensure all widgets are visible and initialized
        try:
            self.logs.log_info("SpectreScan TUI initialized")
            self.logs.log_info("Press 's' to start scan, 'q' to quit")
            self.logs.log_info("Use Tab to switch between Results, Logs, and Stats")
            
            # Initialize results table
            self.results_table.zebra_stripes = True
            
            # Set initial progress
            self.progress.reset()
            
            # Focus on target input
            target_input = self.query_one("#target-input", Input)
            target_input.focus()
        except Exception as e:
            # Fallback if widgets not ready yet
            pass
    
    @property
    def logs(self) -> LogsWidget:
        """Get logs widget."""
        return self.query_one("#logs", LogsWidget)
    
    @property
    def results_table(self) -> ResultsTable:
        """Get results table."""
        return self.query_one("#results-table", ResultsTable)
    
    @property
    def progress(self) -> ProgressWidget:
        """Get progress widget."""
        return self.query_one("#progress", ProgressWidget)
    
    @property
    def status_text(self) -> Static:
        """Get status text widget."""
        return self.query_one("#status-text", Static)
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "scan-button":
            self.action_start_scan()
        elif event.button.id == "stop-button":
            self.action_stop_scan()
        elif event.button.id == "import-button":
            self.action_import_targets()
    
    def action_start_scan(self) -> None:
        """Start scan action."""
        if self.scanning:
            self.logs.log_warning("Scan already in progress")
            return
        
        # Get inputs
        target_input = self.query_one("#target-input", Input)
        ports_input = self.query_one("#ports-input", Input)
        
        self.target = target_input.value
        self.ports = ports_input.value
        
        if not self.target:
            self.logs.log_error("Please enter a target")
            return
        
        # Parse ports
        try:
            self._port_list = parse_ports(self.ports)
        except ValueError as e:
            self.logs.log_error(f"Invalid port specification: {e}")
            return
        
        # Start scan
        self.scanning = True
        self.status_text.update("[yellow]Scanning...[/yellow]")
        self.logs.log_info(f"Starting scan of {self.target}")
        
        # Setup progress
        self.progress.set_total(len(self._port_list))
        
        # Create scanner with quick preset
        config = get_preset_config(ScanPreset.QUICK)
        config.ports = self._port_list
        self.scanner = PortScanner(config)
        self._scan_config = config
        
        # Log that we're starting
        self.logs.log_info(f"Scanning {self.target} on {len(self._port_list)} ports...")
        
        # Run scan using Textual's worker system
        self._run_scan_worker()
    
    def action_stop_scan(self) -> None:
        """Stop scan action."""
        if not self.scanning:
            self.logs.log_warning("No scan in progress")
            return
        
        self.scanning = False
        # Cancel all workers
        self.workers.cancel_all()
        
        self.status_text.update("[red]Scan stopped[/red]")
        self.logs.log_warning("Scan stopped by user")
    
    def action_clear(self) -> None:
        """Clear results action."""
        self.results_table.clear_results()
        self.logs.clear_logs()
        self.progress.reset()
        self.status_text.update("Ready to scan")
        self.logs.log_info("Results cleared")
    
    def action_import_targets(self) -> None:
        """Import targets from file."""
        # For TUI, we'll log instructions since we can't use file dialog
        self.logs.log_info("To import targets:")
        self.logs.log_info("1. Create a file with one target per line")
        self.logs.log_info("2. Use CLI: spectrescan --target-file targets.txt")
        self.logs.log_info("3. Or enter comma-separated: 192.168.1.1,192.168.1.2")
    
    def action_open_profiles(self) -> None:
        """Open profile selection screen."""
        from spectrescan.tui.screens import ProfileSelectionScreen
        
        def on_profile_selected(profile):
            """Callback when profile is selected."""
            # Update input fields
            target_input = self.query_one("#target-input", Input)
            ports_input = self.query_one("#ports-input", Input)
            
            # Set ports from profile
            ports_input.value = ','.join(map(str, profile.ports))
            
            # Log profile load
            self.logs.log_success(f"Profile '{profile.name}' loaded!")
            self.logs.log_info(f"Scan type: {', '.join(profile.scan_types)}")
            self.logs.log_info(f"Ports: {len(profile.ports)} ports")
            self.logs.log_info(f"Threads: {profile.threads}, Timeout: {profile.timeout}s")
        
        self.push_screen(ProfileSelectionScreen(on_select=on_profile_selected))
    
    def action_open_history(self) -> None:
        """Open history browser screen."""
        from spectrescan.tui.screens import HistorySelectionScreen
        self.push_screen(HistorySelectionScreen())
    
    @work(thread=True, exclusive=True)
    def _run_scan_worker(self) -> None:
        """
        Run scan in a background thread using Textual's worker system.
        
        Uses post_message for thread-safe UI updates since this runs in a thread.
        post_message is explicitly documented as thread-safe in Textual.
        """
        worker = get_current_worker()
        
        def target_callback(current_target: str, idx: int, total: int):
            self.current_target_index = idx
            self.total_targets = total
        
        def callback(result: ScanResult):
            if worker.is_cancelled or not self.scanning:
                return
            if result.state == "open":
                # Use post_message which is thread-safe
                self.post_message(ScanResultMessage(result))
            # Update progress via thread-safe call
            self.call_from_thread(self.progress.update_progress, result.state)
        
        try:
            # Run the scan (blocking call in thread)
            self.scanner.scan(self.target, None, callback, target_callback)
            
            # Scan complete - update UI via thread-safe message
            if self.scanning and not worker.is_cancelled:
                summary = self.scanner.get_scan_summary()
                
                # Save to history
                try:
                    self.history_manager.add_entry(
                        target=self.target,
                        ports=self._port_list,
                        scan_type='tcp',
                        duration=summary.get('scan_duration_seconds', 0.0),
                        open_ports=summary.get('open_ports', 0),
                        closed_ports=summary.get('closed_ports', 0),
                        filtered_ports=summary.get('filtered_ports', 0),
                        config={
                            'threads': self._scan_config.threads,
                            'timeout': self._scan_config.timeout,
                            'preset': 'quick',
                        }
                    )
                except Exception:
                    pass
                
                # Use post_message which is thread-safe
                self.post_message(ScanCompleteMessage(summary))
        except Exception as e:
            self.post_message(ScanErrorMessage(str(e)))
        finally:
            self.scanning = False
    
    def on_scan_result_message(self, message: ScanResultMessage) -> None:
        """Handle scan result message (runs in main thread)."""
        result = message.result
        self.results_table.add_result(result)
        self.logs.log_port(result.host, result.port, result.state, result.service)
    
    def on_scan_complete_message(self, message: ScanCompleteMessage) -> None:
        """Handle scan complete message (runs in main thread)."""
        summary = message.summary
        self.status_text.update("[green]Scan complete![/green]")
        self.logs.log_info("Scan saved to history")
        
        if self.total_targets > 1:
            self.logs.log_success(
                f"Scan complete: {self.total_targets} targets scanned, {summary['open_ports']} open ports found in {summary['scan_duration']}"
            )
        else:
            self.logs.log_success(
                f"Scan complete: {summary['open_ports']} open ports found in {summary['scan_duration']}"
            )
        
        # Update stats
        stats_display = self.query_one("#stats-display", Static)
        stats_text = f"""
[bold]Scan Summary[/bold]

Target: {self.target}
Ports Scanned: {summary['total_ports']}
Open Ports: [green]{summary['open_ports']}[/green]
Closed Ports: {summary['closed_ports']}
Filtered Ports: {summary['filtered_ports']}
Duration: {summary['scan_duration']}
        """
        stats_display.update(stats_text)
        
        # Force refresh
        self.results_table.refresh()
        self.logs.refresh()
    
    def on_scan_error_message(self, message: ScanErrorMessage) -> None:
        """Handle scan error message (runs in main thread)."""
        self.logs.log_error(f"Scan error: {message.error}")
        self.status_text.update("[red]Scan error[/red]")
        self.logs.refresh()


def run_tui(target: Optional[str] = None, ports: Optional[str] = None):
    """
    Run the TUI application.
    
    Args:
        target: Optional initial target
        ports: Optional initial port range
    """
    app = SpectreScanTUI(target, ports)
    app.run()


if __name__ == "__main__":
    run_tui()
