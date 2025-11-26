"""
SpectreScan TUI - Textual User Interface
by BitSpectreLabs
"""

import asyncio
from typing import Optional
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Input, Button, Static, TabbedContent, TabPane
from textual.binding import Binding
from spectrescan.core.scanner import PortScanner
from spectrescan.core.presets import ScanPreset, get_preset_config
from spectrescan.core.utils import parse_ports, parse_targets_from_file, ScanResult
from pathlib import Path
from spectrescan.tui.widgets.results_table import ResultsTable
from spectrescan.tui.widgets.progress import ProgressWidget
from spectrescan.tui.widgets.logs import LogsWidget


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
    
    #results-container {
        height: 1fr;
    }
    
    ResultsTable {
        height: 1fr;
    }
    
    LogsWidget {
        height: 10;
        border: solid $primary;
    }
    
    #status-bar {
        height: 3;
        background: $panel;
        padding: 1;
        border: solid $primary;
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
    
    def compose(self) -> ComposeResult:
        """Compose TUI layout."""
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            # Logo
            yield Static(LOGO, id="logo")
            
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
        self.logs.log_info("SpectreScan TUI initialized")
        self.logs.log_info("Press 's' to start scan, 'q' to quit")
    
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
        
        # Start scan
        self.scanning = True
        self.status_text.update("[yellow]Scanning...[/yellow]")
        self.logs.log_info(f"Starting scan of {self.target}")
        
        # Run scan in background
        self.scan_task = asyncio.create_task(self._run_scan())
    
    def action_stop_scan(self) -> None:
        """Stop scan action."""
        if not self.scanning:
            self.logs.log_warning("No scan in progress")
            return
        
        self.scanning = False
        if self.scan_task:
            self.scan_task.cancel()
        
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
    
    async def _run_scan(self) -> None:
        """Run scan in background."""
        try:
            # Parse ports
            try:
                port_list = parse_ports(self.ports)
            except ValueError as e:
                self.logs.log_error(f"Invalid port specification: {e}")
                self.scanning = False
                self.status_text.update("[red]Error[/red]")
                return
            
            # Setup progress
            self.progress.set_total(len(port_list))
            
            # Create scanner with quick preset
            config = get_preset_config(ScanPreset.QUICK)
            config.ports = port_list
            self.scanner = PortScanner(config)
            
            # Target progress callback
            def target_callback(current_target: str, idx: int, total: int):
                self.current_target_index = idx
                self.total_targets = total
                if total > 1:
                    # Use call_from_thread to safely update UI from thread
                    self.call_from_thread(self.logs.log_info, f"Scanning target {idx}/{total}: {current_target}")
                    self.call_from_thread(self.status_text.update, f"[yellow]Scanning target {idx}/{total}...[/yellow]")
            
            # Run scan with callback
            def callback(result: ScanResult):
                if not self.scanning:
                    return
                
                # Use call_from_thread to safely update UI from thread
                # Update progress
                self.call_from_thread(self.progress.update_progress, result.state)
                
                # Add to table if open
                if result.state == "open":
                    self.call_from_thread(self.results_table.add_result, result)
                
                # Log result
                self.call_from_thread(self.logs.log_port, result.host, result.port, result.state, result.service)
            
            # Run scan in thread pool
            await asyncio.get_event_loop().run_in_executor(
                None,
                self.scanner.scan,
                self.target,
                None,
                callback,
                target_callback
            )
            
            # Scan complete
            if self.scanning:
                summary = self.scanner.get_scan_summary()
                self.status_text.update("[green]Scan complete![/green]")
                
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
            
            self.scanning = False
            
        except asyncio.CancelledError:
            self.logs.log_warning("Scan cancelled")
            self.scanning = False
        except Exception as e:
            self.logs.log_error(f"Scan error: {e}")
            self.status_text.update("[red]Scan error[/red]")
            self.scanning = False


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
