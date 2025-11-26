"""
TUI Profile Selection Screen
by BitSpectreLabs
"""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Static, Button, DataTable, Label
from textual.binding import Binding
from spectrescan.core.profiles import ProfileManager, ScanProfile
from typing import Optional, Callable


class ProfileSelectionScreen(Screen):
    """Profile selection screen for TUI."""
    
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Close"),
        Binding("enter", "select_profile", "Select"),
        Binding("d", "delete_profile", "Delete"),
        Binding("n", "new_profile", "New"),
    ]
    
    CSS = """
    ProfileSelectionScreen {
        align: center middle;
    }
    
    #dialog {
        width: 90;
        height: 30;
        border: solid $accent;
        background: $surface;
    }
    
    #title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        background: $accent;
        color: $text;
        text-style: bold;
    }
    
    #content {
        width: 100%;
        height: 1fr;
        padding: 1;
    }
    
    #profile-table {
        height: 1fr;
        border: solid $primary;
    }
    
    #buttons {
        dock: bottom;
        width: 100%;
        height: 3;
        padding: 0 1;
    }
    
    Button {
        margin: 0 1;
    }
    """
    
    def __init__(self, on_select: Optional[Callable[[ScanProfile], None]] = None):
        """
        Initialize profile selection screen.
        
        Args:
            on_select: Callback when profile is selected
        """
        super().__init__()
        self.manager = ProfileManager()
        self.on_select = on_select
        self.selected_profile = None
    
    def compose(self) -> ComposeResult:
        """Compose the UI."""
        with Container(id="dialog"):
            yield Static("📋 Select Profile", id="title")
            
            with Vertical(id="content"):
                # Profile table
                table = DataTable(id="profile-table")
                table.cursor_type = "row"
                table.zebra_stripes = True
                yield table
                
                # Buttons
                with Horizontal(id="buttons"):
                    yield Button("✅ Select", variant="success", id="btn-select")
                    yield Button("➕ New", variant="primary", id="btn-new")
                    yield Button("🗑️ Delete", variant="error", id="btn-delete")
                    yield Button("❌ Cancel", id="btn-cancel")
    
    def on_mount(self) -> None:
        """Setup table when mounted."""
        table = self.query_one(DataTable)
        
        # Add columns
        table.add_columns("Name", "Description", "Ports", "Type", "Created")
        
        # Load profiles
        self._refresh_table()
    
    def _refresh_table(self):
        """Refresh profile table."""
        table = self.query_one(DataTable)
        table.clear()
        
        profiles = self.manager.list_profiles()
        
        for name in profiles:
            try:
                profile = self.manager.load_profile(name)
                
                # Format data
                ports_text = f"{len(profile.ports)} ports"
                scan_types = ", ".join(profile.scan_types)
                created = profile.created_at[:10] if profile.created_at else "Unknown"
                
                table.add_row(
                    profile.name,
                    profile.description[:30],
                    ports_text,
                    scan_types,
                    created
                )
            except Exception as e:
                self.notify(f"Error loading profile {name}: {e}", severity="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id
        
        if button_id == "btn-select":
            self.action_select_profile()
        elif button_id == "btn-new":
            self.action_new_profile()
        elif button_id == "btn-delete":
            self.action_delete_profile()
        elif button_id == "btn-cancel":
            self.app.pop_screen()
    
    def action_select_profile(self) -> None:
        """Select highlighted profile."""
        table = self.query_one(DataTable)
        
        if table.cursor_row is None or table.cursor_row < 0:
            self.notify("No profile selected", severity="warning")
            return
        
        # Get profile name from table
        row_key = table.cursor_row
        try:
            cells = table.get_row_at(row_key)
            profile_name = str(cells[0])
            
            profile = self.manager.load_profile(profile_name)
            
            if self.on_select:
                self.on_select(profile)
            
            self.notify(f"Profile '{profile_name}' loaded!", severity="information")
            self.app.pop_screen()
            
        except Exception as e:
            self.notify(f"Error loading profile: {e}", severity="error")
    
    def action_delete_profile(self) -> None:
        """Delete highlighted profile."""
        table = self.query_one(DataTable)
        
        if table.cursor_row is None or table.cursor_row < 0:
            self.notify("No profile selected", severity="warning")
            return
        
        # Get profile name
        try:
            cells = table.get_row_at(table.cursor_row)
            profile_name = str(cells[0])
            
            self.manager.delete_profile(profile_name)
            self.notify(f"Profile '{profile_name}' deleted", severity="information")
            self._refresh_table()
            
        except Exception as e:
            self.notify(f"Error deleting profile: {e}", severity="error")
    
    def action_new_profile(self) -> None:
        """Create new profile (opens CLI instructions)."""
        message = (
            "To create a new profile:\n\n"
            "1. Exit TUI\n"
            "2. Run: spectrescan profile create\n"
            "3. Or edit ~/.spectrescan/profiles/ manually"
        )
        self.notify(message, severity="information", timeout=10)


class HistorySelectionScreen(Screen):
    """History selection screen for TUI."""
    
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Close"),
        Binding("enter", "view_details", "View"),
        Binding("d", "delete_entry", "Delete"),
        Binding("c", "compare_scans", "Compare"),
        Binding("s", "show_stats", "Stats"),
    ]
    
    CSS = """
    HistorySelectionScreen {
        align: center middle;
    }
    
    #dialog {
        width: 100;
        height: 35;
        border: solid $accent;
        background: $surface;
    }
    
    #title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        background: $accent;
        color: $text;
        text-style: bold;
    }
    
    #content {
        width: 100%;
        height: 1fr;
        padding: 1;
    }
    
    #history-table {
        height: 1fr;
        border: solid $primary;
    }
    
    #buttons {
        dock: bottom;
        width: 100%;
        height: 3;
        padding: 0 1;
    }
    
    Button {
        margin: 0 1;
    }
    """
    
    def __init__(self):
        """Initialize history selection screen."""
        super().__init__()
        from spectrescan.core.history import HistoryManager
        self.manager = HistoryManager()
        self.selected_entries = []
    
    def compose(self) -> ComposeResult:
        """Compose the UI."""
        with Container(id="dialog"):
            yield Static("📚 Scan History", id="title")
            
            with Vertical(id="content"):
                # History table
                table = DataTable(id="history-table", cursor_type="row", zebra_stripes=True)
                yield table
                
                # Buttons
                with Horizontal(id="buttons"):
                    yield Button("👁️ View", variant="primary", id="btn-view")
                    yield Button("⚖️ Compare", variant="warning", id="btn-compare")
                    yield Button("📊 Stats", variant="success", id="btn-stats")
                    yield Button("🗑️ Delete", variant="error", id="btn-delete")
                    yield Button("❌ Close", id="btn-close")
    
    def on_mount(self) -> None:
        """Setup table when mounted."""
        table = self.query_one(DataTable)
        
        # Add columns
        table.add_columns("ID", "Target", "Type", "Time", "Open", "Total", "Duration")
        
        # Load history
        self._refresh_table()
    
    def _refresh_table(self):
        """Refresh history table."""
        table = self.query_one(DataTable)
        table.clear()
        
        entries = self.manager.list_entries(limit=50)
        
        for entry in entries:
            # Format timestamp
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(entry.timestamp)
                timestamp = dt.strftime("%Y-%m-%d %H:%M")
            except:
                timestamp = entry.timestamp[:16]
            
            table.add_row(
                entry.id[:8],
                entry.target[:20],
                entry.scan_type,
                timestamp,
                str(entry.open_ports),
                str(entry.total_ports),
                f"{entry.duration:.1f}s",
                key=entry.id  # Store full ID as key
            )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id
        
        if button_id == "btn-view":
            self.action_view_details()
        elif button_id == "btn-compare":
            self.action_compare_scans()
        elif button_id == "btn-stats":
            self.action_show_stats()
        elif button_id == "btn-delete":
            self.action_delete_entry()
        elif button_id == "btn-close":
            self.app.pop_screen()
    
    def action_view_details(self) -> None:
        """View entry details."""
        table = self.query_one(DataTable)
        
        if table.cursor_row is None:
            self.notify("No entry selected", severity="warning")
            return
        
        row_key = list(table.rows.keys())[table.cursor_row]
        entry = self.manager.get_entry(row_key)
        
        if entry:
            # Show details in notification
            details = (
                f"Target: {entry.target}\n"
                f"Type: {entry.scan_type}\n"
                f"Open: {entry.open_ports}/{entry.total_ports}\n"
                f"Duration: {entry.duration:.2f}s"
            )
            self.notify(details, title=f"Scan {entry.id[:8]}", timeout=10)
        else:
            self.notify("Entry not found", severity="error")
    
    def action_compare_scans(self) -> None:
        """Compare two scans."""
        self.notify(
            "Select 2 scans and press 'c' to compare\n"
            "(Multi-select not yet implemented in TUI)",
            severity="information"
        )
    
    def action_show_stats(self) -> None:
        """Show statistics."""
        stats = self.manager.get_statistics()
        
        message = (
            f"Total Scans: {stats['total_scans']}\n"
            f"Ports Scanned: {stats['total_ports_scanned']:,}\n"
            f"Open Ports: {stats['total_open_ports']:,}\n"
            f"Total Time: {stats['total_duration']:.2f}s\n"
            f"Most Scanned: {stats['most_scanned_target'] or 'N/A'}"
        )
        self.notify(message, title="📊 Statistics", timeout=15)
    
    def action_delete_entry(self) -> None:
        """Delete entry."""
        table = self.query_one(DataTable)
        
        if table.cursor_row is None:
            self.notify("No entry selected", severity="warning")
            return
        
        row_key = list(table.rows.keys())[table.cursor_row]
        
        if self.manager.delete_entry(row_key):
            self.notify(f"Scan {row_key[:8]} deleted", severity="information")
            self._refresh_table()
        else:
            self.notify("Failed to delete entry", severity="error")
