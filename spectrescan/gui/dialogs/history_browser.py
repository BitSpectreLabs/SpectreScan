"""
GUI History Browser Dialog
by BitSpectreLabs
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
from typing import Optional
from spectrescan.core.history import HistoryManager, ScanHistoryEntry


class HistoryBrowserDialog:
    """Scan history browser dialog."""
    
    def __init__(self, parent: tk.Tk, on_compare_callback=None):
        """
        Initialize history browser.
        
        Args:
            parent: Parent window
            on_compare_callback: Callback for scan comparison
        """
        self.parent = parent
        self.on_compare_callback = on_compare_callback
        self.manager = HistoryManager()
        self.selected_for_compare = []
        
        # Create dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Scan History Browser")
        self.dialog.geometry("1200x700")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Colors
        self.colors = {
            'bg': '#000000',
            'surface': '#0A0A0A',
            'border': '#1A1A1A',
            'text_primary': '#FFFFFF',
            'text_secondary': '#888888',
            'accent': '#0070F3',
            'success': '#0DDA83',
            'error': '#E00',
            'warning': '#F5A623',
        }
        
        self.dialog.configure(bg=self.colors['bg'])
        
        self._create_widgets()
        self._refresh_list()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (1200 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (700 // 2)
        self.dialog.geometry(f"1200x700+{x}+{y}")
    
    def _create_widgets(self):
        """Create dialog widgets."""
        # Top frame with title and filters
        top_frame = tk.Frame(self.dialog, bg=self.colors['bg'])
        top_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        # Title
        title = tk.Label(
            top_frame,
            text="Scan History",
            font=("Segoe UI", 18, "bold"),
            fg=self.colors['text_primary'],
            bg=self.colors['bg']
        )
        title.pack(side=tk.LEFT)
        
        # Filter frame
        filter_frame = tk.Frame(top_frame, bg=self.colors['bg'])
        filter_frame.pack(side=tk.RIGHT)
        
        # Search
        tk.Label(filter_frame, text="Search:", fg=self.colors['text_secondary'], bg=self.colors['bg'], font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var, font=("Segoe UI", 10), bg='#1A1A1A', fg=self.colors['text_primary'], relief=tk.FLAT, width=20)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind("<Return>", lambda e: self._search())
        
        self._create_button(filter_frame, "🔍 Search", self._search).pack(side=tk.LEFT, padx=5)
        self._create_button(filter_frame, "🔄 Refresh", self._refresh_list).pack(side=tk.LEFT, padx=5)
        self._create_button(filter_frame, "📊 Stats", self._show_stats).pack(side=tk.LEFT, padx=5)
        
        # List frame
        list_frame = tk.Frame(self.dialog, bg=self.colors['surface'], highlightbackground=self.colors['border'], highlightthickness=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Treeview
        columns = ("id", "target", "scan_type", "timestamp", "duration", "total_ports", "open_ports", "closed_ports", "filtered_ports")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20, selectmode=tk.EXTENDED)
        
        # Configure columns
        self.tree.heading("id", text="Scan ID")
        self.tree.heading("target", text="Target")
        self.tree.heading("scan_type", text="Type")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("duration", text="Duration")
        self.tree.heading("total_ports", text="Total")
        self.tree.heading("open_ports", text="Open")
        self.tree.heading("closed_ports", text="Closed")
        self.tree.heading("filtered_ports", text="Filtered")
        
        self.tree.column("id", width=100)
        self.tree.column("target", width=180)
        self.tree.column("scan_type", width=80, anchor=tk.CENTER)
        self.tree.column("timestamp", width=150)
        self.tree.column("duration", width=80, anchor=tk.CENTER)
        self.tree.column("total_ports", width=60, anchor=tk.CENTER)
        self.tree.column("open_ports", width=60, anchor=tk.CENTER)
        self.tree.column("closed_ports", width=60, anchor=tk.CENTER)
        self.tree.column("filtered_ports", width=60, anchor=tk.CENTER)
        
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                       background=self.colors['surface'],
                       foreground=self.colors['text_primary'],
                       fieldbackground=self.colors['surface'],
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background=self.colors['border'],
                       foreground=self.colors['text_primary'],
                       borderwidth=1)
        style.map("Treeview", background=[("selected", self.colors['accent'])])
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click
        self.tree.bind("<Double-1>", lambda e: self._view_details())
        
        # Action buttons frame
        action_frame = tk.Frame(self.dialog, bg=self.colors['bg'])
        action_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self._create_button(action_frame, "👁️ View", self._view_details).pack(side=tk.LEFT, padx=5)
        self._create_button(action_frame, "⚖️ Compare", self._compare_scans, self.colors['warning']).pack(side=tk.LEFT, padx=5)
        self._create_button(action_frame, "🗑️ Delete", self._delete_entry, self.colors['error']).pack(side=tk.LEFT, padx=5)
        self._create_button(action_frame, "🧹 Clear All", self._clear_all, self.colors['error']).pack(side=tk.LEFT, padx=5)
        
        close_btn = self._create_button(action_frame, "Close", self.dialog.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
    
    def _create_button(self, parent, text: str, command, bg: Optional[str] = None):
        """Create styled button."""
        if bg is None:
            bg = self.colors['accent']
        
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            font=("Segoe UI", 10),
            fg=self.colors['text_primary'],
            bg=bg,
            activebackground=self.colors['accent'],
            activeforeground=self.colors['text_primary'],
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2"
        )
        return btn
    
    def _refresh_list(self, entries=None):
        """Refresh history list."""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load entries
        if entries is None:
            entries = self.manager.list_entries(limit=100)
        
        for entry in entries:
            # Format timestamp
            try:
                dt = datetime.fromisoformat(entry.timestamp)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                timestamp = entry.timestamp[:19]
            
            # Insert row
            self.tree.insert("", tk.END, values=(
                entry.id[:12],
                entry.target[:30],
                entry.scan_type,
                timestamp,
                f"{entry.duration:.1f}s",
                entry.total_ports,
                entry.open_ports,
                entry.closed_ports,
                entry.filtered_ports
            ), tags=(entry.id,))  # Store full ID in tags
    
    def _search(self):
        """Search history."""
        query = self.search_var.get().strip()
        if not query:
            self._refresh_list()
            return
        
        results = self.manager.search_history(query, search_target=True, search_config=False)
        self._refresh_list(results)
    
    def _get_selected_entries(self) -> list:
        """Get selected entry IDs."""
        selection = self.tree.selection()
        if not selection:
            return []
        
        ids = []
        for sel in selection:
            tags = self.tree.item(sel)['tags']
            if tags:
                ids.append(tags[0])  # Full ID stored in first tag
        return ids
    
    def _view_details(self):
        """View entry details."""
        ids = self._get_selected_entries()
        if not ids:
            messagebox.showwarning("No Selection", "Please select a scan to view.")
            return
        
        scan_id = ids[0]
        entry = self.manager.get_entry(scan_id)
        
        if entry:
            HistoryDetailDialog(self.dialog, entry)
        else:
            messagebox.showerror("Error", "Scan not found")
    
    def _compare_scans(self):
        """Compare selected scans."""
        ids = self._get_selected_entries()
        
        if len(ids) != 2:
            messagebox.showwarning("Invalid Selection", "Please select exactly 2 scans to compare.")
            return
        
        entry1 = self.manager.get_entry(ids[0])
        entry2 = self.manager.get_entry(ids[1])
        
        if entry1 and entry2:
            if self.on_compare_callback:
                self.on_compare_callback(entry1, entry2)
            else:
                ScanComparisonDialog(self.dialog, entry1, entry2)
        else:
            messagebox.showerror("Error", "Failed to load scans for comparison")
    
    def _delete_entry(self):
        """Delete selected entries."""
        ids = self._get_selected_entries()
        if not ids:
            messagebox.showwarning("No Selection", "Please select scans to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Delete {len(ids)} scan(s)?"):
            for scan_id in ids:
                self.manager.delete_entry(scan_id)
            
            messagebox.showinfo("Success", f"{len(ids)} scan(s) deleted")
            self._refresh_list()
    
    def _clear_all(self):
        """Clear all history."""
        if messagebox.askyesno("Confirm Clear", "Delete ALL scan history? This cannot be undone!"):
            self.manager.clear_history()
            messagebox.showinfo("Success", "All history cleared")
            self._refresh_list()
    
    def _show_stats(self):
        """Show statistics."""
        stats = self.manager.get_statistics()
        HistoryStatsDialog(self.dialog, stats)


class HistoryDetailDialog:
    """History entry details dialog."""
    
    def __init__(self, parent: tk.Toplevel, entry: ScanHistoryEntry):
        """Initialize detail dialog."""
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Scan Details: {entry.id[:12]}")
        self.dialog.geometry("700x600")
        self.dialog.transient(parent)
        
        # Colors
        bg = '#000000'
        surface = '#0A0A0A'
        text = '#FFFFFF'
        secondary = '#888888'
        success = '#0DDA83'
        error = '#E00'
        
        self.dialog.configure(bg=bg)
        
        # Content frame with scrollbar
        canvas = tk.Canvas(self.dialog, bg=bg, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.dialog, orient=tk.VERTICAL, command=canvas.yview)
        content = tk.Frame(canvas, bg=surface, padx=30, pady=30)
        
        content.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=content, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Title
        title = tk.Label(content, text=f"Scan: {entry.id}", font=("Segoe UI", 16, "bold"), fg=text, bg=surface)
        title.pack(anchor=tk.W, pady=(0, 20))
        
        # Details
        details = [
            ("Target", entry.target),
            ("Scan Type", entry.scan_type.upper()),
            ("Timestamp", entry.timestamp[:19]),
            ("Duration", f"{entry.duration:.2f} seconds"),
            ("Total Ports", str(entry.total_ports)),
            ("Open Ports", str(entry.open_ports), success),
            ("Closed Ports", str(entry.closed_ports)),
            ("Filtered Ports", str(entry.filtered_ports)),
        ]
        
        for item in details:
            label = item[0]
            value = item[1]
            color = item[2] if len(item) > 2 else text
            
            row = tk.Frame(content, bg=surface)
            row.pack(fill=tk.X, pady=5)
            
            lbl = tk.Label(row, text=f"{label}:", font=("Segoe UI", 10, "bold"), fg=secondary, bg=surface, width=15, anchor=tk.W)
            lbl.pack(side=tk.LEFT)
            
            val = tk.Label(row, text=value, font=("Segoe UI", 10), fg=color, bg=surface, anchor=tk.W)
            val.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Ports scanned
        if entry.ports:
            ports_label = tk.Label(content, text="Ports Scanned:", font=("Segoe UI", 11, "bold"), fg=secondary, bg=surface, anchor=tk.W)
            ports_label.pack(fill=tk.X, pady=(15, 5))
            
            ports_text = scrolledtext.ScrolledText(content, height=5, font=("Consolas", 9), bg='#1A1A1A', fg=text, relief=tk.FLAT, wrap=tk.WORD)
            ports_text.pack(fill=tk.X, pady=5)
            ports_text.insert(1.0, ', '.join(map(str, entry.ports[:100])))
            if len(entry.ports) > 100:
                ports_text.insert(tk.END, f"\n... and {len(entry.ports) - 100} more")
            ports_text.configure(state=tk.DISABLED)
        
        # Configuration
        config_label = tk.Label(content, text="Configuration:", font=("Segoe UI", 11, "bold"), fg=secondary, bg=surface, anchor=tk.W)
        config_label.pack(fill=tk.X, pady=(15, 5))
        
        config_text = scrolledtext.ScrolledText(content, height=8, font=("Consolas", 9), bg='#1A1A1A', fg=text, relief=tk.FLAT)
        config_text.pack(fill=tk.X, pady=5)
        
        import json
        config_text.insert(1.0, json.dumps(entry.config, indent=2))
        config_text.configure(state=tk.DISABLED)
        
        # Results file
        if entry.results_file:
            file_label = tk.Label(content, text="Results File:", font=("Segoe UI", 10, "bold"), fg=secondary, bg=surface, anchor=tk.W)
            file_label.pack(fill=tk.X, pady=(10, 2))
            
            file_val = tk.Label(content, text=entry.results_file, font=("Segoe UI", 9), fg='#0070F3', bg=surface, anchor=tk.W, cursor="hand2")
            file_val.pack(fill=tk.X)
        
        # Close button
        close_btn = tk.Button(
            self.dialog,
            text="Close",
            command=self.dialog.destroy,
            font=("Segoe UI", 10),
            fg=text,
            bg='#0070F3',
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2"
        )
        close_btn.pack(pady=10)


class HistoryStatsDialog:
    """History statistics dialog."""
    
    def __init__(self, parent: tk.Toplevel, stats: dict):
        """Initialize stats dialog."""
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Scan History Statistics")
        self.dialog.geometry("600x500")
        self.dialog.transient(parent)
        
        # Colors
        bg = '#000000'
        surface = '#0A0A0A'
        text = '#FFFFFF'
        secondary = '#888888'
        accent = '#0070F3'
        success = '#0DDA83'
        
        self.dialog.configure(bg=bg)
        
        # Content frame
        content = tk.Frame(self.dialog, bg=surface, padx=40, pady=40)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(content, text="📊 Scan Statistics", font=("Segoe UI", 18, "bold"), fg=text, bg=surface)
        title.pack(anchor=tk.W, pady=(0, 30))
        
        # Stats
        stat_items = [
            ("Total Scans Performed", stats['total_scans'], accent),
            ("Total Ports Scanned", f"{stats['total_ports_scanned']:,}", accent),
            ("Total Open Ports Found", f"{stats['total_open_ports']:,}", success),
            ("Total Scan Time", f"{stats['total_duration']:.2f} seconds", accent),
        ]
        
        for label, value, color in stat_items:
            row = tk.Frame(content, bg=surface)
            row.pack(fill=tk.X, pady=10)
            
            lbl = tk.Label(row, text=label, font=("Segoe UI", 11), fg=secondary, bg=surface, anchor=tk.W)
            lbl.pack(side=tk.LEFT)
            
            val = tk.Label(row, text=str(value), font=("Segoe UI", 14, "bold"), fg=color, bg=surface, anchor=tk.E)
            val.pack(side=tk.RIGHT)
        
        # Scan types
        if stats['scan_types']:
            types_label = tk.Label(content, text="Scan Type Distribution:", font=("Segoe UI", 12, "bold"), fg=secondary, bg=surface, anchor=tk.W)
            types_label.pack(fill=tk.X, pady=(20, 10))
            
            for scan_type, count in stats['scan_types'].items():
                row = tk.Frame(content, bg=surface)
                row.pack(fill=tk.X, pady=5)
                
                lbl = tk.Label(row, text=f"  • {scan_type.upper()}", font=("Segoe UI", 10), fg=text, bg=surface, anchor=tk.W)
                lbl.pack(side=tk.LEFT)
                
                val = tk.Label(row, text=str(count), font=("Segoe UI", 10, "bold"), fg=accent, bg=surface, anchor=tk.E)
                val.pack(side=tk.RIGHT)
        
        # Most scanned target
        if stats['most_scanned_target']:
            most_label = tk.Label(content, text="Most Scanned Target:", font=("Segoe UI", 11, "bold"), fg=secondary, bg=surface, anchor=tk.W)
            most_label.pack(fill=tk.X, pady=(20, 5))
            
            most_val = tk.Label(content, text=stats['most_scanned_target'], font=("Segoe UI", 12), fg=success, bg=surface, anchor=tk.W)
            most_val.pack(fill=tk.X)
        
        # Close button
        close_btn = tk.Button(
            self.dialog,
            text="Close",
            command=self.dialog.destroy,
            font=("Segoe UI", 10),
            fg=text,
            bg=accent,
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2"
        )
        close_btn.pack(pady=(20, 0))


class ScanComparisonDialog:
    """Scan comparison dialog."""
    
    def __init__(self, parent: tk.Toplevel, entry1: ScanHistoryEntry, entry2: ScanHistoryEntry):
        """Initialize comparison dialog."""
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Scan Comparison")
        self.dialog.geometry("900x700")
        self.dialog.transient(parent)
        
        # Colors
        bg = '#000000'
        surface = '#0A0A0A'
        text = '#FFFFFF'
        secondary = '#888888'
        accent = '#0070F3'
        success = '#0DDA83'
        error = '#E00'
        warning = '#F5A623'
        
        self.dialog.configure(bg=bg)
        
        # Content frame with scrollbar
        canvas = tk.Canvas(self.dialog, bg=bg, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.dialog, orient=tk.VERTICAL, command=canvas.yview)
        content = tk.Frame(canvas, bg=surface, padx=30, pady=30)
        
        content.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=content, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Title
        title = tk.Label(content, text="⚖️ Scan Comparison", font=("Segoe UI", 18, "bold"), fg=text, bg=surface)
        title.pack(anchor=tk.W, pady=(0, 20))
        
        # Comparison frame
        comp_frame = tk.Frame(content, bg=surface)
        comp_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column (Scan 1)
        left_col = tk.Frame(comp_frame, bg=surface)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self._add_scan_column(left_col, entry1, "Scan 1", text, secondary, accent, success, error)
        
        # Right column (Scan 2)
        right_col = tk.Frame(comp_frame, bg=surface)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        self._add_scan_column(right_col, entry2, "Scan 2", text, secondary, accent, success, error)
        
        # Differences summary
        diff_label = tk.Label(content, text="Differences:", font=("Segoe UI", 14, "bold"), fg=secondary, bg=surface, anchor=tk.W)
        diff_label.pack(fill=tk.X, pady=(20, 10))
        
        # Calculate differences
        open_diff = entry2.open_ports - entry1.open_ports
        closed_diff = entry2.closed_ports - entry1.closed_ports
        duration_diff = entry2.duration - entry1.duration
        
        diffs = [
            ("Open Ports", open_diff, "increase" if open_diff > 0 else "decrease" if open_diff < 0 else "same"),
            ("Closed Ports", closed_diff, "increase" if closed_diff > 0 else "decrease" if closed_diff < 0 else "same"),
            ("Scan Duration", f"{duration_diff:+.2f}s", "slower" if duration_diff > 0 else "faster" if duration_diff < 0 else "same"),
        ]
        
        for label, value, status in diffs:
            row = tk.Frame(content, bg=surface)
            row.pack(fill=tk.X, pady=5)
            
            lbl = tk.Label(row, text=f"{label}:", font=("Segoe UI", 10), fg=secondary, bg=surface, width=15, anchor=tk.W)
            lbl.pack(side=tk.LEFT)
            
            if status == "same":
                color = secondary
                icon = "="
            elif status in ["increase", "slower"]:
                color = warning
                icon = "▲"
            else:
                color = success
                icon = "▼"
            
            val_text = f"{icon} {value}"
            val = tk.Label(row, text=val_text, font=("Segoe UI", 10, "bold"), fg=color, bg=surface, anchor=tk.W)
            val.pack(side=tk.LEFT)
        
        # Close button
        close_btn = tk.Button(
            self.dialog,
            text="Close",
            command=self.dialog.destroy,
            font=("Segoe UI", 10),
            fg=text,
            bg=accent,
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2"
        )
        close_btn.pack(pady=(20, 0))
    
    def _add_scan_column(self, parent, entry: ScanHistoryEntry, title: str, text, secondary, accent, success, error):
        """Add scan information column."""
        # Column title
        col_title = tk.Label(parent, text=title, font=("Segoe UI", 14, "bold"), fg=accent, bg='#0A0A0A', anchor=tk.W)
        col_title.pack(fill=tk.X, pady=(0, 15))
        
        # Details
        details = [
            ("ID", entry.id[:12]),
            ("Target", entry.target),
            ("Type", entry.scan_type.upper()),
            ("Time", entry.timestamp[:19]),
            ("Duration", f"{entry.duration:.2f}s"),
            ("Total Ports", str(entry.total_ports)),
            ("Open", str(entry.open_ports), success),
            ("Closed", str(entry.closed_ports)),
            ("Filtered", str(entry.filtered_ports)),
        ]
        
        for item in details:
            label = item[0]
            value = item[1]
            color = item[2] if len(item) > 2 else text
            
            row = tk.Frame(parent, bg='#0A0A0A')
            row.pack(fill=tk.X, pady=3)
            
            lbl = tk.Label(row, text=f"{label}:", font=("Segoe UI", 9), fg=secondary, bg='#0A0A0A', width=10, anchor=tk.W)
            lbl.pack(side=tk.LEFT)
            
            val = tk.Label(row, text=value, font=("Segoe UI", 9), fg=color, bg='#0A0A0A', anchor=tk.W)
            val.pack(side=tk.LEFT, fill=tk.X, expand=True)
