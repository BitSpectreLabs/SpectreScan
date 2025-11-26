"""
SpectreScan GUI - Tkinter Graphical User Interface
by BitSpectreLabs
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
from typing import Optional, List
from pathlib import Path
from spectrescan.core.scanner import PortScanner
from spectrescan.core.presets import ScanPreset, get_preset_config
from spectrescan.core.utils import parse_ports, parse_targets_from_file, ScanResult
from spectrescan.reports import (
    generate_json_report, generate_csv_report,
    generate_xml_report
)
from spectrescan.reports.html_report import generate_html_report


class SpectreScanGUI:
    """SpectreScan GUI Application."""
    
    def __init__(self, root: tk.Tk):
        """
        Initialize GUI.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("SpectreScan - Professional Port Scanner")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Vercel-inspired color scheme
        self.colors = {
            'bg': '#000000',           # Pure black background
            'surface': '#0A0A0A',      # Card/surface background
            'border': '#1A1A1A',       # Subtle borders
            'text_primary': '#FFFFFF',  # Primary text
            'text_secondary': '#888888', # Secondary text
            'text_tertiary': '#666666',  # Tertiary text
            'accent': '#0070F3',       # Vercel blue
            'accent_hover': '#0761D1', # Darker blue for hover
            'success': '#0DDA83',      # Success green
            'error': '#E00',           # Error red
            'warning': '#F5A623',      # Warning orange
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Variables
        self.target_var = tk.StringVar()
        self.ports_var = tk.StringVar(value="1-1000")
        self.scan_type_var = tk.StringVar(value="tcp")
        self.preset_var = tk.StringVar(value="quick")
        self.threads_var = tk.IntVar(value=100)
        self.timeout_var = tk.DoubleVar(value=2.0)
        
        self.scanner: Optional[PortScanner] = None
        self.scanning = False
        self.scan_thread: Optional[threading.Thread] = None
        self.results: List[ScanResult] = []
        self.current_target_index = 0
        self.total_targets = 0
        self.target_list: List[str] = []
        
        # Setup UI
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup UI components."""
        # Header with logo and title
        header_frame = tk.Frame(self.root, bg=self.colors['bg'], height=80)
        header_frame.pack(fill=tk.X, padx=30, pady=(20, 10))
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="SpectreScan",
            font=("Inter", 28, "bold"),
            bg=self.colors['bg'],
            fg=self.colors['text_primary']
        ).pack(side=tk.LEFT, anchor=tk.W)
        
        tk.Label(
            header_frame,
            text="Professional Network Scanner",
            font=("Inter", 11),
            bg=self.colors['bg'],
            fg=self.colors['text_secondary']
        ).pack(side=tk.LEFT, anchor=tk.W, padx=(15, 0))
        
        # Main container with padding
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 20))
        
        # Left panel - Configuration (fixed width)
        left_panel = tk.Frame(main_container, bg=self.colors['surface'], width=400)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left_panel.pack_propagate(False)
        
        # Scrollable config area
        config_scroll_area = tk.Frame(left_panel, bg=self.colors['surface'])
        config_scroll_area.pack(fill=tk.BOTH, expand=True)
        
        # Fixed button area at bottom
        button_fixed_area = tk.Frame(left_panel, bg=self.colors['surface'])
        button_fixed_area.pack(fill=tk.X, side=tk.BOTTOM, padx=20, pady=20)
        
        self._setup_config_panel(config_scroll_area, button_fixed_area)
        
        # Right panel - Results (expandable)
        right_panel = tk.Frame(main_container, bg=self.colors['surface'])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self._setup_results_panel(right_panel)
        
        # Bottom status bar
        self._setup_status_panel()
    
    def _setup_config_panel(self, parent: tk.Frame, button_area: tk.Frame):
        """Setup configuration panel with Vercel-inspired design."""
        # Scrollable content
        canvas = tk.Canvas(parent, bg=self.colors['surface'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['surface'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=360)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        canvas.pack(side="left", fill="both", expand=True, padx=20, pady=(20, 0))
        scrollbar.pack(side="right", fill="y", padx=(0, 5), pady=(20, 0))
        
        # Section: Target Configuration
        self._create_section_header(scrollable_frame, "Target Configuration")
        
        self._create_modern_entry(scrollable_frame, "Target", self.target_var, "192.168.1.1 or 10.0.0.0/24")
        
        # Import targets button
        import_frame = tk.Frame(scrollable_frame, bg=self.colors['surface'])
        import_frame.pack(fill=tk.X, pady=(0, 12))
        
        tk.Button(
            import_frame,
            text="📁 Import Targets from File",
            command=self._import_targets,
            bg=self.colors['border'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            relief=tk.FLAT,
            cursor="hand2",
            pady=8
        ).pack(fill=tk.X)
        
        self._create_modern_entry(scrollable_frame, "Ports", self.ports_var, "1-1000 or 80,443,8080")
        
        # Profile and History buttons
        profile_hist_frame = tk.Frame(scrollable_frame, bg=self.colors['surface'])
        profile_hist_frame.pack(fill=tk.X, pady=(0, 12))
        
        tk.Button(
            profile_hist_frame,
            text="📋 Manage Profiles",
            command=self._open_profile_manager,
            bg=self.colors['border'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            relief=tk.FLAT,
            cursor="hand2",
            pady=8
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        tk.Button(
            profile_hist_frame,
            text="📚 Scan History",
            command=self._open_history_browser,
            bg=self.colors['border'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            relief=tk.FLAT,
            cursor="hand2",
            pady=8
        ).pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))
        
        # Section: Scan Settings
        self._create_section_header(scrollable_frame, "Scan Settings")
        
        self._create_modern_combobox(scrollable_frame, "Preset", self.preset_var, 
            ["quick", "top-ports", "full", "stealth", "safe", "aggressive"], self._on_preset_change)
        
        self._create_modern_combobox(scrollable_frame, "Scan Type", self.scan_type_var, 
            ["tcp", "syn", "udp"])
        
        # Section: Advanced Options
        self._create_section_header(scrollable_frame, "Advanced Options")
        
        self._create_modern_spinbox(scrollable_frame, "Threads", self.threads_var, 1, 2000, 10)
        self._create_modern_spinbox(scrollable_frame, "Timeout (seconds)", self.timeout_var, 0.5, 10.0, 0.5)
        
        # Detection options
        self.service_detection_var = tk.BooleanVar(value=True)
        self.os_detection_var = tk.BooleanVar(value=False)
        self.banner_grab_var = tk.BooleanVar(value=True)
        
        options_frame = tk.Frame(scrollable_frame, bg=self.colors['surface'])
        options_frame.pack(fill=tk.X, pady=(10, 0))
        
        self._create_modern_checkbox(options_frame, "Service Detection", self.service_detection_var)
        self._create_modern_checkbox(options_frame, "OS Detection", self.os_detection_var)
        self._create_modern_checkbox(options_frame, "Banner Grabbing", self.banner_grab_var)
        
        # Export Section
        self._create_section_header(scrollable_frame, "Export Results")
        
        export_container = tk.Frame(scrollable_frame, bg=self.colors['surface'])
        export_container.pack(fill=tk.X, pady=(10, 0))
        
        export_buttons = [
            ("JSON", "json"),
            ("CSV", "csv"),
            ("HTML", "html")
        ]
        
        for i, (label, fmt) in enumerate(export_buttons):
            btn = tk.Button(
                export_container,
                text=label,
                command=lambda f=fmt: self._export_results(f),
                bg=self.colors['border'],
                fg=self.colors['text_secondary'],
                font=("Inter", 9),
                relief=tk.FLAT,
                cursor="hand2",
                width=10,
                pady=8
            )
            btn.grid(row=0, column=i, padx=2, sticky="ew")
            export_container.grid_columnconfigure(i, weight=1)
        
        # === FIXED ACTION BUTTONS AT BOTTOM (Always Visible) ===
        
        # Start button (primary action - highly visible, always at bottom)
        self.start_button = tk.Button(
            button_area,
            text="▶ Start Scan",
            command=self._start_scan,
            bg=self.colors['accent'],
            fg=self.colors['text_primary'],
            font=("Inter", 12, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            pady=14,
            activebackground=self.colors['accent_hover'],
            activeforeground=self.colors['text_primary']
        )
        self.start_button.pack(fill=tk.X, pady=(0, 8))
        
        # Secondary actions row
        secondary_frame = tk.Frame(button_area, bg=self.colors['surface'])
        secondary_frame.pack(fill=tk.X)
        
        # Stop button
        self.stop_button = tk.Button(
            secondary_frame,
            text="■ Stop",
            command=self._stop_scan,
            bg=self.colors['border'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            relief=tk.FLAT,
            cursor="hand2",
            pady=8,
            state=tk.DISABLED,
            disabledforeground=self.colors['text_tertiary']
        )
        self.stop_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        
        # Clear button
        clear_button = tk.Button(
            secondary_frame,
            text="✕ Clear",
            command=self._clear_results,
            bg=self.colors['border'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            relief=tk.FLAT,
            cursor="hand2",
            pady=8,
            activebackground=self.colors['surface'],
            activeforeground=self.colors['text_primary']
        )
        clear_button.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(4, 0))
    
    def _setup_results_panel(self, parent: tk.Frame):
        """Setup results panel with modern design."""
        # Content padding
        content = tk.Frame(parent, bg=self.colors['surface'])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header with title and stats
        header = tk.Frame(content, bg=self.colors['surface'])
        header.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(
            header,
            text="Scan Results",
            font=("Inter", 16, "bold"),
            bg=self.colors['surface'],
            fg=self.colors['text_primary']
        ).pack(side=tk.LEFT)
        
        self.stats_label = tk.Label(
            header,
            text="Ready to scan",
            bg=self.colors['surface'],
            fg=self.colors['text_secondary'],
            font=("Inter", 10)
        )
        self.stats_label.pack(side=tk.RIGHT)
        
        # Progress bar (modern style)
        progress_container = tk.Frame(content, bg=self.colors['border'], height=6)
        progress_container.pack(fill=tk.X, pady=(0, 15))
        progress_container.pack_propagate(False)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_container,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.BOTH, expand=True)
        
        # Notebook for tabs (styled)
        style = ttk.Style()
        style.theme_use('default')
        style.configure('Custom.TNotebook', background=self.colors['surface'], borderwidth=0)
        style.configure('Custom.TNotebook.Tab', 
            background=self.colors['border'],
            foreground=self.colors['text_secondary'],
            padding=[20, 10],
            font=('Inter', 10))
        style.map('Custom.TNotebook.Tab',
            background=[('selected', self.colors['surface'])],
            foreground=[('selected', self.colors['text_primary'])])
        
        notebook = ttk.Notebook(content, style='Custom.TNotebook')
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Results table tab
        results_frame = tk.Frame(notebook, bg=self.colors['surface'])
        notebook.add(results_frame, text="Results")
        
        # Create treeview with modern styling
        columns = ("Host", "Port", "Protocol", "State", "Service", "Banner")
        
        style.configure("Custom.Treeview",
            background=self.colors['bg'],
            foreground=self.colors['text_primary'],
            fieldbackground=self.colors['bg'],
            borderwidth=0,
            font=('Inter', 9))
        style.configure("Custom.Treeview.Heading",
            background=self.colors['border'],
            foreground=self.colors['text_secondary'],
            borderwidth=0,
            font=('Inter', 9, 'bold'))
        style.map('Custom.Treeview',
            background=[('selected', self.colors['accent'])],
            foreground=[('selected', self.colors['text_primary'])])
        
        self.results_tree = ttk.Treeview(
            results_frame, 
            columns=columns, 
            show="headings",
            style="Custom.Treeview"
        )
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            if col == "Banner":
                self.results_tree.column(col, width=300, anchor=tk.W)
            elif col in ["Host", "Service"]:
                self.results_tree.column(col, width=120, anchor=tk.W)
            else:
                self.results_tree.column(col, width=80, anchor=tk.CENTER)
        
        # Scrollbars
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        # Logs tab
        logs_frame = tk.Frame(notebook, bg=self.colors['surface'])
        notebook.add(logs_frame, text="Logs")
        
        self.logs_text = scrolledtext.ScrolledText(
            logs_frame,
            bg=self.colors['bg'],
            fg=self.colors['success'],
            font=("Consolas", 9),
            wrap=tk.WORD,
            borderwidth=0,
            insertbackground=self.colors['text_primary']
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _setup_status_panel(self):
        """Setup status panel with minimalist design."""
        status_frame = tk.Frame(self.root, bg=self.colors['border'], height=40)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            bg=self.colors['border'],
            fg=self.colors['text_secondary'],
            anchor=tk.W,
            font=("Inter", 9)
        )
        self.status_label.pack(fill=tk.X, padx=30, pady=10)
    
    def _create_section_header(self, parent: tk.Frame, text: str):
        """Create a section header."""
        tk.Label(
            parent,
            text=text,
            font=("Inter", 11, "bold"),
            bg=self.colors['surface'],
            fg=self.colors['text_primary'],
            anchor=tk.W
        ).pack(fill=tk.X, pady=(15, 10))
    
    def _create_modern_entry(self, parent: tk.Frame, label: str, variable: tk.StringVar, placeholder: str = ""):
        """Create modern entry field."""
        container = tk.Frame(parent, bg=self.colors['surface'])
        container.pack(fill=tk.X, pady=(0, 12))
        
        tk.Label(
            container,
            text=label,
            bg=self.colors['surface'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            anchor=tk.W
        ).pack(fill=tk.X, pady=(0, 4))
        
        entry = tk.Entry(
            container,
            textvariable=variable,
            bg=self.colors['bg'],
            fg=self.colors['text_primary'],
            font=("Inter", 10),
            relief=tk.FLAT,
            insertbackground=self.colors['text_primary'],
            selectbackground=self.colors['accent'],
            selectforeground=self.colors['text_primary'],
            highlightthickness=1,
            highlightbackground=self.colors['border'],
            highlightcolor=self.colors['accent']
        )
        entry.pack(fill=tk.X, ipady=8, ipadx=10)
        
        if placeholder and not variable.get():
            entry.insert(0, placeholder)
            entry.config(fg=self.colors['text_tertiary'])
            
            def on_focus_in(e):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.config(fg=self.colors['text_primary'])
            
            def on_focus_out(e):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.config(fg=self.colors['text_tertiary'])
            
            entry.bind('<FocusIn>', on_focus_in)
            entry.bind('<FocusOut>', on_focus_out)
    
    def _create_modern_combobox(self, parent: tk.Frame, label: str, variable: tk.StringVar, values: list, command=None):
        """Create modern combobox."""
        container = tk.Frame(parent, bg=self.colors['surface'])
        container.pack(fill=tk.X, pady=(0, 12))
        
        tk.Label(
            container,
            text=label,
            bg=self.colors['surface'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            anchor=tk.W
        ).pack(fill=tk.X, pady=(0, 4))
        
        style = ttk.Style()
        style.configure('Modern.TCombobox',
            fieldbackground=self.colors['bg'],
            background=self.colors['bg'],
            foreground=self.colors['text_primary'],
            arrowcolor=self.colors['text_secondary'],
            borderwidth=0)
        
        combo = ttk.Combobox(
            container,
            textvariable=variable,
            values=values,
            state="readonly",
            style='Modern.TCombobox',
            font=("Inter", 10)
        )
        combo.pack(fill=tk.X, ipady=6)
        
        if command:
            combo.bind("<<ComboboxSelected>>", command)
    
    def _create_modern_spinbox(self, parent: tk.Frame, label: str, variable, from_: float, to: float, increment: float):
        """Create modern spinbox."""
        container = tk.Frame(parent, bg=self.colors['surface'])
        container.pack(fill=tk.X, pady=(0, 12))
        
        tk.Label(
            container,
            text=label,
            bg=self.colors['surface'],
            fg=self.colors['text_secondary'],
            font=("Inter", 9),
            anchor=tk.W
        ).pack(fill=tk.X, pady=(0, 4))
        
        spinbox = tk.Spinbox(
            container,
            from_=from_,
            to=to,
            increment=increment,
            textvariable=variable,
            bg=self.colors['bg'],
            fg=self.colors['text_primary'],
            font=("Inter", 10),
            relief=tk.FLAT,
            insertbackground=self.colors['text_primary'],
            buttonbackground=self.colors['border'],
            highlightthickness=1,
            highlightbackground=self.colors['border'],
            highlightcolor=self.colors['accent']
        )
        spinbox.pack(fill=tk.X, ipady=6, ipadx=10)
    
    def _create_modern_checkbox(self, parent: tk.Frame, text: str, variable: tk.BooleanVar):
        """Create modern checkbox."""
        cb = tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            bg=self.colors['surface'],
            fg=self.colors['text_secondary'],
            selectcolor=self.colors['bg'],
            activebackground=self.colors['surface'],
            activeforeground=self.colors['text_primary'],
            font=("Inter", 9),
            cursor="hand2",
            relief=tk.FLAT
        )
        cb.pack(anchor=tk.W, pady=3)
    

    
    def _on_preset_change(self, event=None):
        """Handle preset change."""
        preset_name = self.preset_var.get()
        
        if preset_name == "quick":
            self.ports_var.set("1-1000")
            self.threads_var.set(100)
            self.timeout_var.set(1.0)
        elif preset_name == "top-ports":
            self.ports_var.set("1-1000")
            self.threads_var.set(200)
            self.timeout_var.set(2.0)
        elif preset_name == "full":
            self.ports_var.set("1-65535")
            self.threads_var.set(500)
            self.timeout_var.set(3.0)
        elif preset_name == "stealth":
            self.ports_var.set("1-1000")
            self.threads_var.set(10)
            self.timeout_var.set(5.0)
            self.scan_type_var.set("syn")
    
    def _import_targets(self):
        """Import targets from file."""
        filename = filedialog.askopenfilename(
            title="Select Target File",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            targets = parse_targets_from_file(Path(filename))
            target_str = ','.join(targets)
            self.target_var.set(target_str)
            self._log(f"Loaded {len(targets)} targets from {Path(filename).name}", self.colors['success'])
            messagebox.showinfo("Success", f"Loaded {len(targets)} targets from file")
        except FileNotFoundError:
            messagebox.showerror("Error", "Target file not found")
        except ValueError as e:
            messagebox.showerror("Error", f"Failed to parse targets: {e}")
    
    def _open_profile_manager(self):
        """Open profile manager dialog."""
        from spectrescan.gui.dialogs import ProfileManagerDialog
        ProfileManagerDialog(self.root, on_load_callback=self._load_profile_config)
    
    def _open_history_browser(self):
        """Open history browser dialog."""
        from spectrescan.gui.dialogs import HistoryBrowserDialog
        HistoryBrowserDialog(self.root)
    
    def _load_profile_config(self, profile):
        """Load profile configuration into GUI."""
        from spectrescan.core.profiles import ScanProfile
        
        # Set ports
        self.ports_var.set(','.join(map(str, profile.ports)))
        
        # Set scan type
        if 'tcp' in profile.scan_types:
            self.scan_type_var.set('tcp')
        elif 'syn' in profile.scan_types:
            self.scan_type_var.set('syn')
        elif 'udp' in profile.scan_types:
            self.scan_type_var.set('udp')
        elif 'async' in profile.scan_types:
            self.scan_type_var.set('async')
        
        # Set performance settings
        self.threads_var.set(profile.threads)
        self.timeout_var.set(profile.timeout)
        
        # Set feature flags
        self.service_detect_var.set(profile.enable_service_detection)
        self.os_detect_var.set(profile.enable_os_detection)
        self.banner_grab_var.set(profile.enable_banner_grabbing)
        
        self._log(f"Loaded profile: {profile.name}", self.colors['success'])
    
    def _log(self, message: str, color: str = "#00ff00"):
        """Add log message."""
        self.logs_text.insert(tk.END, message + "\n")
        self.logs_text.see(tk.END)
    
    def _start_scan(self):
        """Start scan."""
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress")
            return
        
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        try:
            port_list = parse_ports(self.ports_var.get())
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid port specification: {e}")
            return
        
        self.scanning = True
        self.start_button.config(state=tk.DISABLED, bg=self.colors['border'])
        self.stop_button.config(state=tk.NORMAL, bg=self.colors['error'])
        self.status_label.config(text="Scanning...", fg=self.colors['warning'])
        self.results = []
        
        self._log(f"Starting scan of {target}...")
        
        # Start scan thread
        self.scan_thread = threading.Thread(target=self._run_scan, args=(target, port_list))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _run_scan(self, target: str, ports: List[int]):
        """Run scan in background thread."""
        try:
            # Create config
            preset_map = {
                "quick": ScanPreset.QUICK,
                "top-ports": ScanPreset.TOP_PORTS,
                "full": ScanPreset.FULL,
                "stealth": ScanPreset.STEALTH,
                "safe": ScanPreset.SAFE,
                "aggressive": ScanPreset.AGGRESSIVE,
            }
            
            preset = preset_map.get(self.preset_var.get(), ScanPreset.QUICK)
            config = get_preset_config(preset)
            config.ports = ports
            config.threads = self.threads_var.get()
            config.timeout = self.timeout_var.get()
            config.enable_service_detection = self.service_detection_var.get()
            config.enable_os_detection = self.os_detection_var.get()
            config.enable_banner_grabbing = self.banner_grab_var.get()
            
            if self.scan_type_var.get() == "tcp":
                config.scan_types = ["tcp"]
            elif self.scan_type_var.get() == "syn":
                config.scan_types = ["syn"]
            elif self.scan_type_var.get() == "udp":
                config.scan_types = ["udp"]
            
            # Create scanner
            self.scanner = PortScanner(config)
            
            total_ports = len(ports)
            scanned = [0]
            open_count = [0]
            
            # Target progress callback
            def target_callback(current_target: str, idx: int, total: int):
                self.current_target_index = idx
                self.total_targets = total
                if total > 1:
                    self.root.after(0, lambda: self._log(
                        f"Scanning target {idx}/{total}: {current_target}",
                        self.colors['accent']
                    ))
            
            def callback(result: ScanResult):
                if not self.scanning:
                    return
                
                scanned[0] += 1
                progress = (scanned[0] / total_ports) * 100
                
                self.root.after(0, lambda: self.progress_var.set(progress))
                
                # Update status with multi-target info
                if self.total_targets > 1:
                    status_text = f"Target {self.current_target_index}/{self.total_targets} | Progress: {scanned[0]}/{total_ports} ({progress:.1f}%) | Open: {open_count[0]}"
                else:
                    status_text = f"Progress: {scanned[0]}/{total_ports} ({progress:.1f}%) | Open: {open_count[0]}"
                
                self.root.after(0, lambda: self.stats_label.config(text=status_text))
                
                if result.state == "open":
                    open_count[0] += 1
                    self.results.append(result)
                    
                    # Add to table
                    self.root.after(0, lambda r=result: self.results_tree.insert(
                        "",
                        tk.END,
                        values=(
                            r.host,
                            r.port,
                            r.protocol,
                            r.state,
                            r.service or "unknown",
                            (r.banner[:50] + "...") if r.banner and len(r.banner) > 50 else (r.banner or "")
                        )
                    ))
                    
                    self.root.after(0, lambda r=result: self._log(
                        f"[OPEN] {r.host}:{r.port}/{r.protocol} - {r.service or 'unknown'}"
                    ))
            
            # Run scan with target callback
            self.scanner.scan(target, callback=callback, target_callback=target_callback)
            
            # Complete
            if self.scanning:
                summary = self.scanner.get_scan_summary()
                self.root.after(0, lambda: self._log(
                    f"\nScan complete! Found {summary['open_ports']} open ports in {summary['scan_duration']}"
                ))
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Complete - {summary['open_ports']} open ports found",
                    fg=self.colors['success']
                ))
                self.root.after(0, lambda: messagebox.showinfo(
                    "Scan Complete",
                    f"Scan finished!\n\nOpen ports: {summary['open_ports']}\nDuration: {summary['scan_duration']}"
                ))
        
        except Exception as e:
            self.root.after(0, lambda: self._log(f"Error: {e}"))
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
        
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL, bg=self.colors['accent']))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED, bg=self.colors['border']))
    
    def _stop_scan(self):
        """Stop scan."""
        self.scanning = False
        self.status_label.config(text="Stopped", fg=self.colors['error'])
        self._log("Scan stopped by user")
        self.start_button.config(state=tk.NORMAL, bg=self.colors['accent'])
        self.stop_button.config(state=tk.DISABLED, bg=self.colors['border'])
    
    def _clear_results(self):
        """Clear results."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.logs_text.delete(1.0, tk.END)
        self.results = []
        self.progress_var.set(0)
        self.stats_label.config(text="Ready to scan", fg=self.colors['text_secondary'])
        self.status_label.config(text="Ready", fg=self.colors['text_secondary'])
    
    def _export_results(self, format_type: str):
        """Export results."""
        if not self.results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filetypes = {
            "json": [("JSON files", "*.json")],
            "csv": [("CSV files", "*.csv")],
            "html": [("HTML files", "*.html")],
        }
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=filetypes.get(format_type, [("All files", "*.*")])
        )
        
        if not filepath:
            return
        
        try:
            summary = self.scanner.get_scan_summary() if self.scanner else {}
            
            if format_type == "json":
                generate_json_report(self.results, filepath, summary)
            elif format_type == "csv":
                generate_csv_report(self.results, filepath)
            elif format_type == "html":
                host_info = self.scanner.host_info if self.scanner else {}
                generate_html_report(self.results, filepath, summary, host_info)
            
            messagebox.showinfo("Success", f"Results exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


def run_gui():
    """Run the GUI application."""
    root = tk.Tk()
    app = SpectreScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
