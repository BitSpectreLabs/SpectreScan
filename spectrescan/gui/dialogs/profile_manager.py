"""
GUI Profile Manager Dialog
by BitSpectreLabs
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Optional
from spectrescan.core.profiles import ProfileManager, ScanProfile


class ProfileManagerDialog:
    """Profile management dialog."""
    
    def __init__(self, parent: tk.Tk, on_load_callback=None):
        """
        Initialize profile manager dialog.
        
        Args:
            parent: Parent window
            on_load_callback: Callback when profile is loaded
        """
        self.parent = parent
        self.on_load_callback = on_load_callback
        self.manager = ProfileManager()
        
        # Create dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Profile Manager")
        self.dialog.geometry("800x600")
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
        }
        
        self.dialog.configure(bg=self.colors['bg'])
        
        self._create_widgets()
        self._refresh_list()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (800 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (600 // 2)
        self.dialog.geometry(f"800x600+{x}+{y}")
    
    def _create_widgets(self):
        """Create dialog widgets."""
        # Title
        title_frame = tk.Frame(self.dialog, bg=self.colors['bg'])
        title_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        title = tk.Label(
            title_frame,
            text="Scan Profiles",
            font=("Segoe UI", 18, "bold"),
            fg=self.colors['text_primary'],
            bg=self.colors['bg']
        )
        title.pack(side=tk.LEFT)
        
        # Buttons frame
        btn_frame = tk.Frame(title_frame, bg=self.colors['bg'])
        btn_frame.pack(side=tk.RIGHT)
        
        self._create_button(btn_frame, "➕ New", self._new_profile).pack(side=tk.LEFT, padx=2)
        self._create_button(btn_frame, "📥 Import", self._import_profile).pack(side=tk.LEFT, padx=2)
        self._create_button(btn_frame, "🔄 Refresh", self._refresh_list).pack(side=tk.LEFT, padx=2)
        
        # List frame
        list_frame = tk.Frame(self.dialog, bg=self.colors['surface'], highlightbackground=self.colors['border'], highlightthickness=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Treeview
        columns = ("name", "description", "ports", "scan_types", "created")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.tree.heading("name", text="Profile Name")
        self.tree.heading("description", text="Description")
        self.tree.heading("ports", text="Ports")
        self.tree.heading("scan_types", text="Scan Types")
        self.tree.heading("created", text="Created")
        
        self.tree.column("name", width=150)
        self.tree.column("description", width=250)
        self.tree.column("ports", width=80, anchor=tk.CENTER)
        self.tree.column("scan_types", width=120)
        self.tree.column("created", width=150)
        
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
        self.tree.bind("<Double-1>", lambda e: self._view_profile())
        
        # Action buttons frame
        action_frame = tk.Frame(self.dialog, bg=self.colors['bg'])
        action_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self._create_button(action_frame, "👁️ View", self._view_profile).pack(side=tk.LEFT, padx=5)
        self._create_button(action_frame, "✅ Load", self._load_profile, self.colors['success']).pack(side=tk.LEFT, padx=5)
        self._create_button(action_frame, "📤 Export", self._export_profile).pack(side=tk.LEFT, padx=5)
        self._create_button(action_frame, "🗑️ Delete", self._delete_profile, self.colors['error']).pack(side=tk.LEFT, padx=5)
        
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
    
    def _refresh_list(self):
        """Refresh profile list."""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load profiles
        profiles = self.manager.list_profiles()
        
        for name in profiles:
            try:
                profile = self.manager.load_profile(name)
                
                # Format data
                ports_text = f"{len(profile.ports)} ports"
                scan_types = ", ".join(profile.scan_types)
                created = profile.created_at[:10] if profile.created_at else "Unknown"
                
                self.tree.insert("", tk.END, values=(
                    profile.name,
                    profile.description,
                    ports_text,
                    scan_types,
                    created
                ))
            except Exception as e:
                print(f"Error loading profile {name}: {e}")
    
    def _get_selected_profile(self) -> Optional[str]:
        """Get selected profile name."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a profile first.")
            return None
        
        item = self.tree.item(selection[0])
        return item['values'][0]  # Profile name
    
    def _new_profile(self):
        """Create new profile."""
        dialog = ProfileEditDialog(self.dialog, None, self.manager)
        self.dialog.wait_window(dialog.dialog)
        self._refresh_list()
    
    def _view_profile(self):
        """View profile details."""
        name = self._get_selected_profile()
        if not name:
            return
        
        try:
            profile = self.manager.load_profile(name)
            ProfileViewDialog(self.dialog, profile)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile: {e}")
    
    def _load_profile(self):
        """Load profile into main GUI."""
        name = self._get_selected_profile()
        if not name:
            return
        
        try:
            profile = self.manager.load_profile(name)
            
            if self.on_load_callback:
                self.on_load_callback(profile)
            
            messagebox.showinfo("Success", f"Profile '{name}' loaded successfully!")
            self.dialog.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile: {e}")
    
    def _export_profile(self):
        """Export profile to file."""
        name = self._get_selected_profile()
        if not name:
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"{name}.json"
        )
        
        if filename:
            try:
                self.manager.export_profile(name, Path(filename))
                messagebox.showinfo("Success", f"Profile exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export profile: {e}")
    
    def _import_profile(self):
        """Import profile from file."""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                profile = self.manager.import_profile(Path(filename))
                messagebox.showinfo("Success", f"Profile '{profile.name}' imported successfully!")
                self._refresh_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import profile: {e}")
    
    def _delete_profile(self):
        """Delete selected profile."""
        name = self._get_selected_profile()
        if not name:
            return
        
        if messagebox.askyesno("Confirm Delete", f"Delete profile '{name}'?"):
            try:
                self.manager.delete_profile(name)
                messagebox.showinfo("Success", f"Profile '{name}' deleted")
                self._refresh_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete profile: {e}")


class ProfileViewDialog:
    """Profile details view dialog."""
    
    def __init__(self, parent: tk.Toplevel, profile: ScanProfile):
        """Initialize view dialog."""
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Profile: {profile.name}")
        self.dialog.geometry("600x500")
        self.dialog.transient(parent)
        
        # Colors
        bg = '#000000'
        surface = '#0A0A0A'
        text = '#FFFFFF'
        secondary = '#888888'
        
        self.dialog.configure(bg=bg)
        
        # Content frame
        content = tk.Frame(self.dialog, bg=surface, padx=30, pady=30)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(content, text=profile.name, font=("Segoe UI", 16, "bold"), fg=text, bg=surface)
        title.pack(anchor=tk.W, pady=(0, 20))
        
        # Details
        details = [
            ("Description", profile.description),
            ("Ports", f"{len(profile.ports)} ports: {', '.join(map(str, profile.ports[:10]))}{'...' if len(profile.ports) > 10 else ''}"),
            ("Scan Types", ", ".join(profile.scan_types)),
            ("Threads", str(profile.threads)),
            ("Timeout", f"{profile.timeout}s"),
            ("Rate Limit", str(profile.rate_limit) if profile.rate_limit else "None"),
            ("Service Detection", "Enabled" if profile.enable_service_detection else "Disabled"),
            ("OS Detection", "Enabled" if profile.enable_os_detection else "Disabled"),
            ("Banner Grabbing", "Enabled" if profile.enable_banner_grabbing else "Disabled"),
            ("Randomize", "Yes" if profile.randomize else "No"),
            ("Timing Template", str(profile.timing_template)),
            ("Created", profile.created_at[:19] if profile.created_at else "Unknown"),
            ("Modified", profile.modified_at[:19] if profile.modified_at else "Unknown"),
        ]
        
        for label, value in details:
            row = tk.Frame(content, bg=surface)
            row.pack(fill=tk.X, pady=5)
            
            lbl = tk.Label(row, text=f"{label}:", font=("Segoe UI", 10, "bold"), fg=secondary, bg=surface, width=18, anchor=tk.W)
            lbl.pack(side=tk.LEFT)
            
            val = tk.Label(row, text=value, font=("Segoe UI", 10), fg=text, bg=surface, anchor=tk.W)
            val.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
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


class ProfileEditDialog:
    """Profile create/edit dialog."""
    
    def __init__(self, parent: tk.Toplevel, profile: Optional[ScanProfile], manager: ProfileManager):
        """Initialize edit dialog."""
        self.manager = manager
        self.profile = profile
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("New Profile" if profile is None else f"Edit: {profile.name}")
        self.dialog.geometry("600x700")
        self.dialog.transient(parent)
        
        # Colors
        self.bg = '#000000'
        self.surface = '#0A0A0A'
        self.text = '#FFFFFF'
        self.secondary = '#888888'
        
        self.dialog.configure(bg=self.bg)
        
        self._create_form()
    
    def _create_form(self):
        """Create form widgets."""
        # Content frame with scrollbar
        canvas = tk.Canvas(self.dialog, bg=self.bg, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.dialog, orient=tk.VERTICAL, command=canvas.yview)
        content = tk.Frame(canvas, bg=self.surface, padx=30, pady=30)
        
        content.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=content, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Form fields
        self.fields = {}
        
        # Name
        self._add_field(content, "name", "Profile Name", tk.Entry)
        
        # Description
        self._add_field(content, "description", "Description", tk.Entry)
        
        # Ports
        self._add_field(content, "ports", "Ports (e.g., 80,443,1-1000)", tk.Entry)
        
        # Scan types
        scan_frame = self._add_label(content, "Scan Types")
        self.fields['scan_types'] = {}
        for scan_type in ["tcp", "syn", "udp", "async"]:
            var = tk.BooleanVar(value=scan_type == "tcp")
            cb = tk.Checkbutton(scan_frame, text=scan_type.upper(), variable=var, fg=self.text, bg=self.surface, selectcolor=self.surface, font=("Segoe UI", 10))
            cb.pack(side=tk.LEFT, padx=5)
            self.fields['scan_types'][scan_type] = var
        
        # Threads
        self._add_field(content, "threads", "Threads", tk.Entry, "100")
        
        # Timeout
        self._add_field(content, "timeout", "Timeout (seconds)", tk.Entry, "2.0")
        
        # Features
        features_frame = self._add_label(content, "Features")
        self.fields['features'] = {}
        for feature, default in [
            ("service_detection", True),
            ("os_detection", False),
            ("banner_grabbing", True),
            ("randomize", False)
        ]:
            var = tk.BooleanVar(value=default)
            label = feature.replace("_", " ").title()
            cb = tk.Checkbutton(features_frame, text=label, variable=var, fg=self.text, bg=self.surface, selectcolor=self.surface, font=("Segoe UI", 10))
            cb.pack(anchor=tk.W, pady=2)
            self.fields['features'][feature] = var
        
        # Buttons
        btn_frame = tk.Frame(self.dialog, bg=self.bg)
        btn_frame.pack(fill=tk.X, padx=20, pady=10)
        
        save_btn = tk.Button(btn_frame, text="💾 Save", command=self._save, font=("Segoe UI", 10), fg=self.text, bg='#0DDA83', relief=tk.FLAT, padx=20, pady=10)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = tk.Button(btn_frame, text="Cancel", command=self.dialog.destroy, font=("Segoe UI", 10), fg=self.text, bg='#E00', relief=tk.FLAT, padx=20, pady=10)
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        # Load existing profile data if editing
        if self.profile:
            self._load_profile_data()
    
    def _add_label(self, parent, text):
        """Add section label and return frame."""
        lbl = tk.Label(parent, text=text, font=("Segoe UI", 11, "bold"), fg=self.secondary, bg=self.surface, anchor=tk.W)
        lbl.pack(fill=tk.X, pady=(15, 5))
        
        frame = tk.Frame(parent, bg=self.surface)
        frame.pack(fill=tk.X, pady=5)
        return frame
    
    def _add_field(self, parent, key, label, widget_class, default=""):
        """Add form field."""
        lbl = tk.Label(parent, text=label, font=("Segoe UI", 10), fg=self.secondary, bg=self.surface, anchor=tk.W)
        lbl.pack(fill=tk.X, pady=(10, 2))
        
        widget = widget_class(parent, font=("Segoe UI", 10), bg='#1A1A1A', fg=self.text, insertbackground=self.text, relief=tk.FLAT)
        widget.pack(fill=tk.X, ipady=8)
        
        if default:
            widget.insert(0, default)
        
        self.fields[key] = widget
    
    def _load_profile_data(self):
        """Load existing profile data into form."""
        self.fields['name'].insert(0, self.profile.name)
        self.fields['description'].insert(0, self.profile.description)
        self.fields['ports'].insert(0, ','.join(map(str, self.profile.ports)))
        self.fields['threads'].delete(0, tk.END)
        self.fields['threads'].insert(0, str(self.profile.threads))
        self.fields['timeout'].delete(0, tk.END)
        self.fields['timeout'].insert(0, str(self.profile.timeout))
        
        for scan_type, var in self.fields['scan_types'].items():
            var.set(scan_type in self.profile.scan_types)
        
        self.fields['features']['service_detection'].set(self.profile.enable_service_detection)
        self.fields['features']['os_detection'].set(self.profile.enable_os_detection)
        self.fields['features']['banner_grabbing'].set(self.profile.enable_banner_grabbing)
        self.fields['features']['randomize'].set(self.profile.randomize)
    
    def _save(self):
        """Save profile."""
        try:
            # Get values
            name = self.fields['name'].get().strip()
            description = self.fields['description'].get().strip()
            ports_str = self.fields['ports'].get().strip()
            threads = int(self.fields['threads'].get())
            timeout = float(self.fields['timeout'].get())
            
            if not name:
                messagebox.showerror("Error", "Profile name is required")
                return
            
            # Parse ports
            from spectrescan.core.utils import parse_ports
            ports = parse_ports(ports_str)
            
            # Get scan types
            scan_types = [st for st, var in self.fields['scan_types'].items() if var.get()]
            if not scan_types:
                messagebox.showerror("Error", "At least one scan type must be selected")
                return
            
            # Create profile
            profile = ScanProfile(
                name=name,
                description=description,
                ports=ports,
                scan_types=scan_types,
                threads=threads,
                timeout=timeout,
                enable_service_detection=self.fields['features']['service_detection'].get(),
                enable_os_detection=self.fields['features']['os_detection'].get(),
                enable_banner_grabbing=self.fields['features']['banner_grabbing'].get(),
                randomize=self.fields['features']['randomize'].get(),
                timing_template=3
            )
            
            self.manager.save_profile(profile)
            messagebox.showinfo("Success", f"Profile '{name}' saved successfully!")
            self.dialog.destroy()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profile: {e}")
