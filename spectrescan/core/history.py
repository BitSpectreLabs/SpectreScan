"""
Scan History Management
by BitSpectreLabs

Manages scan history and allows re-running previous scans.
"""

import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib


@dataclass
class ScanHistoryEntry:
    """Scan history entry."""
    
    id: str
    target: str
    ports: List[int]
    scan_type: str
    timestamp: str
    duration: float
    open_ports: int
    closed_ports: int
    filtered_ports: int
    total_ports: int
    config: Dict[str, Any]
    results_file: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanHistoryEntry':
        """Create entry from dictionary."""
        return cls(**data)


class HistoryManager:
    """Manages scan history."""
    
    def __init__(self, history_dir: Optional[Path] = None):
        """
        Initialize history manager.
        
        Args:
            history_dir: Directory to store history (default: ~/.spectrescan/history/)
        """
        if history_dir is None:
            home = Path.home()
            history_dir = home / ".spectrescan" / "history"
        
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.history_dir / "scan_history.json"
        
        # Initialize history file if it doesn't exist
        if not self.history_file.exists():
            self._save_history([])
    
    def add_entry(
        self,
        target: str,
        ports: List[int],
        scan_type: str,
        duration: float,
        open_ports: int,
        closed_ports: int,
        filtered_ports: int,
        config: Dict[str, Any],
        results_file: Optional[str] = None
    ) -> ScanHistoryEntry:
        """
        Add a scan history entry.
        
        Args:
            target: Scan target
            ports: List of scanned ports
            scan_type: Type of scan
            duration: Scan duration in seconds
            open_ports: Number of open ports found
            closed_ports: Number of closed ports
            filtered_ports: Number of filtered ports
            config: Scan configuration
            results_file: Optional path to results file
        
        Returns:
            Created ScanHistoryEntry
        """
        # Generate unique ID
        scan_id = self._generate_id(target, ports, scan_type)
        
        entry = ScanHistoryEntry(
            id=scan_id,
            target=target,
            ports=ports,
            scan_type=scan_type,
            timestamp=datetime.now().isoformat(),
            duration=duration,
            open_ports=open_ports,
            closed_ports=closed_ports,
            filtered_ports=filtered_ports,
            total_ports=len(ports),
            config=config,
            results_file=results_file
        )
        
        history = self._load_history()
        history.append(entry.to_dict())
        self._save_history(history)
        
        return entry
    
    def get_entry(self, scan_id: str) -> Optional[ScanHistoryEntry]:
        """
        Get a history entry by ID.
        
        Args:
            scan_id: Scan ID
        
        Returns:
            ScanHistoryEntry if found, None otherwise
        """
        history = self._load_history()
        for entry_dict in history:
            if entry_dict['id'] == scan_id:
                return ScanHistoryEntry.from_dict(entry_dict)
        return None
    
    def list_entries(
        self,
        limit: Optional[int] = None,
        target_filter: Optional[str] = None,
        scan_type_filter: Optional[str] = None
    ) -> List[ScanHistoryEntry]:
        """
        List history entries with optional filtering.
        
        Args:
            limit: Maximum number of entries to return
            target_filter: Filter by target (substring match)
            scan_type_filter: Filter by scan type
        
        Returns:
            List of ScanHistoryEntry objects
        """
        history = self._load_history()
        entries = []
        
        for entry_dict in reversed(history):  # Most recent first
            entry = ScanHistoryEntry.from_dict(entry_dict)
            
            # Apply filters
            if target_filter and target_filter not in entry.target:
                continue
            if scan_type_filter and entry.scan_type != scan_type_filter:
                continue
            
            entries.append(entry)
            
            if limit and len(entries) >= limit:
                break
        
        return entries
    
    def delete_entry(self, scan_id: str) -> bool:
        """
        Delete a history entry.
        
        Args:
            scan_id: Scan ID
        
        Returns:
            True if deleted, False if not found
        """
        history = self._load_history()
        original_length = len(history)
        
        history = [e for e in history if e['id'] != scan_id]
        
        if len(history) < original_length:
            self._save_history(history)
            return True
        return False
    
    def clear_history(self) -> None:
        """Clear all history entries."""
        self._save_history([])
    
    def search_history(
        self,
        query: str,
        search_target: bool = True,
        search_config: bool = False
    ) -> List[ScanHistoryEntry]:
        """
        Search history entries.
        
        Args:
            query: Search query
            search_target: Search in target field
            search_config: Search in config field
        
        Returns:
            List of matching ScanHistoryEntry objects
        """
        history = self._load_history()
        results = []
        query_lower = query.lower()
        
        for entry_dict in reversed(history):
            entry = ScanHistoryEntry.from_dict(entry_dict)
            
            if search_target and query_lower in entry.target.lower():
                results.append(entry)
                continue
            
            if search_config:
                config_str = json.dumps(entry.config).lower()
                if query_lower in config_str:
                    results.append(entry)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get history statistics.
        
        Returns:
            Dictionary with statistics
        """
        history = self._load_history()
        
        if not history:
            return {
                'total_scans': 0,
                'total_ports_scanned': 0,
                'total_open_ports': 0,
                'total_duration': 0,
                'scan_types': {},
                'most_scanned_target': None
            }
        
        total_scans = len(history)
        total_ports = sum(e['total_ports'] for e in history)
        total_open = sum(e['open_ports'] for e in history)
        total_duration = sum(e['duration'] for e in history)
        
        # Count scan types
        scan_types = {}
        for entry in history:
            scan_type = entry['scan_type']
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        # Find most scanned target
        target_counts = {}
        for entry in history:
            target = entry['target']
            target_counts[target] = target_counts.get(target, 0) + 1
        
        most_scanned = max(target_counts.items(), key=lambda x: x[1])[0] if target_counts else None
        
        return {
            'total_scans': total_scans,
            'total_ports_scanned': total_ports,
            'total_open_ports': total_open,
            'total_duration': round(total_duration, 2),
            'scan_types': scan_types,
            'most_scanned_target': most_scanned
        }
    
    def _load_history(self) -> List[Dict[str, Any]]:
        """Load history from file."""
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def _save_history(self, history: List[Dict[str, Any]]) -> None:
        """Save history to file."""
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def _generate_id(self, target: str, ports: List[int], scan_type: str) -> str:
        """
        Generate unique scan ID.
        
        Args:
            target: Scan target
            ports: List of ports
            scan_type: Scan type
        
        Returns:
            Unique scan ID
        """
        timestamp = datetime.now().isoformat()
        data = f"{target}:{ports}:{scan_type}:{timestamp}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
