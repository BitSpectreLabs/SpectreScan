"""
Scan Comparison Feature
by BitSpectreLabs

Compares two scan results to identify differences.
"""

from dataclasses import dataclass
from typing import List, Dict, Set, Optional
from spectrescan.core.utils import ScanResult
from spectrescan.core.history import HistoryManager, ScanHistoryEntry


@dataclass
class PortDifference:
    """Represents a difference in port states between scans."""
    
    port: int
    protocol: str
    old_state: str
    new_state: str
    service_old: Optional[str] = None
    service_new: Optional[str] = None


@dataclass
class ScanComparison:
    """Result of comparing two scans."""
    
    scan1_id: str
    scan2_id: str
    scan1_target: str
    scan2_target: str
    scan1_timestamp: str
    scan2_timestamp: str
    
    # Ports that changed state
    newly_opened: List[PortDifference]
    newly_closed: List[PortDifference]
    newly_filtered: List[PortDifference]
    
    # Ports with changed services
    service_changed: List[PortDifference]
    
    # Summary statistics
    total_changes: int
    scan1_open_count: int
    scan2_open_count: int
    open_diff: int  # positive = more open ports in scan2


class ScanComparer:
    """Compare two scans to identify differences."""
    
    def __init__(self):
        """Initialize scan comparer."""
        self.history_manager = HistoryManager()
    
    def compare_scans(
        self,
        scan1_id: str,
        scan2_id: str,
        results1: Optional[List[ScanResult]] = None,
        results2: Optional[List[ScanResult]] = None
    ) -> ScanComparison:
        """
        Compare two scans.
        
        Args:
            scan1_id: First scan ID (older scan)
            scan2_id: Second scan ID (newer scan)
            results1: Optional scan results for scan1 (if not in history)
            results2: Optional scan results for scan2 (if not in history)
        
        Returns:
            ScanComparison object
        
        Raises:
            ValueError: If scans not found or have different targets
        """
        # Get history entries
        entry1 = self.history_manager.get_entry(scan1_id)
        entry2 = self.history_manager.get_entry(scan2_id)
        
        if not entry1:
            raise ValueError(f"Scan {scan1_id} not found in history")
        if not entry2:
            raise ValueError(f"Scan {scan2_id} not found in history")
        
        # Verify same target
        if entry1.target != entry2.target:
            raise ValueError(
                f"Cannot compare scans with different targets: "
                f"{entry1.target} vs {entry2.target}"
            )
        
        # Load results if not provided
        if results1 is None:
            results1 = self._load_results_from_history(entry1)
        if results2 is None:
            results2 = self._load_results_from_history(entry2)
        
        # Create port maps
        ports1 = {(r.port, r.protocol): r for r in results1}
        ports2 = {(r.port, r.protocol): r for r in results2}
        
        # Find differences
        newly_opened = []
        newly_closed = []
        newly_filtered = []
        service_changed = []
        
        # Check all ports in both scans
        all_ports = set(ports1.keys()) | set(ports2.keys())
        
        for port_key in all_ports:
            port, protocol = port_key
            
            result1 = ports1.get(port_key)
            result2 = ports2.get(port_key)
            
            if result1 and result2:
                # Port exists in both scans
                if result1.state != result2.state:
                    # State changed
                    diff = PortDifference(
                        port=port,
                        protocol=protocol,
                        old_state=result1.state,
                        new_state=result2.state,
                        service_old=result1.service,
                        service_new=result2.service
                    )
                    
                    if result2.state == "open":
                        newly_opened.append(diff)
                    elif result2.state == "closed":
                        newly_closed.append(diff)
                    elif result2.state == "filtered":
                        newly_filtered.append(diff)
                
                elif result1.service != result2.service:
                    # Service changed but state same
                    if result1.state == "open":  # Only care about open ports
                        diff = PortDifference(
                            port=port,
                            protocol=protocol,
                            old_state=result1.state,
                            new_state=result2.state,
                            service_old=result1.service,
                            service_new=result2.service
                        )
                        service_changed.append(diff)
            
            elif result2 and not result1:
                # Port only in scan2 (newly scanned)
                if result2.state == "open":
                    diff = PortDifference(
                        port=port,
                        protocol=protocol,
                        old_state="not_scanned",
                        new_state=result2.state,
                        service_new=result2.service
                    )
                    newly_opened.append(diff)
            
            elif result1 and not result2:
                # Port only in scan1 (no longer scanned)
                if result1.state == "open":
                    diff = PortDifference(
                        port=port,
                        protocol=protocol,
                        old_state=result1.state,
                        new_state="not_scanned",
                        service_old=result1.service
                    )
                    newly_closed.append(diff)
        
        # Calculate statistics
        total_changes = len(newly_opened) + len(newly_closed) + len(newly_filtered) + len(service_changed)
        open_diff = entry2.open_ports - entry1.open_ports
        
        return ScanComparison(
            scan1_id=scan1_id,
            scan2_id=scan2_id,
            scan1_target=entry1.target,
            scan2_target=entry2.target,
            scan1_timestamp=entry1.timestamp,
            scan2_timestamp=entry2.timestamp,
            newly_opened=newly_opened,
            newly_closed=newly_closed,
            newly_filtered=newly_filtered,
            service_changed=service_changed,
            total_changes=total_changes,
            scan1_open_count=entry1.open_ports,
            scan2_open_count=entry2.open_ports,
            open_diff=open_diff
        )
    
    def _load_results_from_history(self, entry: ScanHistoryEntry) -> List[ScanResult]:
        """
        Load scan results from history entry.
        
        Args:
            entry: History entry
        
        Returns:
            List of ScanResult objects
        
        Note:
            This is a placeholder. In a full implementation, you would load
            the actual results from the results_file path stored in the entry.
            For now, we'll create synthetic results based on the entry metadata.
        """
        # In a real implementation, you would:
        # 1. Check if entry.results_file exists
        # 2. Load the JSON/CSV/XML file
        # 3. Parse it back into ScanResult objects
        
        # For now, create synthetic results (this is a limitation)
        # In practice, scans should save their detailed results to files
        # and store the file path in the history entry
        
        results = []
        # This is incomplete - real implementation needs actual result storage
        # For demonstration, we just return empty list
        # TODO: Implement proper result file loading
        return results
    
    def format_comparison_text(self, comparison: ScanComparison) -> str:
        """
        Format comparison result as human-readable text.
        
        Args:
            comparison: ScanComparison object
        
        Returns:
            Formatted text
        """
        lines = []
        lines.append("=" * 70)
        lines.append("SCAN COMPARISON REPORT")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Scan 1 ID: {comparison.scan1_id}")
        lines.append(f"Scan 1 Time: {comparison.scan1_timestamp}")
        lines.append(f"Scan 1 Open Ports: {comparison.scan1_open_count}")
        lines.append("")
        lines.append(f"Scan 2 ID: {comparison.scan2_id}")
        lines.append(f"Scan 2 Time: {comparison.scan2_timestamp}")
        lines.append(f"Scan 2 Open Ports: {comparison.scan2_open_count}")
        lines.append("")
        lines.append(f"Target: {comparison.scan1_target}")
        lines.append(f"Change in Open Ports: {comparison.open_diff:+d}")
        lines.append(f"Total Changes: {comparison.total_changes}")
        lines.append("")
        
        if comparison.newly_opened:
            lines.append("NEWLY OPENED PORTS:")
            lines.append("-" * 70)
            for diff in comparison.newly_opened:
                service = diff.service_new or "unknown"
                lines.append(f"  {diff.port}/{diff.protocol} - {service}")
                lines.append(f"    Changed from: {diff.old_state} -> {diff.new_state}")
            lines.append("")
        
        if comparison.newly_closed:
            lines.append("NEWLY CLOSED PORTS:")
            lines.append("-" * 70)
            for diff in comparison.newly_closed:
                service = diff.service_old or "unknown"
                lines.append(f"  {diff.port}/{diff.protocol} - {service}")
                lines.append(f"    Changed from: {diff.old_state} -> {diff.new_state}")
            lines.append("")
        
        if comparison.newly_filtered:
            lines.append("NEWLY FILTERED PORTS:")
            lines.append("-" * 70)
            for diff in comparison.newly_filtered:
                lines.append(f"  {diff.port}/{diff.protocol}")
                lines.append(f"    Changed from: {diff.old_state} -> {diff.new_state}")
            lines.append("")
        
        if comparison.service_changed:
            lines.append("SERVICE CHANGES:")
            lines.append("-" * 70)
            for diff in comparison.service_changed:
                lines.append(f"  {diff.port}/{diff.protocol}")
                lines.append(f"    Service: {diff.service_old} -> {diff.service_new}")
            lines.append("")
        
        if not comparison.total_changes:
            lines.append("No changes detected between scans.")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def compare_by_target(
        self,
        target: str,
        limit: int = 2
    ) -> Optional[ScanComparison]:
        """
        Compare the two most recent scans for a target.
        
        Args:
            target: Target to compare
            limit: Number of recent scans to consider (default 2)
        
        Returns:
            ScanComparison or None if not enough scans found
        """
        entries = self.history_manager.list_entries(
            limit=limit,
            target_filter=target
        )
        
        if len(entries) < 2:
            return None
        
        # Compare most recent two scans
        return self.compare_scans(entries[1].id, entries[0].id)
