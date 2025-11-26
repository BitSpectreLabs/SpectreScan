"""
Scan Resume/Checkpoint Module for SpectreScan.

Provides checkpoint functionality for resuming interrupted scans:
- CheckpointData dataclass for scan state serialization
- CheckpointManager for save/load/cleanup operations
- Signal handling for graceful interrupts
- Periodic auto-save during long scans

by BitSpectreLabs
"""

import json
import signal
import hashlib
import threading
import atexit
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Callable, Set
from enum import Enum


class CheckpointState(str, Enum):
    """Checkpoint state enumeration."""
    RUNNING = "running"
    PAUSED = "paused"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanProgress:
    """Track scan progress for checkpoint."""
    total_targets: int = 0
    completed_targets: int = 0
    total_ports: int = 0
    completed_ports: int = 0
    current_target: Optional[str] = None
    current_port: Optional[int] = None
    start_time: Optional[str] = None
    last_update: Optional[str] = None
    elapsed_seconds: float = 0.0
    estimated_remaining_seconds: Optional[float] = None
    scan_rate_per_second: float = 0.0
    
    @property
    def target_percent(self) -> float:
        """Get target completion percentage."""
        if self.total_targets == 0:
            return 0.0
        return (self.completed_targets / self.total_targets) * 100
    
    @property
    def port_percent(self) -> float:
        """Get port completion percentage."""
        if self.total_ports == 0:
            return 0.0
        return (self.completed_ports / self.total_ports) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanProgress":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class CheckpointData:
    """
    Complete checkpoint data for scan resumption.
    
    Contains all information needed to resume an interrupted scan.
    """
    # Checkpoint metadata
    checkpoint_id: str = ""
    checkpoint_version: str = "1.0"
    created_at: str = ""
    updated_at: str = ""
    state: CheckpointState = CheckpointState.RUNNING
    
    # Scan configuration
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    scan_type: str = "tcp"
    threads: int = 100
    timeout: float = 2.0
    rate_limit: Optional[int] = None
    randomize: bool = False
    
    # Feature flags
    enable_service_detection: bool = True
    enable_os_detection: bool = False
    enable_banner_grabbing: bool = True
    enable_ssl_analysis: bool = False
    enable_cve_matching: bool = False
    
    # Progress tracking
    progress: ScanProgress = field(default_factory=ScanProgress)
    
    # Completed work - track what's done
    completed_targets: Set[str] = field(default_factory=set)
    completed_ports_per_target: Dict[str, Set[int]] = field(default_factory=dict)
    
    # Partial results
    results: List[Dict[str, Any]] = field(default_factory=list)
    host_info: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Error tracking
    errors: List[Dict[str, str]] = field(default_factory=list)
    retry_queue: List[Dict[str, Any]] = field(default_factory=list)
    
    # Output configuration
    output_file: Optional[str] = None
    output_format: str = "json"
    
    def generate_id(self) -> str:
        """Generate unique checkpoint ID based on scan parameters."""
        content = f"{sorted(self.targets)}{sorted(self.ports)}{self.scan_type}{self.created_at}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert checkpoint to dictionary for serialization."""
        data = {
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_version": self.checkpoint_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "state": self.state.value if isinstance(self.state, CheckpointState) else self.state,
            "targets": self.targets,
            "ports": self.ports,
            "scan_type": self.scan_type,
            "threads": self.threads,
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "randomize": self.randomize,
            "enable_service_detection": self.enable_service_detection,
            "enable_os_detection": self.enable_os_detection,
            "enable_banner_grabbing": self.enable_banner_grabbing,
            "enable_ssl_analysis": self.enable_ssl_analysis,
            "enable_cve_matching": self.enable_cve_matching,
            "progress": self.progress.to_dict(),
            "completed_targets": list(self.completed_targets),
            "completed_ports_per_target": {
                k: list(v) for k, v in self.completed_ports_per_target.items()
            },
            "results": self.results,
            "host_info": self.host_info,
            "errors": self.errors,
            "retry_queue": self.retry_queue,
            "output_file": self.output_file,
            "output_format": self.output_format,
        }
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckpointData":
        """Create checkpoint from dictionary."""
        # Handle progress
        progress_data = data.get("progress", {})
        progress = ScanProgress.from_dict(progress_data) if progress_data else ScanProgress()
        
        # Handle state enum
        state = data.get("state", "running")
        if isinstance(state, str):
            state = CheckpointState(state)
        
        # Handle sets
        completed_targets = set(data.get("completed_targets", []))
        completed_ports = {
            k: set(v) for k, v in data.get("completed_ports_per_target", {}).items()
        }
        
        return cls(
            checkpoint_id=data.get("checkpoint_id", ""),
            checkpoint_version=data.get("checkpoint_version", "1.0"),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            state=state,
            targets=data.get("targets", []),
            ports=data.get("ports", []),
            scan_type=data.get("scan_type", "tcp"),
            threads=data.get("threads", 100),
            timeout=data.get("timeout", 2.0),
            rate_limit=data.get("rate_limit"),
            randomize=data.get("randomize", False),
            enable_service_detection=data.get("enable_service_detection", True),
            enable_os_detection=data.get("enable_os_detection", False),
            enable_banner_grabbing=data.get("enable_banner_grabbing", True),
            enable_ssl_analysis=data.get("enable_ssl_analysis", False),
            enable_cve_matching=data.get("enable_cve_matching", False),
            progress=progress,
            completed_targets=completed_targets,
            completed_ports_per_target=completed_ports,
            results=data.get("results", []),
            host_info=data.get("host_info", {}),
            errors=data.get("errors", []),
            retry_queue=data.get("retry_queue", []),
            output_file=data.get("output_file"),
            output_format=data.get("output_format", "json"),
        )
    
    def get_remaining_targets(self) -> List[str]:
        """Get list of targets that haven't been fully scanned."""
        return [t for t in self.targets if t not in self.completed_targets]
    
    def get_remaining_ports(self, target: str) -> List[int]:
        """Get list of ports not yet scanned for a target."""
        completed = self.completed_ports_per_target.get(target, set())
        return [p for p in self.ports if p not in completed]
    
    def mark_port_complete(self, target: str, port: int) -> None:
        """Mark a port as scanned for a target."""
        if target not in self.completed_ports_per_target:
            self.completed_ports_per_target[target] = set()
        self.completed_ports_per_target[target].add(port)
        self.progress.completed_ports += 1
        self.progress.current_port = port
    
    def mark_target_complete(self, target: str) -> None:
        """Mark a target as fully scanned."""
        self.completed_targets.add(target)
        self.progress.completed_targets += 1
        self.progress.current_target = None
    
    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a scan result."""
        self.results.append(result)
    
    def add_error(self, target: str, port: int, error: str) -> None:
        """Record an error during scanning."""
        self.errors.append({
            "target": target,
            "port": port,
            "error": error,
            "timestamp": datetime.now().isoformat()
        })
    
    def add_to_retry_queue(self, target: str, port: int, reason: str) -> None:
        """Add a failed scan to retry queue."""
        self.retry_queue.append({
            "target": target,
            "port": port,
            "reason": reason,
            "attempts": 0
        })


class CheckpointManager:
    """
    Manager for scan checkpoints.
    
    Handles:
    - Checkpoint file I/O (save/load)
    - Auto-save with configurable intervals
    - Signal handling for graceful interrupts
    - Checkpoint cleanup
    - Listing and managing checkpoint files
    """
    
    DEFAULT_CHECKPOINT_DIR = Path.home() / ".spectrescan" / "checkpoints"
    DEFAULT_AUTOSAVE_INTERVAL = 30  # seconds
    
    def __init__(
        self,
        checkpoint_dir: Optional[Path] = None,
        autosave_interval: int = DEFAULT_AUTOSAVE_INTERVAL,
        enable_signal_handlers: bool = True
    ):
        """
        Initialize CheckpointManager.
        
        Args:
            checkpoint_dir: Directory for checkpoint files
            autosave_interval: Seconds between auto-saves (0 to disable)
            enable_signal_handlers: Whether to install signal handlers
        """
        self.checkpoint_dir = checkpoint_dir or self.DEFAULT_CHECKPOINT_DIR
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        self.autosave_interval = autosave_interval
        self.enable_signal_handlers = enable_signal_handlers
        
        # Current checkpoint state
        self._current_checkpoint: Optional[CheckpointData] = None
        self._checkpoint_file: Optional[Path] = None
        
        # Auto-save timer
        self._autosave_timer: Optional[threading.Timer] = None
        self._autosave_lock = threading.Lock()
        self._autosave_enabled = False
        
        # Signal handling
        self._original_sigint: Optional[Any] = None
        self._original_sigterm: Optional[Any] = None
        self._interrupt_callback: Optional[Callable] = None
        
        # Register cleanup on exit
        atexit.register(self._cleanup)
    
    def create_checkpoint(
        self,
        targets: List[str],
        ports: List[int],
        scan_type: str = "tcp",
        **kwargs
    ) -> CheckpointData:
        """
        Create a new checkpoint for a scan.
        
        Args:
            targets: List of scan targets
            ports: List of ports to scan
            scan_type: Type of scan (tcp, syn, udp, async)
            **kwargs: Additional scan configuration
        
        Returns:
            New CheckpointData instance
        """
        now = datetime.now().isoformat()
        
        checkpoint = CheckpointData(
            created_at=now,
            updated_at=now,
            state=CheckpointState.RUNNING,
            targets=targets,
            ports=ports,
            scan_type=scan_type,
            threads=kwargs.get("threads", 100),
            timeout=kwargs.get("timeout", 2.0),
            rate_limit=kwargs.get("rate_limit"),
            randomize=kwargs.get("randomize", False),
            enable_service_detection=kwargs.get("enable_service_detection", True),
            enable_os_detection=kwargs.get("enable_os_detection", False),
            enable_banner_grabbing=kwargs.get("enable_banner_grabbing", True),
            enable_ssl_analysis=kwargs.get("enable_ssl_analysis", False),
            enable_cve_matching=kwargs.get("enable_cve_matching", False),
            output_file=kwargs.get("output_file"),
            output_format=kwargs.get("output_format", "json"),
        )
        
        # Set up progress
        checkpoint.progress.total_targets = len(targets)
        checkpoint.progress.total_ports = len(targets) * len(ports)
        checkpoint.progress.start_time = now
        
        # Generate ID
        checkpoint.checkpoint_id = checkpoint.generate_id()
        
        # Store as current
        self._current_checkpoint = checkpoint
        self._checkpoint_file = self.checkpoint_dir / f"{checkpoint.checkpoint_id}.json"
        
        # Install signal handlers
        if self.enable_signal_handlers:
            self._install_signal_handlers()
        
        # Start auto-save
        if self.autosave_interval > 0:
            self._start_autosave()
        
        # Initial save
        self.save_checkpoint(checkpoint)
        
        return checkpoint
    
    def save_checkpoint(
        self,
        checkpoint: Optional[CheckpointData] = None,
        file_path: Optional[Path] = None
    ) -> Path:
        """
        Save checkpoint to file.
        
        Args:
            checkpoint: Checkpoint to save (uses current if None)
            file_path: Custom file path (uses default if None)
        
        Returns:
            Path to saved checkpoint file
        """
        checkpoint = checkpoint or self._current_checkpoint
        if checkpoint is None:
            raise ValueError("No checkpoint to save")
        
        # Update timestamp
        checkpoint.updated_at = datetime.now().isoformat()
        
        # Determine file path
        if file_path is None:
            file_path = self._checkpoint_file or (
                self.checkpoint_dir / f"{checkpoint.checkpoint_id}.json"
            )
        
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write atomically (write to temp, then rename)
        temp_path = file_path.with_suffix(".tmp")
        try:
            with open(temp_path, "w") as f:
                json.dump(checkpoint.to_dict(), f, indent=2)
            temp_path.replace(file_path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise
        
        return file_path
    
    def load_checkpoint(self, checkpoint_id_or_path: str) -> CheckpointData:
        """
        Load checkpoint from file.
        
        Args:
            checkpoint_id_or_path: Checkpoint ID or file path
        
        Returns:
            Loaded CheckpointData
        """
        # Determine path
        path = Path(checkpoint_id_or_path)
        if not path.is_absolute():
            # Try as checkpoint ID
            path = self.checkpoint_dir / f"{checkpoint_id_or_path}.json"
            if not path.exists():
                # Try as relative path
                path = Path(checkpoint_id_or_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_id_or_path}")
        
        with open(path, "r") as f:
            data = json.load(f)
        
        checkpoint = CheckpointData.from_dict(data)
        
        # Store as current
        self._current_checkpoint = checkpoint
        self._checkpoint_file = path
        
        return checkpoint
    
    def update_progress(
        self,
        target: Optional[str] = None,
        port: Optional[int] = None,
        result: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update checkpoint progress.
        
        Args:
            target: Current target being scanned
            port: Current port being scanned
            result: Scan result to add
        """
        if self._current_checkpoint is None:
            return
        
        checkpoint = self._current_checkpoint
        checkpoint.progress.last_update = datetime.now().isoformat()
        
        if target:
            checkpoint.progress.current_target = target
        
        if port:
            checkpoint.progress.current_port = port
        
        if result:
            checkpoint.add_result(result)
            if target and port:
                checkpoint.mark_port_complete(target, port)
        
        # Calculate elapsed time
        if checkpoint.progress.start_time:
            start = datetime.fromisoformat(checkpoint.progress.start_time)
            elapsed = (datetime.now() - start).total_seconds()
            checkpoint.progress.elapsed_seconds = elapsed
            
            # Calculate scan rate
            if elapsed > 0:
                completed = checkpoint.progress.completed_ports
                checkpoint.progress.scan_rate_per_second = completed / elapsed
                
                # Estimate remaining time
                remaining = checkpoint.progress.total_ports - completed
                if checkpoint.progress.scan_rate_per_second > 0:
                    checkpoint.progress.estimated_remaining_seconds = (
                        remaining / checkpoint.progress.scan_rate_per_second
                    )
    
    def mark_complete(self) -> None:
        """Mark current checkpoint as completed and clean up."""
        if self._current_checkpoint is None:
            return
        
        self._current_checkpoint.state = CheckpointState.COMPLETED
        self._current_checkpoint.updated_at = datetime.now().isoformat()
        
        # Final save
        self.save_checkpoint()
        
        # Stop auto-save
        self._stop_autosave()
        
        # Remove signal handlers
        self._remove_signal_handlers()
    
    def mark_interrupted(self) -> None:
        """Mark current checkpoint as interrupted."""
        if self._current_checkpoint is None:
            return
        
        self._current_checkpoint.state = CheckpointState.INTERRUPTED
        self.save_checkpoint()
    
    def mark_failed(self, error: str) -> None:
        """Mark current checkpoint as failed."""
        if self._current_checkpoint is None:
            return
        
        self._current_checkpoint.state = CheckpointState.FAILED
        self._current_checkpoint.add_error("", 0, error)
        self.save_checkpoint()
    
    def delete_checkpoint(
        self,
        checkpoint_id_or_path: str,
        force: bool = False
    ) -> bool:
        """
        Delete a checkpoint file.
        
        Args:
            checkpoint_id_or_path: Checkpoint ID or file path
            force: Delete even if checkpoint is running
        
        Returns:
            True if deleted, False otherwise
        """
        # Determine path
        path = Path(checkpoint_id_or_path)
        if not path.is_absolute():
            path = self.checkpoint_dir / f"{checkpoint_id_or_path}.json"
            if not path.exists():
                path = Path(checkpoint_id_or_path)
        
        if not path.exists():
            return False
        
        # Check state if not forcing
        if not force:
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                if data.get("state") == CheckpointState.RUNNING.value:
                    return False
            except Exception:
                pass
        
        path.unlink()
        return True
    
    def list_checkpoints(self) -> List[Dict[str, Any]]:
        """
        List all checkpoint files.
        
        Returns:
            List of checkpoint summaries
        """
        checkpoints = []
        
        for path in self.checkpoint_dir.glob("*.json"):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                
                checkpoints.append({
                    "id": data.get("checkpoint_id", path.stem),
                    "state": data.get("state", "unknown"),
                    "targets": data.get("targets", [])[:3],  # First 3 targets
                    "target_count": len(data.get("targets", [])),
                    "port_count": len(data.get("ports", [])),
                    "scan_type": data.get("scan_type", "tcp"),
                    "created_at": data.get("created_at", ""),
                    "updated_at": data.get("updated_at", ""),
                    "progress_percent": self._calculate_progress(data),
                    "file_path": str(path),
                })
            except Exception:
                continue
        
        # Sort by updated_at descending
        checkpoints.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        
        return checkpoints
    
    def cleanup_completed(self, keep_days: int = 7) -> int:
        """
        Clean up old completed checkpoints.
        
        Args:
            keep_days: Keep checkpoints newer than this many days
        
        Returns:
            Number of checkpoints deleted
        """
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=keep_days)
        deleted = 0
        
        for path in self.checkpoint_dir.glob("*.json"):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                
                # Only cleanup completed/failed
                state = data.get("state", "")
                if state not in [CheckpointState.COMPLETED.value, CheckpointState.FAILED.value]:
                    continue
                
                # Check age
                updated = data.get("updated_at", "")
                if updated:
                    updated_dt = datetime.fromisoformat(updated)
                    if updated_dt < cutoff:
                        path.unlink()
                        deleted += 1
            except Exception:
                continue
        
        return deleted
    
    def set_interrupt_callback(self, callback: Callable) -> None:
        """Set callback to be called on interrupt signals."""
        self._interrupt_callback = callback
    
    def get_current_checkpoint(self) -> Optional[CheckpointData]:
        """Get the current active checkpoint."""
        return self._current_checkpoint
    
    def _calculate_progress(self, data: Dict[str, Any]) -> float:
        """Calculate progress percentage from checkpoint data."""
        progress = data.get("progress", {})
        total = progress.get("total_ports", 0)
        completed = progress.get("completed_ports", 0)
        if total == 0:
            return 0.0
        return round((completed / total) * 100, 1)
    
    def _install_signal_handlers(self) -> None:
        """Install signal handlers for graceful interrupt."""
        try:
            self._original_sigint = signal.getsignal(signal.SIGINT)
            self._original_sigterm = signal.getsignal(signal.SIGTERM)
            
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (ValueError, OSError):
            # Signal handling not available (e.g., not main thread)
            pass
    
    def _remove_signal_handlers(self) -> None:
        """Remove signal handlers and restore originals."""
        try:
            if self._original_sigint is not None:
                signal.signal(signal.SIGINT, self._original_sigint)
            if self._original_sigterm is not None:
                signal.signal(signal.SIGTERM, self._original_sigterm)
        except (ValueError, OSError):
            pass
    
    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle interrupt signals."""
        # Mark checkpoint as interrupted
        self.mark_interrupted()
        
        # Stop auto-save
        self._stop_autosave()
        
        # Call user callback
        if self._interrupt_callback:
            self._interrupt_callback()
        
        # Restore original handler and re-raise
        self._remove_signal_handlers()
        
        # Re-raise the signal
        if signum == signal.SIGINT:
            raise KeyboardInterrupt()
        elif signum == signal.SIGTERM:
            raise SystemExit(128 + signum)
    
    def _start_autosave(self) -> None:
        """Start auto-save timer."""
        if self.autosave_interval <= 0:
            return
        
        self._autosave_enabled = True
        self._schedule_autosave()
    
    def _stop_autosave(self) -> None:
        """Stop auto-save timer."""
        self._autosave_enabled = False
        with self._autosave_lock:
            if self._autosave_timer:
                self._autosave_timer.cancel()
                self._autosave_timer = None
    
    def _schedule_autosave(self) -> None:
        """Schedule next auto-save."""
        if not self._autosave_enabled:
            return
        
        with self._autosave_lock:
            self._autosave_timer = threading.Timer(
                self.autosave_interval,
                self._autosave_callback
            )
            self._autosave_timer.daemon = True
            self._autosave_timer.start()
    
    def _autosave_callback(self) -> None:
        """Auto-save callback."""
        try:
            if self._current_checkpoint and self._autosave_enabled:
                self.save_checkpoint()
        except Exception:
            pass
        
        # Schedule next auto-save
        self._schedule_autosave()
    
    def _cleanup(self) -> None:
        """Cleanup on exit."""
        self._stop_autosave()
        self._remove_signal_handlers()


def can_resume_scan(checkpoint: CheckpointData) -> bool:
    """
    Check if a checkpoint can be resumed.
    
    Args:
        checkpoint: Checkpoint to check
    
    Returns:
        True if checkpoint can be resumed
    """
    resumable_states = [
        CheckpointState.RUNNING,
        CheckpointState.PAUSED,
        CheckpointState.INTERRUPTED,
    ]
    return checkpoint.state in resumable_states


def get_resume_summary(checkpoint: CheckpointData) -> Dict[str, Any]:
    """
    Get summary of what will be resumed.
    
    Args:
        checkpoint: Checkpoint to summarize
    
    Returns:
        Summary dictionary
    """
    remaining_targets = checkpoint.get_remaining_targets()
    
    # Calculate remaining ports
    remaining_ports_count = 0
    for target in remaining_targets:
        remaining_ports_count += len(checkpoint.get_remaining_ports(target))
    
    # Add remaining ports for partially completed targets
    for target in checkpoint.targets:
        if target not in checkpoint.completed_targets:
            if target not in remaining_targets:
                remaining_ports_count += len(checkpoint.get_remaining_ports(target))
    
    return {
        "checkpoint_id": checkpoint.checkpoint_id,
        "state": checkpoint.state.value if isinstance(checkpoint.state, CheckpointState) else checkpoint.state,
        "scan_type": checkpoint.scan_type,
        "total_targets": len(checkpoint.targets),
        "remaining_targets": len(remaining_targets),
        "total_ports": checkpoint.progress.total_ports,
        "completed_ports": checkpoint.progress.completed_ports,
        "remaining_ports": remaining_ports_count,
        "results_collected": len(checkpoint.results),
        "errors_encountered": len(checkpoint.errors),
        "elapsed_time": checkpoint.progress.elapsed_seconds,
        "created_at": checkpoint.created_at,
        "last_update": checkpoint.progress.last_update,
    }
