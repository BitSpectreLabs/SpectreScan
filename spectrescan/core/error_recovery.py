"""
Error Recovery
Retry logic, graceful degradation, partial result preservation, resume capability.

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import logging
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional, Callable, Any, List
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels."""
    RECOVERABLE = "recoverable"  # Can retry
    DEGRADED = "degraded"  # Continue with reduced functionality
    FATAL = "fatal"  # Must abort


@dataclass
class ErrorContext:
    """Context information for an error."""
    error_type: str
    error_message: str
    severity: ErrorSeverity
    timestamp: float
    retry_count: int
    max_retries: int
    context: dict


class RetryStrategy:
    """Retry strategy with exponential backoff."""
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
        jitter: bool = True
    ):
        """
        Initialize retry strategy.
        
        Args:
            max_retries: Maximum number of retry attempts
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            exponential_base: Base for exponential backoff
            jitter: Add random jitter to delay
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def get_delay(self, retry_count: int) -> float:
        """
        Calculate delay for retry attempt.
        
        Args:
            retry_count: Current retry count (0-indexed)
        
        Returns:
            Delay in seconds
        """
        # Exponential backoff
        delay = min(
            self.base_delay * (self.exponential_base ** retry_count),
            self.max_delay
        )
        
        # Add jitter (±20%)
        if self.jitter:
            import random
            jitter_factor = random.uniform(0.8, 1.2)
            delay *= jitter_factor
        
        return delay
    
    def should_retry(self, retry_count: int, error: Exception) -> bool:
        """
        Determine if operation should be retried.
        
        Args:
            retry_count: Current retry count
            error: Exception that occurred
        
        Returns:
            True if should retry
        """
        # Don't retry if max retries exceeded
        if retry_count >= self.max_retries:
            return False
        
        # Retry on specific errors
        retryable_errors = (
            ConnectionError,
            TimeoutError,
            OSError,
            asyncio.TimeoutError
        )
        
        return isinstance(error, retryable_errors)


async def retry_async(
    func: Callable,
    *args,
    strategy: Optional[RetryStrategy] = None,
    on_retry: Optional[Callable] = None,
    **kwargs
) -> Any:
    """
    Retry an async function with exponential backoff.
    
    Args:
        func: Async function to retry
        strategy: Retry strategy (default if None)
        on_retry: Callback on retry (called with error, retry_count)
        *args, **kwargs: Arguments for func
    
    Returns:
        Result from func
    
    Raises:
        Last exception if all retries failed
    """
    if strategy is None:
        strategy = RetryStrategy()
    
    retry_count = 0
    last_error = None
    
    while retry_count <= strategy.max_retries:
        try:
            return await func(*args, **kwargs)
        
        except Exception as e:
            last_error = e
            
            if not strategy.should_retry(retry_count, e):
                logger.error(f"Non-retryable error: {e}")
                raise
            
            if retry_count >= strategy.max_retries:
                logger.error(f"Max retries ({strategy.max_retries}) exceeded")
                raise
            
            # Calculate delay
            delay = strategy.get_delay(retry_count)
            
            logger.warning(
                f"Retry {retry_count + 1}/{strategy.max_retries} after {delay:.1f}s: {e}"
            )
            
            # Call retry callback
            if on_retry:
                on_retry(e, retry_count)
            
            # Wait before retry
            await asyncio.sleep(delay)
            retry_count += 1
    
    # Should never reach here, but just in case
    raise last_error


class PartialResultsManager:
    """
    Manage partial scan results.
    Allows preserving results even if scan is interrupted.
    """
    
    def __init__(self, checkpoint_dir: Optional[Path] = None):
        """
        Initialize partial results manager.
        
        Args:
            checkpoint_dir: Directory to save checkpoints
        """
        self.checkpoint_dir = checkpoint_dir or Path.home() / ".spectrescan" / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        self.results = []
        self.metadata = {}
        self.last_checkpoint = None
        
        logger.info(f"Partial results: {self.checkpoint_dir}")
    
    def add_result(self, result: Any) -> None:
        """Add a result to partial results."""
        self.results.append(result)
    
    def add_results(self, results: List[Any]) -> None:
        """Add multiple results."""
        self.results.extend(results)
    
    def set_metadata(self, key: str, value: Any) -> None:
        """Set metadata for scan."""
        self.metadata[key] = value
    
    def save_checkpoint(self, scan_id: str) -> Path:
        """
        Save checkpoint to disk.
        
        Args:
            scan_id: Unique scan identifier
        
        Returns:
            Path to checkpoint file
        """
        checkpoint_path = self.checkpoint_dir / f"{scan_id}.json"
        
        # Convert results to dicts
        results_data = []
        for result in self.results:
            if hasattr(result, '__dict__'):
                results_data.append(asdict(result) if hasattr(result, '__dataclass_fields__') else result.__dict__)
            else:
                results_data.append(result)
        
        # Save checkpoint
        checkpoint = {
            "scan_id": scan_id,
            "timestamp": time.time(),
            "metadata": self.metadata,
            "results": results_data,
            "result_count": len(results_data)
        }
        
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint, f, default=str, indent=2)
        
        self.last_checkpoint = checkpoint_path
        logger.info(f"Saved checkpoint: {checkpoint_path} ({len(results_data)} results)")
        
        return checkpoint_path
    
    def load_checkpoint(self, scan_id: str) -> dict:
        """
        Load checkpoint from disk.
        
        Args:
            scan_id: Unique scan identifier
        
        Returns:
            Checkpoint data
        """
        checkpoint_path = self.checkpoint_dir / f"{scan_id}.json"
        
        if not checkpoint_path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
        
        with open(checkpoint_path, 'r') as f:
            checkpoint = json.load(f)
        
        logger.info(f"Loaded checkpoint: {checkpoint_path} ({checkpoint['result_count']} results)")
        
        return checkpoint
    
    def list_checkpoints(self) -> List[dict]:
        """List all available checkpoints."""
        checkpoints = []
        
        for checkpoint_file in self.checkpoint_dir.glob("*.json"):
            try:
                with open(checkpoint_file, 'r') as f:
                    data = json.load(f)
                    checkpoints.append({
                        "scan_id": data["scan_id"],
                        "timestamp": data["timestamp"],
                        "result_count": data["result_count"],
                        "path": str(checkpoint_file)
                    })
            except Exception as e:
                logger.warning(f"Failed to load checkpoint {checkpoint_file}: {e}")
        
        return sorted(checkpoints, key=lambda x: x["timestamp"], reverse=True)
    
    def delete_checkpoint(self, scan_id: str) -> None:
        """Delete a checkpoint."""
        checkpoint_path = self.checkpoint_dir / f"{scan_id}.json"
        
        if checkpoint_path.exists():
            checkpoint_path.unlink()
            logger.info(f"Deleted checkpoint: {checkpoint_path}")


class ResumableScanner:
    """
    Scanner with resume capability.
    Can resume interrupted scans from checkpoint.
    """
    
    def __init__(
        self,
        scan_id: str,
        checkpoint_interval: int = 1000
    ):
        """
        Initialize resumable scanner.
        
        Args:
            scan_id: Unique scan identifier
            checkpoint_interval: Save checkpoint every N results
        """
        self.scan_id = scan_id
        self.checkpoint_interval = checkpoint_interval
        self.results_manager = PartialResultsManager()
        self.result_count = 0
        self.completed_ports = set()
        
        logger.info(f"ResumableScanner: {scan_id}, checkpoint every {checkpoint_interval} results")
    
    async def scan_with_resume(
        self,
        scanner,
        ports: List[int],
        *args,
        **kwargs
    ):
        """
        Scan with resume capability.
        
        Args:
            scanner: Scanner instance
            ports: List of ports to scan
            *args, **kwargs: Scanner arguments
        
        Yields:
            Scan results
        """
        # Try to load checkpoint
        try:
            checkpoint = self.results_manager.load_checkpoint(self.scan_id)
            
            # Extract completed ports from results
            for result in checkpoint["results"]:
                if "port" in result:
                    self.completed_ports.add(result["port"])
            
            # Restore metadata
            self.results_manager.metadata = checkpoint["metadata"]
            self.result_count = checkpoint["result_count"]
            
            logger.info(f"Resuming scan: {len(self.completed_ports)} ports already completed")
        
        except FileNotFoundError:
            logger.info("No checkpoint found, starting fresh scan")
        
        # Filter out completed ports
        remaining_ports = [p for p in ports if p not in self.completed_ports]
        
        if not remaining_ports:
            logger.info("All ports already scanned")
            return
        
        logger.info(f"Scanning {len(remaining_ports)} remaining ports")
        
        # Scan remaining ports
        try:
            async for result in scanner.scan_ports(*args, ports=remaining_ports, **kwargs):
                # Add to results
                self.results_manager.add_result(result)
                self.result_count += 1
                
                # Mark port as completed
                if hasattr(result, 'port'):
                    self.completed_ports.add(result.port)
                
                # Checkpoint periodically
                if self.result_count % self.checkpoint_interval == 0:
                    self.results_manager.save_checkpoint(self.scan_id)
                
                yield result
        
        finally:
            # Save final checkpoint
            self.results_manager.save_checkpoint(self.scan_id)


class GracefulDegradation:
    """
    Implement graceful degradation strategies.
    Continue scanning with reduced features on errors.
    """
    
    def __init__(self):
        """Initialize graceful degradation manager."""
        self.degraded_features = set()
        self.error_counts = {}
        self.degradation_threshold = 10  # Disable feature after N errors
    
    def record_error(self, feature: str, error: Exception) -> bool:
        """
        Record an error for a feature.
        
        Args:
            feature: Feature name
            error: Exception that occurred
        
        Returns:
            True if feature should be degraded
        """
        if feature not in self.error_counts:
            self.error_counts[feature] = 0
        
        self.error_counts[feature] += 1
        
        if self.error_counts[feature] >= self.degradation_threshold:
            self.degrade_feature(feature)
            return True
        
        return False
    
    def degrade_feature(self, feature: str) -> None:
        """
        Degrade a feature.
        
        Args:
            feature: Feature to degrade
        """
        if feature not in self.degraded_features:
            self.degraded_features.add(feature)
            logger.warning(f"Feature degraded due to errors: {feature}")
    
    def is_degraded(self, feature: str) -> bool:
        """Check if feature is degraded."""
        return feature in self.degraded_features
    
    def restore_feature(self, feature: str) -> None:
        """Restore a degraded feature."""
        if feature in self.degraded_features:
            self.degraded_features.discard(feature)
            self.error_counts[feature] = 0
            logger.info(f"Feature restored: {feature}")
    
    def get_status(self) -> dict:
        """Get degradation status."""
        return {
            "degraded_features": list(self.degraded_features),
            "error_counts": self.error_counts,
            "threshold": self.degradation_threshold
        }
