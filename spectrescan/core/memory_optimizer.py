"""
Memory Optimization
Stream results, connection pooling limits, garbage collection, large scan support.

Author: BitSpectreLabs
License: MIT
"""

import gc
import logging
import psutil
from dataclasses import dataclass
from typing import Optional, Iterator, Any, List
from pathlib import Path
import json

logger = logging.getLogger(__name__)


@dataclass
class MemoryStats:
    """Memory usage statistics."""
    rss_mb: float  # Resident Set Size in MB
    vms_mb: float  # Virtual Memory Size in MB
    percent: float  # Memory usage percentage
    available_mb: float  # Available memory in MB


class MemoryMonitor:
    """Monitor and manage memory usage."""
    
    def __init__(self, max_memory_mb: Optional[int] = None):
        """
        Initialize memory monitor.
        
        Args:
            max_memory_mb: Maximum memory limit in MB (None = no limit)
        """
        self.max_memory_mb = max_memory_mb
        self.process = psutil.Process()
        self.initial_memory = self.get_memory_usage()
        
        if max_memory_mb:
            logger.info(f"Memory limit set to {max_memory_mb} MB")
    
    def get_memory_usage(self) -> MemoryStats:
        """Get current memory usage statistics."""
        memory_info = self.process.memory_info()
        system_memory = psutil.virtual_memory()
        
        return MemoryStats(
            rss_mb=memory_info.rss / 1024 / 1024,
            vms_mb=memory_info.vms / 1024 / 1024,
            percent=self.process.memory_percent(),
            available_mb=system_memory.available / 1024 / 1024
        )
    
    def check_memory_limit(self) -> bool:
        """
        Check if memory usage exceeds limit.
        
        Returns:
            True if within limit, False if exceeded
        """
        if not self.max_memory_mb:
            return True
        
        stats = self.get_memory_usage()
        if stats.rss_mb > self.max_memory_mb:
            logger.warning(f"Memory limit exceeded: {stats.rss_mb:.1f} MB > {self.max_memory_mb} MB")
            return False
        
        return True
    
    def force_gc(self) -> int:
        """
        Force garbage collection.
        
        Returns:
            Number of objects collected
        """
        before = self.get_memory_usage()
        collected = gc.collect()
        after = self.get_memory_usage()
        
        freed_mb = before.rss_mb - after.rss_mb
        if freed_mb > 1:
            logger.info(f"GC freed {freed_mb:.1f} MB, collected {collected} objects")
        
        return collected
    
    def get_memory_summary(self) -> dict:
        """Get memory usage summary."""
        current = self.get_memory_usage()
        delta_mb = current.rss_mb - self.initial_memory.rss_mb
        
        return {
            "current_mb": round(current.rss_mb, 2),
            "initial_mb": round(self.initial_memory.rss_mb, 2),
            "delta_mb": round(delta_mb, 2),
            "percent": round(current.percent, 2),
            "available_mb": round(current.available_mb, 2),
            "limit_mb": self.max_memory_mb
        }


class StreamingResultWriter:
    """
    Stream scan results to disk instead of accumulating in memory.
    Supports large scans (100K+ ports).
    """
    
    def __init__(self, output_path: Optional[Path] = None):
        """
        Initialize streaming writer.
        
        Args:
            output_path: Path to write results (None = in-memory only)
        """
        self.output_path = output_path
        self.file_handle = None
        self.result_count = 0
        
        if output_path:
            self.file_handle = open(output_path, 'w')
            self.file_handle.write('[\n')  # Start JSON array
            logger.info(f"Streaming results to {output_path}")
    
    def write_result(self, result: Any) -> None:
        """
        Write a single result to stream.
        
        Args:
            result: Scan result to write
        """
        if not self.file_handle:
            return
        
        # Write comma separator if not first result
        if self.result_count > 0:
            self.file_handle.write(',\n')
        
        # Convert result to JSON
        if hasattr(result, '__dict__'):
            result_dict = result.__dict__
        else:
            result_dict = result
        
        json.dump(result_dict, self.file_handle, default=str, indent=2)
        self.result_count += 1
        
        # Flush periodically
        if self.result_count % 100 == 0:
            self.file_handle.flush()
    
    def write_batch(self, results: List[Any]) -> None:
        """Write a batch of results."""
        for result in results:
            self.write_result(result)
    
    def close(self) -> None:
        """Close the stream."""
        if self.file_handle:
            self.file_handle.write('\n]\n')  # End JSON array
            self.file_handle.close()
            logger.info(f"Wrote {self.result_count} results to {self.output_path}")


class ResultIterator:
    """
    Iterator for scan results that yields results one at a time.
    Prevents memory accumulation for large scans.
    """
    
    def __init__(self, scan_function, *args, **kwargs):
        """
        Initialize result iterator.
        
        Args:
            scan_function: Async function that yields results
            *args, **kwargs: Arguments to pass to scan function
        """
        self.scan_function = scan_function
        self.args = args
        self.kwargs = kwargs
    
    async def __aiter__(self):
        """Async iterator protocol."""
        async for result in self.scan_function(*self.args, **self.kwargs):
            yield result


class MemoryOptimizedScanner:
    """
    Scanner optimized for low memory usage.
    Suitable for large scans (65K ports, multiple hosts).
    """
    
    def __init__(
        self,
        max_memory_mb: Optional[int] = 2048,
        gc_interval: int = 1000,
        stream_results: bool = True
    ):
        """
        Initialize memory-optimized scanner.
        
        Args:
            max_memory_mb: Maximum memory limit in MB
            gc_interval: Trigger GC every N results
            stream_results: Stream results to disk instead of memory
        """
        self.memory_monitor = MemoryMonitor(max_memory_mb)
        self.gc_interval = gc_interval
        self.stream_results = stream_results
        self.result_count = 0
        
        # Disable automatic GC for better control
        gc.disable()
        
        logger.info(f"MemoryOptimizedScanner initialized: max_memory={max_memory_mb}MB, stream={stream_results}")
    
    async def scan_with_streaming(
        self,
        scanner,
        *args,
        output_path: Optional[Path] = None,
        **kwargs
    ) -> Iterator[Any]:
        """
        Scan with memory streaming.
        
        Args:
            scanner: Scanner instance
            output_path: Optional path to stream results
            *args, **kwargs: Scanner arguments
        
        Yields:
            Scan results one at a time
        """
        writer = StreamingResultWriter(output_path) if self.stream_results else None
        
        try:
            async for result in scanner.scan_ports(*args, **kwargs):
                # Write to stream if enabled
                if writer:
                    writer.write_result(result)
                
                # Yield result
                yield result
                
                self.result_count += 1
                
                # Periodic GC
                if self.result_count % self.gc_interval == 0:
                    self._check_and_cleanup()
        
        finally:
            if writer:
                writer.close()
            
            # Final cleanup
            self._check_and_cleanup(force=True)
    
    def _check_and_cleanup(self, force: bool = False) -> None:
        """Check memory usage and cleanup if needed."""
        stats = self.memory_monitor.get_memory_usage()
        
        # Log memory stats
        if force or stats.rss_mb > 500:
            logger.debug(f"Memory: {stats.rss_mb:.1f} MB ({stats.percent:.1f}%)")
        
        # Check limit
        if not self.memory_monitor.check_memory_limit():
            logger.warning("Memory limit exceeded, forcing GC")
            force = True
        
        # Force GC if needed
        if force or stats.rss_mb > 1000:
            self.memory_monitor.force_gc()
    
    def get_stats(self) -> dict:
        """Get scanner statistics."""
        return {
            "results_processed": self.result_count,
            "memory": self.memory_monitor.get_memory_summary(),
            "gc_count": gc.get_count()
        }
    
    def __del__(self):
        """Cleanup on deletion."""
        gc.enable()  # Re-enable automatic GC


class ChunkedResultProcessor:
    """
    Process results in chunks to limit memory usage.
    Useful for post-scan processing.
    """
    
    def __init__(self, chunk_size: int = 1000):
        """
        Initialize chunked processor.
        
        Args:
            chunk_size: Number of results to process at once
        """
        self.chunk_size = chunk_size
    
    def process_chunks(
        self,
        results: List[Any],
        processor_func,
        **kwargs
    ) -> List[Any]:
        """
        Process results in chunks.
        
        Args:
            results: List of results
            processor_func: Function to process each chunk
            **kwargs: Additional arguments for processor
        
        Returns:
            Processed results
        """
        processed = []
        
        for i in range(0, len(results), self.chunk_size):
            chunk = results[i:i + self.chunk_size]
            
            # Process chunk
            chunk_results = processor_func(chunk, **kwargs)
            processed.extend(chunk_results)
            
            # Cleanup
            del chunk
            if i % (self.chunk_size * 10) == 0:
                gc.collect()
        
        return processed


def optimize_memory_settings() -> dict:
    """
    Get recommended memory settings based on system resources.
    
    Returns:
        Dictionary of recommended settings
    """
    system_memory = psutil.virtual_memory()
    available_mb = system_memory.available / 1024 / 1024
    total_mb = system_memory.total / 1024 / 1024
    
    # Use 50% of available memory as limit
    recommended_limit = int(available_mb * 0.5)
    
    # GC interval based on memory
    if recommended_limit < 512:
        gc_interval = 500
    elif recommended_limit < 2048:
        gc_interval = 1000
    else:
        gc_interval = 2000
    
    return {
        "max_memory_mb": recommended_limit,
        "gc_interval": gc_interval,
        "stream_results": total_mb < 8192,  # Stream if < 8GB RAM
        "system_info": {
            "total_mb": round(total_mb, 2),
            "available_mb": round(available_mb, 2),
            "percent_used": round(system_memory.percent, 2)
        }
    }
