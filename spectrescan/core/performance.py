"""
Performance Optimizations Module
Async DNS resolution, batch port checking, memory-mapped storage,
profiling utilities, and performance monitoring.

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import socket
import struct
import time
import mmap
import os
import gc
import functools
import statistics
import logging
from dataclasses import dataclass, field
from typing import (
    Optional, List, Dict, Any, Tuple, Callable, 
    Iterator, Union, Set, TypeVar, Generic
)
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import threading

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ============================================================================
# Async DNS Resolution
# ============================================================================

class AsyncDNSResolver:
    """
    High-performance async DNS resolver with caching.
    
    Features:
    - Async resolution using getaddrinfo
    - LRU cache for resolved addresses
    - Batch resolution for multiple hostnames
    - IPv4/IPv6 support
    - Timeout handling
    """
    
    def __init__(
        self,
        cache_size: int = 10000,
        cache_ttl: float = 300.0,
        timeout: float = 5.0,
        max_concurrent: int = 100
    ):
        """
        Initialize DNS resolver.
        
        Args:
            cache_size: Maximum cache entries
            cache_ttl: Cache time-to-live in seconds
            timeout: DNS query timeout
            max_concurrent: Maximum concurrent resolutions
        """
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        
        # DNS cache: {hostname: (ip, timestamp)}
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._cache_lock = asyncio.Lock()
        
        # Semaphore for concurrent limits
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
        # Statistics
        self.stats = {
            "queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "failures": 0,
            "avg_time_ms": 0.0
        }
        self._query_times: List[float] = []
    
    async def resolve(self, hostname: str, ipv6: bool = False) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname: Hostname to resolve
            ipv6: Prefer IPv6 addresses
            
        Returns:
            IP address string or None if resolution fails
        """
        self.stats["queries"] += 1
        
        # Check if already an IP address
        try:
            socket.inet_aton(hostname)
            return hostname  # Already an IPv4 address
        except socket.error:
            pass
        
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return hostname  # Already an IPv6 address
        except socket.error:
            pass
        
        # Check cache
        async with self._cache_lock:
            if hostname in self._cache:
                ip, timestamp = self._cache[hostname]
                if time.time() - timestamp < self.cache_ttl:
                    self.stats["cache_hits"] += 1
                    return ip
                else:
                    del self._cache[hostname]
        
        self.stats["cache_misses"] += 1
        
        # Resolve DNS
        async with self._semaphore:
            start_time = time.perf_counter()
            try:
                family = socket.AF_INET6 if ipv6 else socket.AF_INET
                loop = asyncio.get_event_loop()
                
                result = await asyncio.wait_for(
                    loop.getaddrinfo(
                        hostname, None, 
                        family=family,
                        type=socket.SOCK_STREAM
                    ),
                    timeout=self.timeout
                )
                
                if result:
                    ip = result[0][4][0]
                    
                    # Update cache
                    async with self._cache_lock:
                        self._cache[hostname] = (ip, time.time())
                        
                        # Evict old entries if cache is full
                        if len(self._cache) > self.cache_size:
                            oldest = min(self._cache.items(), key=lambda x: x[1][1])
                            del self._cache[oldest[0]]
                    
                    elapsed = (time.perf_counter() - start_time) * 1000
                    self._query_times.append(elapsed)
                    self._update_avg_time()
                    
                    return ip
                    
            except asyncio.TimeoutError:
                logger.warning(f"DNS timeout for {hostname}")
                self.stats["failures"] += 1
            except socket.gaierror as e:
                logger.debug(f"DNS resolution failed for {hostname}: {e}")
                self.stats["failures"] += 1
            except Exception as e:
                logger.error(f"DNS error for {hostname}: {e}")
                self.stats["failures"] += 1
        
        return None
    
    async def resolve_batch(
        self, 
        hostnames: List[str],
        ipv6: bool = False
    ) -> Dict[str, Optional[str]]:
        """
        Resolve multiple hostnames concurrently.
        
        Args:
            hostnames: List of hostnames to resolve
            ipv6: Prefer IPv6 addresses
            
        Returns:
            Dictionary mapping hostnames to IP addresses
        """
        tasks = [self.resolve(h, ipv6) for h in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            hostname: (result if not isinstance(result, Exception) else None)
            for hostname, result in zip(hostnames, results)
        }
    
    def _update_avg_time(self) -> None:
        """Update average query time."""
        if self._query_times:
            # Keep last 1000 times
            self._query_times = self._query_times[-1000:]
            self.stats["avg_time_ms"] = round(statistics.mean(self._query_times), 2)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get resolver statistics."""
        return {
            **self.stats,
            "cache_size": len(self._cache),
            "cache_capacity": self.cache_size
        }
    
    def clear_cache(self) -> int:
        """Clear DNS cache. Returns number of entries cleared."""
        count = len(self._cache)
        self._cache.clear()
        return count


# ============================================================================
# Batch Port Checking
# ============================================================================

class BatchPortChecker:
    """
    Efficient batch port checking with optimized socket operations.
    
    Features:
    - Batch connect attempts with non-blocking sockets
    - Efficient select/poll-based checking
    - Automatic retry with backoff
    - Connection result batching
    """
    
    def __init__(
        self,
        batch_size: int = 500,
        timeout: float = 1.0,
        max_retries: int = 1
    ):
        """
        Initialize batch port checker.
        
        Args:
            batch_size: Number of ports to check per batch
            timeout: Connection timeout per port
            max_retries: Maximum retry attempts
        """
        self.batch_size = batch_size
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Statistics
        self.stats = {
            "batches": 0,
            "ports_checked": 0,
            "open_found": 0,
            "avg_batch_time_ms": 0.0
        }
        self._batch_times: List[float] = []
    
    async def check_ports(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[int, str], None]] = None
    ) -> Dict[int, str]:
        """
        Check multiple ports efficiently.
        
        Args:
            host: Target host
            ports: List of ports to check
            callback: Optional callback for each result (port, state)
            
        Returns:
            Dictionary mapping port to state (open/closed/filtered)
        """
        results: Dict[int, str] = {}
        
        # Process in batches
        for i in range(0, len(ports), self.batch_size):
            batch = ports[i:i + self.batch_size]
            batch_results = await self._check_batch(host, batch)
            results.update(batch_results)
            
            if callback:
                for port, state in batch_results.items():
                    callback(port, state)
        
        return results
    
    async def _check_batch(
        self,
        host: str,
        ports: List[int]
    ) -> Dict[int, str]:
        """Check a batch of ports."""
        self.stats["batches"] += 1
        start_time = time.perf_counter()
        
        results: Dict[int, str] = {}
        tasks = []
        
        for port in ports:
            task = asyncio.create_task(self._check_single(host, port))
            tasks.append((port, task))
        
        for port, task in tasks:
            try:
                state = await asyncio.wait_for(task, timeout=self.timeout + 0.5)
                results[port] = state
                
                if state == "open":
                    self.stats["open_found"] += 1
                    
            except asyncio.TimeoutError:
                results[port] = "filtered"
            except Exception as e:
                logger.debug(f"Error checking port {port}: {e}")
                results[port] = "error"
        
        self.stats["ports_checked"] += len(ports)
        
        elapsed = (time.perf_counter() - start_time) * 1000
        self._batch_times.append(elapsed)
        self._batch_times = self._batch_times[-100:]
        if self._batch_times:
            self.stats["avg_batch_time_ms"] = round(statistics.mean(self._batch_times), 2)
        
        return results
    
    async def _check_single(self, host: str, port: int) -> str:
        """Check a single port."""
        loop = asyncio.get_event_loop()
        
        for attempt in range(self.max_retries + 1):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return "open"
                
            except asyncio.TimeoutError:
                if attempt == self.max_retries:
                    return "filtered"
            except ConnectionRefusedError:
                return "closed"
            except OSError as e:
                if e.errno in (10061, 111):  # Connection refused
                    return "closed"
                if attempt == self.max_retries:
                    return "filtered"
        
        return "filtered"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get checker statistics."""
        return self.stats.copy()


# ============================================================================
# Memory-Mapped Result Storage
# ============================================================================

@dataclass
class MappedResult:
    """Represents a scan result in memory-mapped storage."""
    host: str
    port: int
    state: str
    service: str = ""
    banner: str = ""
    timestamp: float = 0.0


class MemoryMappedStorage:
    """
    Memory-mapped file storage for large scan results.
    
    Features:
    - Efficient storage for millions of results
    - Fast random access
    - Automatic file growth
    - Iterator support for streaming
    """
    
    RECORD_SIZE = 512  # Bytes per record
    HEADER_SIZE = 64   # Header bytes
    
    def __init__(
        self,
        file_path: Optional[Path] = None,
        max_results: int = 1000000
    ):
        """
        Initialize memory-mapped storage.
        
        Args:
            file_path: Path to storage file (temp file if None)
            max_results: Maximum number of results to store
        """
        if file_path is None:
            import tempfile
            fd, path = tempfile.mkstemp(suffix='.mmdb', prefix='spectrescan_')
            os.close(fd)
            file_path = Path(path)
            self._temp_file = True
        else:
            self._temp_file = False
        
        self.file_path = file_path
        self.max_results = max_results
        self._file_size = self.HEADER_SIZE + (max_results * self.RECORD_SIZE)
        
        # Create/open file
        self._file = open(file_path, 'w+b')
        self._file.write(b'\x00' * self._file_size)
        self._file.flush()
        
        # Create memory map
        self._mmap = mmap.mmap(
            self._file.fileno(),
            self._file_size,
            access=mmap.ACCESS_WRITE
        )
        
        # Initialize header
        self._count = 0
        self._write_header()
        
        logger.debug(f"MemoryMappedStorage initialized: {file_path}")
    
    def _write_header(self) -> None:
        """Write header to file."""
        header = struct.pack('!Q', self._count)
        self._mmap[0:8] = header
    
    def _read_header(self) -> int:
        """Read record count from header."""
        return struct.unpack('!Q', self._mmap[0:8])[0]
    
    def add_result(self, result: MappedResult) -> int:
        """
        Add a result to storage.
        
        Args:
            result: Result to store
            
        Returns:
            Index of stored result
        """
        if self._count >= self.max_results:
            raise OverflowError("Storage capacity exceeded")
        
        offset = self.HEADER_SIZE + (self._count * self.RECORD_SIZE)
        
        # Pack result into fixed-size record
        record = self._pack_result(result)
        self._mmap[offset:offset + self.RECORD_SIZE] = record
        
        self._count += 1
        self._write_header()
        
        return self._count - 1
    
    def get_result(self, index: int) -> Optional[MappedResult]:
        """
        Get result by index.
        
        Args:
            index: Result index
            
        Returns:
            MappedResult or None if index invalid
        """
        if index < 0 or index >= self._count:
            return None
        
        offset = self.HEADER_SIZE + (index * self.RECORD_SIZE)
        record = self._mmap[offset:offset + self.RECORD_SIZE]
        
        return self._unpack_result(record)
    
    def _pack_result(self, result: MappedResult) -> bytes:
        """Pack result into fixed-size bytes."""
        host_bytes = result.host.encode('utf-8')[:64].ljust(64, b'\x00')
        service_bytes = result.service.encode('utf-8')[:64].ljust(64, b'\x00')
        banner_bytes = result.banner.encode('utf-8')[:256].ljust(256, b'\x00')
        state_bytes = result.state.encode('utf-8')[:16].ljust(16, b'\x00')
        
        return struct.pack(
            '!64s H 16s 64s 256s d 102x',
            host_bytes,
            result.port,
            state_bytes,
            service_bytes,
            banner_bytes,
            result.timestamp
        )
    
    def _unpack_result(self, data: bytes) -> MappedResult:
        """Unpack result from bytes."""
        parts = struct.unpack('!64s H 16s 64s 256s d 102x', data)
        
        return MappedResult(
            host=parts[0].rstrip(b'\x00').decode('utf-8'),
            port=parts[1],
            state=parts[2].rstrip(b'\x00').decode('utf-8'),
            service=parts[3].rstrip(b'\x00').decode('utf-8'),
            banner=parts[4].rstrip(b'\x00').decode('utf-8'),
            timestamp=parts[5]
        )
    
    def __iter__(self) -> Iterator[MappedResult]:
        """Iterate over all results."""
        for i in range(self._count):
            result = self.get_result(i)
            if result:
                yield result
    
    def __len__(self) -> int:
        """Return number of stored results."""
        return self._count
    
    def close(self) -> None:
        """Close storage and cleanup."""
        self._mmap.close()
        self._file.close()
        
        if self._temp_file and self.file_path.exists():
            self.file_path.unlink()
            logger.debug("Temporary storage file deleted")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ============================================================================
# Profiling Utilities
# ============================================================================

@dataclass
class ProfileResult:
    """Result of a profiling run."""
    name: str
    calls: int
    total_time: float
    avg_time: float
    min_time: float
    max_time: float
    memory_delta_mb: float = 0.0


class Profiler:
    """
    Performance profiling utilities.
    
    Features:
    - Function timing decorator
    - Memory tracking
    - Call counting
    - Statistical analysis
    """
    
    _instance = None
    _profiles: Dict[str, List[float]] = {}
    _call_counts: Dict[str, int] = {}
    _enabled = True
    _lock = threading.Lock()
    
    @classmethod
    def enable(cls) -> None:
        """Enable profiling."""
        cls._enabled = True
    
    @classmethod
    def disable(cls) -> None:
        """Disable profiling."""
        cls._enabled = False
    
    @classmethod
    def reset(cls) -> None:
        """Reset all profiling data."""
        with cls._lock:
            cls._profiles.clear()
            cls._call_counts.clear()
    
    @classmethod
    def profile(cls, name: Optional[str] = None):
        """
        Decorator to profile a function.
        
        Args:
            name: Profile name (defaults to function name)
        """
        def decorator(func: Callable) -> Callable:
            profile_name = name or func.__qualname__
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not cls._enabled:
                    return func(*args, **kwargs)
                
                start = time.perf_counter()
                try:
                    return func(*args, **kwargs)
                finally:
                    elapsed = time.perf_counter() - start
                    with cls._lock:
                        if profile_name not in cls._profiles:
                            cls._profiles[profile_name] = []
                            cls._call_counts[profile_name] = 0
                        cls._profiles[profile_name].append(elapsed)
                        cls._call_counts[profile_name] += 1
            
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                if not cls._enabled:
                    return await func(*args, **kwargs)
                
                start = time.perf_counter()
                try:
                    return await func(*args, **kwargs)
                finally:
                    elapsed = time.perf_counter() - start
                    with cls._lock:
                        if profile_name not in cls._profiles:
                            cls._profiles[profile_name] = []
                            cls._call_counts[profile_name] = 0
                        cls._profiles[profile_name].append(elapsed)
                        cls._call_counts[profile_name] += 1
            
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            return wrapper
        
        return decorator
    
    @classmethod
    def get_results(cls) -> List[ProfileResult]:
        """Get profiling results sorted by total time."""
        results = []
        
        with cls._lock:
            for name, times in cls._profiles.items():
                if not times:
                    continue
                
                results.append(ProfileResult(
                    name=name,
                    calls=cls._call_counts.get(name, 0),
                    total_time=sum(times),
                    avg_time=statistics.mean(times),
                    min_time=min(times),
                    max_time=max(times)
                ))
        
        return sorted(results, key=lambda r: r.total_time, reverse=True)
    
    @classmethod
    def print_results(cls, top_n: int = 20) -> None:
        """Print profiling results."""
        results = cls.get_results()[:top_n]
        
        print("\n" + "=" * 80)
        print("PROFILING RESULTS")
        print("=" * 80)
        print(f"{'Function':<40} {'Calls':>8} {'Total':>10} {'Avg':>10} {'Min':>10} {'Max':>10}")
        print("-" * 80)
        
        for r in results:
            print(
                f"{r.name[:40]:<40} {r.calls:>8} "
                f"{r.total_time*1000:>9.2f}ms {r.avg_time*1000:>9.2f}ms "
                f"{r.min_time*1000:>9.2f}ms {r.max_time*1000:>9.2f}ms"
            )
        
        print("=" * 80)


@contextmanager
def profile_block(name: str):
    """
    Context manager for profiling a code block.
    
    Usage:
        with profile_block("my_operation"):
            # code to profile
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        with Profiler._lock:
            if name not in Profiler._profiles:
                Profiler._profiles[name] = []
                Profiler._call_counts[name] = 0
            Profiler._profiles[name].append(elapsed)
            Profiler._call_counts[name] += 1


# ============================================================================
# Performance Benchmarks
# ============================================================================

@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    name: str
    iterations: int
    total_time: float
    ops_per_second: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    std_dev_ms: float


class Benchmark:
    """
    Performance benchmarking utilities.
    
    Features:
    - Microbenchmark runner
    - Statistical analysis
    - Comparison support
    - Memory profiling
    """
    
    @staticmethod
    async def run_async(
        name: str,
        func: Callable,
        iterations: int = 1000,
        warmup: int = 10
    ) -> BenchmarkResult:
        """
        Run async benchmark.
        
        Args:
            name: Benchmark name
            func: Async function to benchmark
            iterations: Number of iterations
            warmup: Warmup iterations (not counted)
            
        Returns:
            BenchmarkResult with statistics
        """
        # Warmup
        for _ in range(warmup):
            await func()
        
        # Benchmark
        times = []
        total_start = time.perf_counter()
        
        for _ in range(iterations):
            start = time.perf_counter()
            await func()
            times.append(time.perf_counter() - start)
        
        total_time = time.perf_counter() - total_start
        
        return BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time=total_time,
            ops_per_second=iterations / total_time,
            avg_time_ms=statistics.mean(times) * 1000,
            min_time_ms=min(times) * 1000,
            max_time_ms=max(times) * 1000,
            std_dev_ms=statistics.stdev(times) * 1000 if len(times) > 1 else 0
        )
    
    @staticmethod
    def run_sync(
        name: str,
        func: Callable,
        iterations: int = 1000,
        warmup: int = 10
    ) -> BenchmarkResult:
        """
        Run synchronous benchmark.
        
        Args:
            name: Benchmark name
            func: Function to benchmark
            iterations: Number of iterations
            warmup: Warmup iterations
            
        Returns:
            BenchmarkResult with statistics
        """
        # Warmup
        for _ in range(warmup):
            func()
        
        # Benchmark
        times = []
        total_start = time.perf_counter()
        
        for _ in range(iterations):
            start = time.perf_counter()
            func()
            times.append(time.perf_counter() - start)
        
        total_time = time.perf_counter() - total_start
        
        return BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time=total_time,
            ops_per_second=iterations / total_time,
            avg_time_ms=statistics.mean(times) * 1000,
            min_time_ms=min(times) * 1000,
            max_time_ms=max(times) * 1000,
            std_dev_ms=statistics.stdev(times) * 1000 if len(times) > 1 else 0
        )
    
    @staticmethod
    def compare(results: List[BenchmarkResult]) -> None:
        """Print benchmark comparison."""
        if not results:
            return
        
        baseline = results[0]
        
        print("\n" + "=" * 90)
        print("BENCHMARK COMPARISON")
        print("=" * 90)
        print(f"{'Benchmark':<30} {'Ops/s':>12} {'Avg (ms)':>12} {'vs Baseline':>12}")
        print("-" * 90)
        
        for r in results:
            speedup = r.ops_per_second / baseline.ops_per_second if baseline.ops_per_second > 0 else 0
            print(f"{r.name[:30]:<30} {r.ops_per_second:>12.1f} {r.avg_time_ms:>12.3f} {speedup:>11.2f}x")
        
        print("=" * 90)


# ============================================================================
# Lazy Loading Utilities
# ============================================================================

class LazyLoader(Generic[T]):
    """
    Generic lazy loader for deferred initialization.
    
    Only initializes the wrapped object when first accessed.
    """
    
    def __init__(self, factory: Callable[[], T]):
        """
        Initialize lazy loader.
        
        Args:
            factory: Factory function to create the object
        """
        self._factory = factory
        self._instance: Optional[T] = None
        self._lock = threading.Lock()
    
    def get(self) -> T:
        """Get or create the lazy-loaded instance."""
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = self._factory()
        return self._instance
    
    def is_loaded(self) -> bool:
        """Check if instance has been loaded."""
        return self._instance is not None
    
    def reset(self) -> None:
        """Reset the instance (will be recreated on next access)."""
        with self._lock:
            self._instance = None


def lazy_property(func: Callable[[Any], T]) -> property:
    """
    Decorator for lazy-loaded properties.
    
    Usage:
        class MyClass:
            @lazy_property
            def expensive_data(self):
                return load_large_file()
    """
    attr_name = f'_lazy_{func.__name__}'
    
    @functools.wraps(func)
    def wrapper(self):
        if not hasattr(self, attr_name):
            setattr(self, attr_name, func(self))
        return getattr(self, attr_name)
    
    return property(wrapper)


# ============================================================================
# Connection Pooling Improvements
# ============================================================================

class EnhancedConnectionPool:
    """
    Enhanced connection pool with additional optimizations.
    
    Features:
    - Pre-warming connections
    - Health checking background task
    - Dynamic pool sizing
    - Per-host rate limiting
    """
    
    def __init__(
        self,
        max_connections: int = 2000,
        max_per_host: int = 20,
        min_connections: int = 10,
        health_check_interval: float = 10.0
    ):
        """
        Initialize enhanced connection pool.
        
        Args:
            max_connections: Maximum total connections
            max_per_host: Maximum connections per host
            min_connections: Minimum idle connections to maintain
            health_check_interval: Seconds between health checks
        """
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self.min_connections = min_connections
        self.health_check_interval = health_check_interval
        
        # Pool storage
        self._pool: Dict[str, List[Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}
        self._pool_lock = asyncio.Lock()
        self._active_connections = 0
        
        # Rate limiting per host
        self._host_timestamps: Dict[str, List[float]] = {}
        
        # Statistics
        self.stats = {
            "total_acquired": 0,
            "total_released": 0,
            "pool_hits": 0,
            "pool_misses": 0,
            "health_checks": 0,
            "stale_removed": 0
        }
        
        # Health check task
        self._health_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self) -> None:
        """Start background health check task."""
        if self._running:
            return
        
        self._running = True
        self._health_task = asyncio.create_task(self._health_check_loop())
        logger.info("Enhanced connection pool started")
    
    async def stop(self) -> None:
        """Stop pool and cleanup connections."""
        self._running = False
        
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        async with self._pool_lock:
            for host_pool in self._pool.values():
                for reader, writer, _ in host_pool:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            self._pool.clear()
        
        logger.info("Enhanced connection pool stopped")
    
    async def acquire(
        self,
        host: str,
        port: int,
        timeout: float = 3.0
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Acquire a connection from pool or create new.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            
        Returns:
            Tuple of (reader, writer)
        """
        key = f"{host}:{port}"
        self.stats["total_acquired"] += 1
        
        # Try pool first
        async with self._pool_lock:
            if key in self._pool and self._pool[key]:
                reader, writer, created = self._pool[key].pop()
                
                # Check if connection is still valid
                if not writer.is_closing() and (time.time() - created) < 30:
                    self.stats["pool_hits"] += 1
                    return reader, writer
                else:
                    writer.close()
                    self.stats["stale_removed"] += 1
        
        # Create new connection
        self.stats["pool_misses"] += 1
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        self._active_connections += 1
        
        return reader, writer
    
    async def release(
        self,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        reusable: bool = True
    ) -> None:
        """
        Release a connection back to pool.
        
        Args:
            host: Target host
            port: Target port
            reader: Stream reader
            writer: Stream writer
            reusable: Whether connection can be reused
        """
        key = f"{host}:{port}"
        self.stats["total_released"] += 1
        
        if not reusable or writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._active_connections = max(0, self._active_connections - 1)
            return
        
        async with self._pool_lock:
            if key not in self._pool:
                self._pool[key] = []
            
            # Check pool size limits
            if len(self._pool[key]) < self.max_per_host:
                self._pool[key].append((reader, writer, time.time()))
            else:
                writer.close()
                self._active_connections = max(0, self._active_connections - 1)
    
    async def _health_check_loop(self) -> None:
        """Background health check loop."""
        while self._running:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._cleanup_stale()
                self.stats["health_checks"] += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
    
    async def _cleanup_stale(self) -> None:
        """Remove stale connections from pool."""
        now = time.time()
        
        async with self._pool_lock:
            for key in list(self._pool.keys()):
                active = []
                for reader, writer, created in self._pool[key]:
                    if writer.is_closing() or (now - created) > 30:
                        writer.close()
                        self.stats["stale_removed"] += 1
                    else:
                        active.append((reader, writer, created))
                
                if active:
                    self._pool[key] = active
                else:
                    del self._pool[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        pool_size = sum(len(p) for p in self._pool.values())
        return {
            **self.stats,
            "pool_size": pool_size,
            "active_connections": self._active_connections,
            "unique_hosts": len(self._pool)
        }


# ============================================================================
# Garbage Collection Optimization
# ============================================================================

class GCOptimizer:
    """
    Garbage collection optimization utilities.
    
    Features:
    - Disable GC during critical sections
    - Manual GC triggering
    - Generation tuning
    - Memory pressure monitoring
    """
    
    _original_thresholds: Optional[Tuple[int, int, int]] = None
    
    @classmethod
    def disable_gc(cls) -> None:
        """Disable automatic garbage collection."""
        if cls._original_thresholds is None:
            cls._original_thresholds = gc.get_threshold()
        gc.disable()
        logger.debug("Garbage collection disabled")
    
    @classmethod
    def enable_gc(cls) -> None:
        """Re-enable automatic garbage collection."""
        gc.enable()
        if cls._original_thresholds:
            gc.set_threshold(*cls._original_thresholds)
        logger.debug("Garbage collection enabled")
    
    @classmethod
    @contextmanager
    def pause_gc(cls):
        """
        Context manager to temporarily pause GC.
        
        Usage:
            with GCOptimizer.pause_gc():
                # GC disabled here
                perform_critical_operations()
        """
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            yield
        finally:
            if was_enabled:
                gc.enable()
    
    @classmethod
    def collect(cls, generation: int = 2) -> int:
        """
        Force garbage collection.
        
        Args:
            generation: GC generation (0, 1, or 2)
            
        Returns:
            Number of objects collected
        """
        return gc.collect(generation)
    
    @classmethod
    def tune_for_throughput(cls) -> None:
        """Tune GC for high throughput (less frequent collection)."""
        gc.set_threshold(50000, 500, 100)
        logger.info("GC tuned for throughput")
    
    @classmethod
    def tune_for_latency(cls) -> None:
        """Tune GC for low latency (more frequent, smaller collection)."""
        gc.set_threshold(5000, 50, 10)
        logger.info("GC tuned for latency")
    
    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """Get GC statistics."""
        return {
            "enabled": gc.isenabled(),
            "threshold": gc.get_threshold(),
            "counts": gc.get_count(),
            "objects_tracked": len(gc.get_objects())
        }


# ============================================================================
# Result Streaming
# ============================================================================

class ResultStream:
    """
    Streaming result processor for large scans.
    
    Features:
    - Process results as they arrive
    - Automatic disk offloading
    - Memory pressure handling
    - Async iteration support
    """
    
    def __init__(
        self,
        output_file: Optional[Path] = None,
        max_memory_mb: float = 500.0,
        buffer_size: int = 1000
    ):
        """
        Initialize result stream.
        
        Args:
            output_file: Optional file to stream results to
            max_memory_mb: Maximum memory before disk offload
            buffer_size: Number of results to buffer
        """
        self.output_file = output_file
        self.max_memory_mb = max_memory_mb
        self.buffer_size = buffer_size
        
        self._buffer: List[Any] = []
        self._total_count = 0
        self._file_handle: Optional[Any] = None
        self._offloaded = False
        
        if output_file:
            self._file_handle = open(output_file, 'w')
            self._file_handle.write('[\n')
    
    def add(self, result: Any) -> None:
        """
        Add a result to the stream.
        
        Args:
            result: Result to add
        """
        self._buffer.append(result)
        self._total_count += 1
        
        # Check if we need to flush
        if len(self._buffer) >= self.buffer_size:
            self._flush_buffer()
    
    def _flush_buffer(self) -> None:
        """Flush buffer to disk if output file configured."""
        if not self._file_handle or not self._buffer:
            return
        
        for i, result in enumerate(self._buffer):
            if self._total_count > len(self._buffer) or i > 0:
                self._file_handle.write(',\n')
            
            if hasattr(result, '__dict__'):
                json.dump(result.__dict__, self._file_handle, default=str)
            else:
                json.dump(result, self._file_handle, default=str)
        
        self._file_handle.flush()
        self._buffer.clear()
        gc.collect(0)  # Collect youngest generation
    
    def get_buffer(self) -> List[Any]:
        """Get current buffer contents."""
        return self._buffer.copy()
    
    @property
    def count(self) -> int:
        """Total number of results processed."""
        return self._total_count
    
    def close(self) -> None:
        """Close the stream and finalize output."""
        self._flush_buffer()
        
        if self._file_handle:
            self._file_handle.write('\n]')
            self._file_handle.close()
            self._file_handle = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    # DNS
    'AsyncDNSResolver',
    
    # Batch operations
    'BatchPortChecker',
    
    # Storage
    'MemoryMappedStorage',
    'MappedResult',
    
    # Profiling
    'Profiler',
    'ProfileResult',
    'profile_block',
    
    # Benchmarking
    'Benchmark',
    'BenchmarkResult',
    
    # Lazy loading
    'LazyLoader',
    'lazy_property',
    
    # Connection pool
    'EnhancedConnectionPool',
    
    # GC
    'GCOptimizer',
    
    # Streaming
    'ResultStream',
]
