"""
Resource Limiter
Configurable CPU/memory/network limits, file descriptor management.

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import logging
import os
import psutil
import time
from dataclasses import dataclass
from typing import Optional
from contextlib import asynccontextmanager

try:
    import resource  # type: ignore
except ImportError:  # pragma: no cover
    # The stdlib 'resource' module is Unix-only.
    resource = None

logger = logging.getLogger(__name__)


@dataclass
class ResourceLimits:
    """Resource limit configuration."""
    max_memory_mb: Optional[int] = None  # Maximum memory in MB
    max_cpu_percent: Optional[int] = None  # Maximum CPU usage percentage
    max_network_mbps: Optional[float] = None  # Maximum network bandwidth in Mbps
    max_file_descriptors: Optional[int] = None  # Maximum open file descriptors
    max_threads: Optional[int] = None  # Maximum thread count
    max_connections: Optional[int] = None  # Maximum concurrent connections


class CPULimiter:
    """Limit CPU usage."""
    
    def __init__(self, max_cpu_percent: int = 80):
        """
        Initialize CPU limiter.
        
        Args:
            max_cpu_percent: Maximum CPU usage (0-100)
        """
        self.max_cpu_percent = max_cpu_percent
        self.process = psutil.Process()
        self.last_check = time.time()
        self.throttle_sleep = 0.0
        
        logger.info(f"CPU limiter: max {max_cpu_percent}%")
    
    async def check_and_throttle(self) -> None:
        """Check CPU usage and throttle if needed."""
        now = time.time()
        
        # Check every 1 second
        if now - self.last_check < 1.0:
            if self.throttle_sleep > 0:
                await asyncio.sleep(self.throttle_sleep)
            return
        
        self.last_check = now
        
        # Get CPU usage
        cpu_percent = self.process.cpu_percent()
        
        if cpu_percent > self.max_cpu_percent:
            # Calculate throttle delay
            overage = cpu_percent - self.max_cpu_percent
            self.throttle_sleep = min(overage / 100, 0.5)  # Max 500ms delay
            
            logger.debug(f"CPU throttling: {cpu_percent:.1f}% > {self.max_cpu_percent}%, sleep {self.throttle_sleep:.3f}s")
            await asyncio.sleep(self.throttle_sleep)
        else:
            self.throttle_sleep = 0.0
    
    def get_current_usage(self) -> float:
        """Get current CPU usage percentage."""
        return self.process.cpu_percent()


class NetworkThrottler:
    """Throttle network bandwidth."""
    
    def __init__(self, max_mbps: float = 100.0):
        """
        Initialize network throttler.
        
        Args:
            max_mbps: Maximum bandwidth in Mbps
        """
        self.max_mbps = max_mbps
        self.max_bytes_per_second = max_mbps * 1024 * 1024 / 8
        self.bytes_sent = 0
        self.window_start = time.time()
        self.window_duration = 1.0  # 1 second window
        
        logger.info(f"Network throttler: max {max_mbps} Mbps")
    
    async def wait_if_needed(self, bytes_to_send: int) -> None:
        """
        Wait if bandwidth limit would be exceeded.
        
        Args:
            bytes_to_send: Number of bytes about to send
        """
        now = time.time()
        elapsed = now - self.window_start
        
        # Reset window if expired
        if elapsed >= self.window_duration:
            self.bytes_sent = 0
            self.window_start = now
            elapsed = 0
        
        # Check if we'd exceed limit
        if self.bytes_sent + bytes_to_send > self.max_bytes_per_second:
            # Calculate wait time
            wait_time = self.window_duration - elapsed
            
            if wait_time > 0:
                logger.debug(f"Network throttling: {self.bytes_sent} bytes sent, waiting {wait_time:.3f}s")
                await asyncio.sleep(wait_time)
                
                # Reset window
                self.bytes_sent = 0
                self.window_start = time.time()
        
        # Track bytes
        self.bytes_sent += bytes_to_send
    
    def get_current_usage(self) -> dict:
        """Get current bandwidth usage."""
        elapsed = time.time() - self.window_start
        if elapsed > 0:
            current_bps = self.bytes_sent / elapsed
            current_mbps = current_bps * 8 / 1024 / 1024
        else:
            current_mbps = 0.0
        
        return {
            "current_mbps": round(current_mbps, 2),
            "max_mbps": self.max_mbps,
            "bytes_sent": self.bytes_sent,
            "window_elapsed": round(elapsed, 2)
        }


class FileDescriptorManager:
    """Manage file descriptor limits."""
    
    def __init__(self, max_fds: Optional[int] = None):
        """
        Initialize FD manager.
        
        Args:
            max_fds: Maximum file descriptors (None = use system limit)
        """
        self.max_fds = max_fds
        self.process = psutil.Process()
        
        # Get system limits
        if os.name != 'nt' and resource is not None:  # Unix-like systems
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            self.system_soft_limit = soft
            self.system_hard_limit = hard
            
            if max_fds and max_fds < hard:
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (max_fds, hard))
                    logger.info(f"Set file descriptor limit to {max_fds}")
                except Exception as e:
                    logger.warning(f"Failed to set FD limit: {e}")
        else:
            # Windows doesn't have the same FD limits
            self.system_soft_limit = 512
            self.system_hard_limit = 2048
        
        logger.info(f"File descriptor limits: soft={self.system_soft_limit}, hard={self.system_hard_limit}")
    
    def get_fd_count(self) -> int:
        """Get current number of open file descriptors."""
        try:
            return self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
        except Exception:
            return 0
    
    def check_fd_limit(self, reserve: int = 100) -> bool:
        """
        Check if FD limit is approaching.
        
        Args:
            reserve: Number of FDs to keep in reserve
        
        Returns:
            True if within limit, False if approaching limit
        """
        current = self.get_fd_count()
        limit = self.max_fds or self.system_soft_limit
        
        if current + reserve >= limit:
            logger.warning(f"Approaching FD limit: {current}/{limit}")
            return False
        
        return True
    
    def get_fd_stats(self) -> dict:
        """Get FD usage statistics."""
        current = self.get_fd_count()
        limit = self.max_fds or self.system_soft_limit
        
        return {
            "current": current,
            "soft_limit": self.system_soft_limit,
            "hard_limit": self.system_hard_limit,
            "custom_limit": self.max_fds,
            "percent_used": round((current / limit * 100), 2) if limit > 0 else 0
        }


class ConnectionPool:
    """
    Connection pool with size limits.
    Prevents resource exhaustion from too many concurrent connections.
    """
    
    def __init__(self, max_connections: int = 1000):
        """
        Initialize connection pool.
        
        Args:
            max_connections: Maximum concurrent connections
        """
        self.max_connections = max_connections
        self.semaphore = asyncio.Semaphore(max_connections)
        self.active_connections = 0
        self.total_connections = 0
        self.peak_connections = 0
        
        logger.info(f"Connection pool: max {max_connections} concurrent")
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire a connection slot."""
        async with self.semaphore:
            self.active_connections += 1
            self.total_connections += 1
            self.peak_connections = max(self.peak_connections, self.active_connections)
            
            try:
                yield
            finally:
                self.active_connections -= 1
    
    def get_stats(self) -> dict:
        """Get connection pool statistics."""
        return {
            "active": self.active_connections,
            "max": self.max_connections,
            "total": self.total_connections,
            "peak": self.peak_connections,
            "utilization": round((self.active_connections / self.max_connections * 100), 2)
        }


class ResourceLimiter:
    """
    Unified resource limiter.
    Manages CPU, memory, network, and file descriptor limits.
    """
    
    def __init__(self, limits: ResourceLimits):
        """
        Initialize resource limiter.
        
        Args:
            limits: Resource limit configuration
        """
        self.limits = limits
        
        # Initialize limiters
        self.cpu_limiter = CPULimiter(limits.max_cpu_percent) if limits.max_cpu_percent else None
        self.network_throttler = NetworkThrottler(limits.max_network_mbps) if limits.max_network_mbps else None
        self.fd_manager = FileDescriptorManager(limits.max_file_descriptors)
        self.connection_pool = ConnectionPool(limits.max_connections) if limits.max_connections else None
        
        logger.info(f"ResourceLimiter initialized: {limits}")
    
    async def check_limits(self) -> dict:
        """
        Check all resource limits.
        
        Returns:
            Dictionary of limit statuses
        """
        status = {}
        
        # CPU
        if self.cpu_limiter:
            await self.cpu_limiter.check_and_throttle()
            status["cpu_percent"] = self.cpu_limiter.get_current_usage()
        
        # File descriptors
        status["fd_ok"] = self.fd_manager.check_fd_limit()
        status["fd_stats"] = self.fd_manager.get_fd_stats()
        
        # Network
        if self.network_throttler:
            status["network"] = self.network_throttler.get_current_usage()
        
        # Connections
        if self.connection_pool:
            status["connections"] = self.connection_pool.get_stats()
        
        return status
    
    async def throttle_network(self, bytes_to_send: int) -> None:
        """Throttle network if needed."""
        if self.network_throttler:
            await self.network_throttler.wait_if_needed(bytes_to_send)
    
    @asynccontextmanager
    async def acquire_connection(self):
        """Acquire a connection slot from pool."""
        if self.connection_pool:
            async with self.connection_pool.acquire():
                yield
        else:
            yield
    
    def get_resource_summary(self) -> dict:
        """Get summary of all resource usage."""
        summary = {
            "limits": {
                "max_memory_mb": self.limits.max_memory_mb,
                "max_cpu_percent": self.limits.max_cpu_percent,
                "max_network_mbps": self.limits.max_network_mbps,
                "max_file_descriptors": self.limits.max_file_descriptors,
                "max_connections": self.limits.max_connections
            }
        }
        
        if self.cpu_limiter:
            summary["cpu_percent"] = self.cpu_limiter.get_current_usage()
        
        if self.network_throttler:
            summary["network"] = self.network_throttler.get_current_usage()
        
        summary["file_descriptors"] = self.fd_manager.get_fd_stats()
        
        if self.connection_pool:
            summary["connections"] = self.connection_pool.get_stats()
        
        return summary


def get_system_limits() -> dict:
    """
    Get current system resource limits.
    
    Returns:
        Dictionary of system limits
    """
    limits = {}
    
    # Memory
    memory = psutil.virtual_memory()
    limits["memory"] = {
        "total_mb": round(memory.total / 1024 / 1024, 2),
        "available_mb": round(memory.available / 1024 / 1024, 2),
        "percent_used": memory.percent
    }
    
    # CPU
    limits["cpu"] = {
        "count": psutil.cpu_count(),
        "physical_count": psutil.cpu_count(logical=False),
        "percent": psutil.cpu_percent(interval=1)
    }
    
    # File descriptors (Unix only)
    if os.name != 'nt' and resource is not None:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        limits["file_descriptors"] = {
            "soft_limit": soft,
            "hard_limit": hard
        }
    
    # Network
    net_io = psutil.net_io_counters()
    limits["network"] = {
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv,
        "packets_sent": net_io.packets_sent,
        "packets_recv": net_io.packets_recv
    }
    
    return limits


def recommend_resource_limits() -> ResourceLimits:
    """
    Get recommended resource limits based on system.
    
    Returns:
        Recommended ResourceLimits
    """
    system = get_system_limits()
    
    # Memory: Use 50% of available
    max_memory = int(system["memory"]["available_mb"] * 0.5)
    
    # CPU: Leave 20% for system
    max_cpu = 80
    
    # Network: No limit by default
    max_network = None
    
    # File descriptors: Use 80% of soft limit
    if "file_descriptors" in system:
        max_fds = int(system["file_descriptors"]["soft_limit"] * 0.8)
    else:
        max_fds = 400  # Windows default
    
    # Connections: Based on FDs and CPU
    max_connections = min(max_fds // 2, system["cpu"]["count"] * 100)
    
    return ResourceLimits(
        max_memory_mb=max_memory,
        max_cpu_percent=max_cpu,
        max_network_mbps=max_network,
        max_file_descriptors=max_fds,
        max_connections=max_connections
    )
