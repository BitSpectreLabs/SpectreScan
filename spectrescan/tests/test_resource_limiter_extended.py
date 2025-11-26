"""
Tests for Resource Limiter Module.

Author: BitSpectreLabs
License: MIT

Note: This module tests Unix-only functionality (resource module).
Tests are skipped on Windows.
"""

import pytest
import asyncio
import os
import sys

# Skip this entire module on Windows - resource module is Unix-only
if sys.platform == 'win32':
    pytest.skip("Resource limiter uses Unix-only 'resource' module", allow_module_level=True)

from spectrescan.core.resource_limiter import (
    ResourceLimits,
    CPULimiter,
    NetworkThrottler,
    FileDescriptorManager,
    ConnectionPool,
    ResourceLimiter,
    get_system_limits,
    recommend_resource_limits
)


class TestResourceLimits:
    """Tests for ResourceLimits dataclass."""
    
    def test_default_values(self):
        """Test default values are None."""
        limits = ResourceLimits()
        
        assert limits.max_memory_mb is None
        assert limits.max_cpu_percent is None
        assert limits.max_network_mbps is None
        assert limits.max_file_descriptors is None
        assert limits.max_threads is None
        assert limits.max_connections is None
    
    def test_with_memory_limit(self):
        """Test with memory limit."""
        limits = ResourceLimits(max_memory_mb=512)
        assert limits.max_memory_mb == 512
    
    def test_with_cpu_limit(self):
        """Test with CPU limit."""
        limits = ResourceLimits(max_cpu_percent=80)
        assert limits.max_cpu_percent == 80
    
    def test_with_network_limit(self):
        """Test with network limit."""
        limits = ResourceLimits(max_network_mbps=100.0)
        assert limits.max_network_mbps == 100.0
    
    def test_with_all_limits(self):
        """Test with all limits set."""
        limits = ResourceLimits(
            max_memory_mb=1024,
            max_cpu_percent=90,
            max_network_mbps=50.0,
            max_file_descriptors=1024,
            max_threads=100,
            max_connections=500
        )
        
        assert limits.max_memory_mb == 1024
        assert limits.max_cpu_percent == 90
        assert limits.max_network_mbps == 50.0
        assert limits.max_file_descriptors == 1024
        assert limits.max_threads == 100
        assert limits.max_connections == 500


class TestCPULimiter:
    """Tests for CPULimiter class."""
    
    def test_init(self):
        """Test initialization."""
        limiter = CPULimiter(max_cpu_percent=80)
        
        assert limiter.max_cpu_percent == 80
        assert limiter.process is not None
        assert limiter.throttle_sleep == 0.0
    
    def test_default_limit(self):
        """Test default limit."""
        limiter = CPULimiter()
        assert limiter.max_cpu_percent == 80
    
    def test_get_current_usage(self):
        """Test getting current CPU usage."""
        limiter = CPULimiter()
        usage = limiter.get_current_usage()
        
        # CPU usage should be a non-negative number
        assert isinstance(usage, float)
        assert usage >= 0
    
    @pytest.mark.asyncio
    async def test_check_and_throttle(self):
        """Test check and throttle method."""
        limiter = CPULimiter(max_cpu_percent=100)
        
        # Should not throttle when limit is 100%
        await limiter.check_and_throttle()
        
        # Should complete without error
        assert True
    
    @pytest.mark.asyncio
    async def test_throttle_sleep_value(self):
        """Test throttle sleep is reset when under limit."""
        limiter = CPULimiter(max_cpu_percent=100)
        limiter.last_check = 0  # Force check
        
        await limiter.check_and_throttle()
        
        # Should be 0 when under limit
        assert limiter.throttle_sleep == 0.0


class TestNetworkThrottler:
    """Tests for NetworkThrottler class."""
    
    def test_init(self):
        """Test initialization."""
        throttler = NetworkThrottler(max_mbps=100.0)
        
        assert throttler.max_mbps == 100.0
        assert throttler.max_bytes_per_second > 0
        assert throttler.bytes_sent == 0
    
    def test_bytes_per_second_calculation(self):
        """Test bytes per second calculation."""
        throttler = NetworkThrottler(max_mbps=8.0)  # 8 Mbps = 1 MB/s
        
        # 8 Mbps = 8 * 1024 * 1024 / 8 = 1048576 bytes/s
        assert throttler.max_bytes_per_second == 8 * 1024 * 1024 / 8
    
    @pytest.mark.asyncio
    async def test_wait_if_needed_under_limit(self):
        """Test no wait when under limit."""
        throttler = NetworkThrottler(max_mbps=100.0)
        
        # Send a small amount of data
        await throttler.wait_if_needed(1000)
        
        assert throttler.bytes_sent == 1000
    
    @pytest.mark.asyncio
    async def test_bytes_tracking(self):
        """Test bytes tracking."""
        throttler = NetworkThrottler(max_mbps=100.0)
        
        await throttler.wait_if_needed(500)
        await throttler.wait_if_needed(300)
        await throttler.wait_if_needed(200)
        
        assert throttler.bytes_sent == 1000
    
    def test_get_current_usage(self):
        """Test getting current usage."""
        throttler = NetworkThrottler(max_mbps=100.0)
        usage = throttler.get_current_usage()
        
        assert "current_mbps" in usage
        assert "max_mbps" in usage
        assert "bytes_sent" in usage
        assert "window_elapsed" in usage
        
        assert usage["max_mbps"] == 100.0


class TestFileDescriptorManager:
    """Tests for FileDescriptorManager class."""
    
    def test_init(self):
        """Test initialization."""
        manager = FileDescriptorManager()
        
        assert manager is not None
        assert manager.system_soft_limit > 0
        assert manager.system_hard_limit >= manager.system_soft_limit
    
    def test_init_with_max_fds(self):
        """Test initialization with max FDs."""
        manager = FileDescriptorManager(max_fds=500)
        
        assert manager.max_fds == 500
    
    def test_get_fd_count(self):
        """Test getting FD count."""
        manager = FileDescriptorManager()
        count = manager.get_fd_count()
        
        # Should be a non-negative integer
        assert isinstance(count, int)
        assert count >= 0
    
    def test_check_fd_limit(self):
        """Test checking FD limit."""
        manager = FileDescriptorManager()
        result = manager.check_fd_limit()
        
        # Should return True when within limit
        assert isinstance(result, bool)
    
    def test_get_fd_stats(self):
        """Test getting FD stats."""
        manager = FileDescriptorManager()
        stats = manager.get_fd_stats()
        
        assert "current" in stats
        assert "soft_limit" in stats
        assert "hard_limit" in stats
        assert "percent_used" in stats
        
        assert stats["soft_limit"] > 0


class TestConnectionPool:
    """Tests for ConnectionPool class."""
    
    def test_init(self):
        """Test initialization."""
        pool = ConnectionPool(max_connections=100)
        
        assert pool.max_connections == 100
        assert pool.active_connections == 0
        assert pool.total_connections == 0
        assert pool.peak_connections == 0
    
    @pytest.mark.asyncio
    async def test_acquire_and_release(self):
        """Test acquiring and releasing connection slots."""
        pool = ConnectionPool(max_connections=10)
        
        assert pool.active_connections == 0
        
        async with pool.acquire():
            assert pool.active_connections == 1
            assert pool.total_connections == 1
        
        assert pool.active_connections == 0
        assert pool.total_connections == 1
    
    @pytest.mark.asyncio
    async def test_multiple_acquisitions(self):
        """Test multiple connection acquisitions."""
        pool = ConnectionPool(max_connections=10)
        
        async def acquire_slot():
            async with pool.acquire():
                await asyncio.sleep(0.01)
        
        # Acquire 5 slots concurrently
        await asyncio.gather(*[acquire_slot() for _ in range(5)])
        
        assert pool.total_connections == 5
        assert pool.active_connections == 0
    
    @pytest.mark.asyncio
    async def test_peak_tracking(self):
        """Test peak connection tracking."""
        pool = ConnectionPool(max_connections=10)
        
        async def hold_slot(delay):
            async with pool.acquire():
                await asyncio.sleep(delay)
        
        # Create overlapping acquisitions
        task1 = asyncio.create_task(hold_slot(0.05))
        task2 = asyncio.create_task(hold_slot(0.05))
        task3 = asyncio.create_task(hold_slot(0.05))
        
        await asyncio.gather(task1, task2, task3)
        
        assert pool.peak_connections >= 1
    
    def test_get_stats(self):
        """Test getting pool stats."""
        pool = ConnectionPool(max_connections=100)
        stats = pool.get_stats()
        
        assert "active" in stats
        assert "max" in stats
        assert "total" in stats
        assert "peak" in stats
        assert "utilization" in stats
        
        assert stats["max"] == 100


class TestResourceLimiter:
    """Tests for ResourceLimiter class."""
    
    def test_init_with_no_limits(self):
        """Test initialization with no limits."""
        limits = ResourceLimits()
        limiter = ResourceLimiter(limits)
        
        assert limiter.cpu_limiter is None
        assert limiter.network_throttler is None
        assert limiter.connection_pool is None
    
    def test_init_with_cpu_limit(self):
        """Test initialization with CPU limit."""
        limits = ResourceLimits(max_cpu_percent=80)
        limiter = ResourceLimiter(limits)
        
        assert limiter.cpu_limiter is not None
        assert limiter.cpu_limiter.max_cpu_percent == 80
    
    def test_init_with_network_limit(self):
        """Test initialization with network limit."""
        limits = ResourceLimits(max_network_mbps=50.0)
        limiter = ResourceLimiter(limits)
        
        assert limiter.network_throttler is not None
    
    def test_init_with_connection_limit(self):
        """Test initialization with connection limit."""
        limits = ResourceLimits(max_connections=500)
        limiter = ResourceLimiter(limits)
        
        assert limiter.connection_pool is not None
        assert limiter.connection_pool.max_connections == 500
    
    @pytest.mark.asyncio
    async def test_check_limits(self):
        """Test checking all limits."""
        limits = ResourceLimits(
            max_cpu_percent=90,
            max_network_mbps=100.0,
            max_connections=500
        )
        limiter = ResourceLimiter(limits)
        
        status = await limiter.check_limits()
        
        assert "fd_ok" in status
        assert "fd_stats" in status
    
    @pytest.mark.asyncio
    async def test_throttle_network(self):
        """Test network throttling."""
        limits = ResourceLimits(max_network_mbps=100.0)
        limiter = ResourceLimiter(limits)
        
        await limiter.throttle_network(1000)
        
        assert limiter.network_throttler.bytes_sent == 1000
    
    @pytest.mark.asyncio
    async def test_throttle_network_no_throttler(self):
        """Test network throttling without throttler."""
        limits = ResourceLimits()
        limiter = ResourceLimiter(limits)
        
        # Should not raise error
        await limiter.throttle_network(1000)
    
    @pytest.mark.asyncio
    async def test_acquire_connection(self):
        """Test acquiring connection slot."""
        limits = ResourceLimits(max_connections=10)
        limiter = ResourceLimiter(limits)
        
        async with limiter.acquire_connection():
            assert limiter.connection_pool.active_connections == 1
        
        assert limiter.connection_pool.active_connections == 0
    
    @pytest.mark.asyncio
    async def test_acquire_connection_no_pool(self):
        """Test acquiring connection without pool."""
        limits = ResourceLimits()
        limiter = ResourceLimiter(limits)
        
        # Should not raise error
        async with limiter.acquire_connection():
            pass
    
    def test_get_resource_summary(self):
        """Test getting resource summary."""
        limits = ResourceLimits(
            max_memory_mb=1024,
            max_cpu_percent=80,
            max_network_mbps=100.0,
            max_connections=500
        )
        limiter = ResourceLimiter(limits)
        
        summary = limiter.get_resource_summary()
        
        assert "limits" in summary
        assert "file_descriptors" in summary
        assert summary["limits"]["max_memory_mb"] == 1024


class TestSystemLimits:
    """Tests for system limit functions."""
    
    def test_get_system_limits(self):
        """Test getting system limits."""
        limits = get_system_limits()
        
        assert "memory" in limits
        assert "cpu" in limits
        assert "network" in limits
        
        # Memory should have basic info
        assert "total_mb" in limits["memory"]
        assert "available_mb" in limits["memory"]
        assert limits["memory"]["total_mb"] > 0
        
        # CPU should have count
        assert "count" in limits["cpu"]
        assert limits["cpu"]["count"] > 0
    
    def test_recommend_resource_limits(self):
        """Test recommended limits."""
        limits = recommend_resource_limits()
        
        assert isinstance(limits, ResourceLimits)
        assert limits.max_memory_mb is not None
        assert limits.max_memory_mb > 0
        assert limits.max_cpu_percent is not None
        assert limits.max_cpu_percent > 0
        assert limits.max_cpu_percent <= 100
        assert limits.max_connections is not None
        assert limits.max_connections > 0
