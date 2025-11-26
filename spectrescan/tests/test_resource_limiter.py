"""
Tests for resource limiter module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import sys

# The `resource` module is not available on Windows. Skip these tests on Windows.
pytest.skip("Skipping resource_limiter tests on Windows (resource module not available)", allow_module_level=True) if sys.platform == "win32" else None
import asyncio
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


@pytest.mark.asyncio
async def test_cpu_limiter():
    """Test CPU limiter."""
    limiter = CPULimiter(max_cpu_percent=80)
    
    assert limiter.max_cpu_percent == 80
    
    # Check and throttle
    await limiter.check_and_throttle()
    
    # Get current usage
    usage = limiter.get_current_usage()
    assert usage >= 0


@pytest.mark.asyncio
async def test_network_throttler():
    """Test network throttler."""
    throttler = NetworkThrottler(max_mbps=100.0)
    
    assert throttler.max_mbps == 100.0
    
    # Wait if needed (small bytes shouldn't throttle)
    await throttler.wait_if_needed(1024)
    
    # Get usage
    usage = throttler.get_current_usage()
    assert "current_mbps" in usage
    assert "max_mbps" in usage


def test_file_descriptor_manager():
    """Test file descriptor manager."""
    manager = FileDescriptorManager(max_fds=1024)
    
    # Get FD count
    count = manager.get_fd_count()
    assert count >= 0
    
    # Check limit
    within_limit = manager.check_fd_limit()
    assert isinstance(within_limit, bool)
    
    # Get stats
    stats = manager.get_fd_stats()
    assert "current" in stats
    assert "soft_limit" in stats
    assert "hard_limit" in stats


@pytest.mark.asyncio
async def test_connection_pool():
    """Test connection pool."""
    pool = ConnectionPool(max_connections=100)
    
    assert pool.max_connections == 100
    assert pool.active_connections == 0
    
    # Acquire connection
    async with pool.acquire():
        assert pool.active_connections == 1
    
    assert pool.active_connections == 0
    
    # Get stats
    stats = pool.get_stats()
    assert "active" in stats
    assert "max" in stats
    assert "total" in stats


@pytest.mark.asyncio
async def test_resource_limiter():
    """Test unified resource limiter."""
    limits = ResourceLimits(
        max_cpu_percent=80,
        max_network_mbps=100.0,
        max_connections=1000
    )
    
    limiter = ResourceLimiter(limits)
    
    # Check limits
    status = await limiter.check_limits()
    assert "fd_ok" in status
    assert "fd_stats" in status
    
    # Get summary
    summary = limiter.get_resource_summary()
    assert "limits" in summary
    assert "file_descriptors" in summary


def test_get_system_limits():
    """Test getting system limits."""
    limits = get_system_limits()
    
    assert "memory" in limits
    assert "cpu" in limits
    assert "network" in limits
    
    assert limits["memory"]["total_mb"] > 0
    assert limits["cpu"]["count"] > 0


def test_recommend_resource_limits():
    """Test resource limit recommendations."""
    limits = recommend_resource_limits()
    
    assert isinstance(limits, ResourceLimits)
    assert limits.max_memory_mb > 0
    assert limits.max_cpu_percent > 0
    assert limits.max_connections > 0
