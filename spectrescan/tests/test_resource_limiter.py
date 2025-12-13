"""\
Tests for resource limiter module.
by BitSpectreLabs
"""

from __future__ import annotations

from typing import Any

import pytest

import spectrescan.core.resource_limiter as rl


class TestResourceLimiter:
    """Test suite for resource limiting utilities."""

    @pytest.mark.asyncio
    async def test_cpu_limiter_throttles_when_over_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CPULimiter throttles when usage exceeds max."""

        limiter = rl.CPULimiter(max_cpu_percent=1)
        limiter.last_check = 0.0

        monkeypatch.setattr(limiter.process, "cpu_percent", lambda: 100.0)

        slept: list[float] = []

        async def _fake_sleep(seconds: float) -> None:
            slept.append(seconds)

        monkeypatch.setattr(rl.asyncio, "sleep", _fake_sleep)

        await limiter.check_and_throttle()

        assert limiter.throttle_sleep > 0
        assert slept

    @pytest.mark.asyncio
    async def test_network_throttler_waits_when_over_budget(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """NetworkThrottler waits when the window budget would be exceeded."""

        now = {"t": 1000.0}

        def _time() -> float:
            return now["t"]

        monkeypatch.setattr(rl.time, "time", _time)

        slept: list[float] = []

        async def _fake_sleep(seconds: float) -> None:
            slept.append(seconds)
            now["t"] += seconds

        monkeypatch.setattr(rl.asyncio, "sleep", _fake_sleep)

        throttler = rl.NetworkThrottler(max_mbps=0.0001)

        # Send enough bytes to force a wait.
        await throttler.wait_if_needed(int(throttler.max_bytes_per_second) + 1)

        assert slept

        usage = throttler.get_current_usage()
        assert usage["max_mbps"] == pytest.approx(0.0001)
        assert usage["bytes_sent"] >= 0

    def test_file_descriptor_manager_reports_stats(self) -> None:
        """FD manager reports stable stats across platforms."""

        manager = rl.FileDescriptorManager(max_fds=1024)
        stats = manager.get_fd_stats()
        assert "current" in stats
        assert "soft_limit" in stats
        assert "hard_limit" in stats
        assert stats["custom_limit"] == 1024

    @pytest.mark.asyncio
    async def test_connection_pool_tracks_counts(self) -> None:
        """ConnectionPool tracks active and peak connections."""

        pool = rl.ConnectionPool(max_connections=2)
        assert pool.active_connections == 0

        async with pool.acquire():
            assert pool.active_connections == 1
            assert pool.peak_connections >= 1

        assert pool.active_connections == 0

    @pytest.mark.asyncio
    async def test_resource_limiter_minimal_configuration(self) -> None:
        """ResourceLimiter works with default limits."""

        limiter = rl.ResourceLimiter(rl.ResourceLimits())
        status = await limiter.check_limits()
        assert "fd_ok" in status
        assert "fd_stats" in status

    def test_get_system_limits_fast(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """System limits can be gathered without sleeping in tests."""

        monkeypatch.setattr(rl.psutil, "cpu_percent", lambda interval=1: 0.0)
        limits = rl.get_system_limits()

        assert "memory" in limits
        assert "cpu" in limits
        assert "network" in limits
        assert limits["cpu"]["count"] > 0

    def test_recommend_resource_limits_uses_windows_fallback_when_no_fd_limits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """recommend_resource_limits uses a fallback when FD limits are unavailable."""

        fake_system: dict[str, Any] = {
            "memory": {"available_mb": 1000.0},
            "cpu": {"count": 4},
            "network": {"bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0},
        }

        monkeypatch.setattr(rl, "get_system_limits", lambda: fake_system)
        limits = rl.recommend_resource_limits()

        assert isinstance(limits, rl.ResourceLimits)
        assert limits.max_file_descriptors == 400
        assert limits.max_connections == 200
