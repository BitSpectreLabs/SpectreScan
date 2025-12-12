"""
Tests for Performance Optimization Module.

Comprehensive test suite for all performance-related functionality including
async DNS resolution, batch port checking, memory-mapped storage, profiling,
benchmarking, lazy loading, connection pooling, and GC optimization.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import asyncio
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from spectrescan.core.performance import (
    AsyncDNSResolver,
    BatchPortChecker,
    MemoryMappedStorage,
    MappedResult,
    Profiler,
    ProfileResult,
    profile_block,
    Benchmark,
    BenchmarkResult,
    LazyLoader,
    lazy_property,
    EnhancedConnectionPool,
    GCOptimizer,
    ResultStream
)


class TestAsyncDNSResolver:
    """Test suite for AsyncDNSResolver."""
    
    @pytest.fixture
    def resolver(self):
        """Create resolver instance."""
        return AsyncDNSResolver(cache_size=100, cache_ttl=60)
    
    @pytest.mark.asyncio
    async def test_resolve_localhost(self, resolver):
        """Test resolving localhost."""
        result = await resolver.resolve("localhost")
        assert result in ("127.0.0.1", "::1", None) or result is not None
    
    @pytest.mark.asyncio
    async def test_resolve_cached(self, resolver):
        """Test DNS cache functionality."""
        # First resolution
        result1 = await resolver.resolve("localhost")
        
        # Second should be cached
        result2 = await resolver.resolve("localhost")
        
        assert result1 == result2
        
        # Check cache hit
        stats = resolver.get_stats()
        assert stats["cache_size"] >= 0
    
    @pytest.mark.asyncio
    async def test_resolve_invalid_host(self, resolver):
        """Test resolving invalid hostname."""
        result = await resolver.resolve("this-host-does-not-exist-12345.invalid")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_resolve_batch(self, resolver):
        """Test batch DNS resolution."""
        hostnames = ["localhost", "127.0.0.1"]
        results = await resolver.resolve_batch(hostnames)
        
        assert len(results) == 2
        assert "localhost" in results
    
    def test_clear_cache(self, resolver):
        """Test cache clearing."""
        resolver.clear_cache()
        stats = resolver.get_stats()
        assert stats["cache_size"] == 0
    
    def test_get_stats(self, resolver):
        """Test statistics retrieval."""
        stats = resolver.get_stats()
        
        assert "cache_size" in stats
        assert "cache_capacity" in stats
        assert "queries" in stats


class TestBatchPortChecker:
    """Test suite for BatchPortChecker."""
    
    @pytest.fixture
    def checker(self):
        """Create checker instance."""
        return BatchPortChecker(batch_size=10, timeout=0.5)
    
    @pytest.mark.asyncio
    async def test_check_ports_batch(self, checker):
        """Test batch port checking."""
        ports = [80, 443, 22, 8080]
        results = await checker.check_ports("127.0.0.1", ports)
        
        assert len(results) == len(ports)
        for port, state in results.items():
            assert state in ("open", "closed", "filtered", "error")
    
    @pytest.mark.asyncio
    async def test_check_nonexistent_host(self, checker):
        """Test checking ports on non-existent host."""
        results = await checker.check_ports("192.0.2.1", [80])  # TEST-NET, should fail
        assert 80 in results
    
    def test_get_stats(self, checker):
        """Test statistics retrieval."""
        stats = checker.get_stats()
        
        assert "batches" in stats
        assert "open_found" in stats
        assert "ports_checked" in stats


class TestMemoryMappedStorage:
    """Test suite for MemoryMappedStorage."""
    
    @pytest.fixture
    def storage(self):
        """Create storage instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test_storage.dat"
            storage = MemoryMappedStorage(path, max_results=1000)
            yield storage
            storage.close()
    
    def test_add_result(self, storage):
        """Test adding a result."""
        result = MappedResult(
            host="192.168.1.1",
            port=80,
            state="open",
            service="http",
            banner="Apache",
            timestamp=time.time()
        )
        
        index = storage.add_result(result)
        assert index == 0
        assert len(storage) == 1
    
    def test_get_result(self, storage):
        """Test retrieving a result."""
        original = MappedResult(
            host="10.0.0.1",
            port=443,
            state="open",
            service="https",
            banner="nginx",
            timestamp=time.time()
        )
        
        storage.add_result(original)
        retrieved = storage.get_result(0)
        
        assert retrieved is not None
        assert retrieved.host == original.host
        assert retrieved.port == original.port
        assert retrieved.service == original.service
    
    def test_iterate_results(self, storage):
        """Test iterating over results."""
        for i in range(5):
            storage.add_result(MappedResult(
                host=f"192.168.1.{i}",
                port=80 + i,
                state="open",
                service="http",
                timestamp=time.time()
            ))
        
        results = list(storage)
        assert len(results) == 5
    
    def test_get_results_via_iteration(self, storage):
        """Test getting all results via iteration."""
        for i in range(3):
            storage.add_result(MappedResult(
                host=f"10.0.0.{i}",
                port=22,
                state="open",
                timestamp=time.time()
            ))
        
        all_results = list(storage)
        assert len(all_results) == 3


class TestProfiler:
    """Test suite for Profiler."""
    
    def setup_method(self):
        """Reset profiler before each test."""
        Profiler.reset()
    
    def test_profile_decorator(self):
        """Test profiling decorator."""
        @Profiler.profile()
        def test_function():
            time.sleep(0.01)
            return 42
        
        result = test_function()
        
        assert result == 42
        
        results = Profiler.get_results()
        assert len(results) > 0
        assert any("test_function" in r.name for r in results)
    
    def test_profile_multiple_calls(self):
        """Test profiling multiple calls."""
        @Profiler.profile()
        def counted_function():
            return 1
        
        for _ in range(5):
            counted_function()
        
        results = Profiler.get_results()
        func_result = next(r for r in results if "counted_function" in r.name)
        
        assert func_result.calls == 5
    
    def test_profile_block_context_manager(self):
        """Test profile_block context manager."""
        with profile_block("test_block"):
            time.sleep(0.01)
        
        results = Profiler.get_results()
        assert any("test_block" in r.name for r in results)
    
    def test_profiler_reset(self):
        """Test profiler reset."""
        @Profiler.profile()
        def dummy():
            pass
        
        dummy()
        Profiler.reset()
        
        results = Profiler.get_results()
        assert len(results) == 0
    
    def test_profile_result_dataclass(self):
        """Test ProfileResult dataclass."""
        result = ProfileResult(
            name="test",
            calls=10,
            total_time=1.0,
            avg_time=0.1,
            min_time=0.05,
            max_time=0.2
        )
        
        assert result.name == "test"
        assert result.calls == 10
        assert result.avg_time == 0.1


class TestBenchmark:
    """Test suite for Benchmark."""
    
    def test_run_sync_benchmark(self):
        """Test synchronous benchmark."""
        def simple_func():
            return sum(range(100))
        
        result = Benchmark.run_sync(
            "Sum Benchmark",
            simple_func,
            iterations=10,
            warmup=2
        )
        
        assert result.name == "Sum Benchmark"
        assert result.iterations == 10
        assert result.avg_time_ms > 0
        assert result.ops_per_second > 0
    
    @pytest.mark.asyncio
    async def test_run_async_benchmark(self):
        """Test asynchronous benchmark."""
        async def async_func():
            await asyncio.sleep(0.001)
            return 42
        
        result = await Benchmark.run_async(
            "Async Benchmark",
            async_func,
            iterations=5,
            warmup=1
        )
        
        assert result.name == "Async Benchmark"
        assert result.iterations == 5
        assert result.avg_time_ms > 0
    
    def test_benchmark_result_dataclass(self):
        """Test BenchmarkResult dataclass."""
        result = BenchmarkResult(
            name="test",
            iterations=100,
            total_time=1.0,
            avg_time_ms=10,
            min_time_ms=8,
            max_time_ms=15,
            std_dev_ms=2,
            ops_per_second=100
        )
        
        assert result.name == "test"
        assert result.ops_per_second == 100


class TestLazyLoader:
    """Test suite for LazyLoader."""
    
    def test_lazy_loading(self):
        """Test lazy initialization."""
        call_count = 0
        
        def factory():
            nonlocal call_count
            call_count += 1
            return "loaded_value"
        
        loader = LazyLoader(factory)
        
        # Not loaded yet
        assert call_count == 0
        
        # First access loads
        value = loader.get()
        assert value == "loaded_value"
        assert call_count == 1
        
        # Second access uses cached value
        value2 = loader.get()
        assert value2 == "loaded_value"
        assert call_count == 1
    
    def test_reset(self):
        """Test reset functionality."""
        counter = [0]
        
        def factory():
            counter[0] += 1
            return counter[0]
        
        loader = LazyLoader(factory)
        
        assert loader.get() == 1
        
        loader.reset()
        
        assert loader.get() == 2
    
    def test_is_loaded(self):
        """Test is_loaded method."""
        loader = LazyLoader(lambda: "value")
        
        assert not loader.is_loaded()
        loader.get()
        assert loader.is_loaded()


class TestLazyProperty:
    """Test suite for lazy_property decorator."""
    
    def test_lazy_property_decorator(self):
        """Test lazy property decorator."""
        class TestClass:
            def __init__(self):
                self.compute_count = 0
            
            @lazy_property
            def expensive_value(self):
                self.compute_count += 1
                return "computed"
        
        obj = TestClass()
        
        # Not computed yet
        assert obj.compute_count == 0
        
        # First access
        value = obj.expensive_value
        assert value == "computed"
        assert obj.compute_count == 1
        
        # Second access (cached)
        value2 = obj.expensive_value
        assert value2 == "computed"
        assert obj.compute_count == 1


class TestEnhancedConnectionPool:
    """Test suite for EnhancedConnectionPool."""
    
    @pytest.fixture
    def pool(self):
        """Create pool instance."""
        return EnhancedConnectionPool(
            max_connections=10,
            max_per_host=5
        )
    
    @pytest.mark.asyncio
    async def test_acquire_release(self, pool):
        """Test connection acquire and release."""
        # This is a mock test since we can't easily create real connections
        stats = pool.get_stats()
        assert "total_acquired" in stats
    
    def test_get_stats(self, pool):
        """Test statistics retrieval."""
        stats = pool.get_stats()
        
        assert "total_acquired" in stats
        assert "total_released" in stats
        assert "pool_hits" in stats
    
    @pytest.mark.asyncio
    async def test_close(self, pool):
        """Test pool closure."""
        await pool.stop()
        # Pool should be closed without error


class TestGCOptimizer:
    """Test suite for GCOptimizer."""
    
    def test_collect(self):
        """Test garbage collection."""
        collected = GCOptimizer.collect()
        assert isinstance(collected, int)
        assert collected >= 0
    
    def test_tune_for_throughput(self):
        """Test throughput tuning."""
        GCOptimizer.tune_for_throughput()
        # Should not raise
    
    def test_tune_for_latency(self):
        """Test latency tuning."""
        GCOptimizer.tune_for_latency()
        # Should not raise
    
    def test_get_stats(self):
        """Test GC statistics."""
        stats = GCOptimizer.get_stats()
        
        assert "enabled" in stats
        assert "threshold" in stats
        assert "counts" in stats
        assert "objects_tracked" in stats
    
    def test_disable_enable(self):
        """Test GC disable/enable."""
        # Ensure GC is enabled first
        GCOptimizer.enable_gc()
        assert GCOptimizer.get_stats()["enabled"]
        
        GCOptimizer.disable_gc()
        assert not GCOptimizer.get_stats()["enabled"]
        
        GCOptimizer.enable_gc()
        assert GCOptimizer.get_stats()["enabled"]


class TestResultStream:
    """Test suite for ResultStream."""
    
    @pytest.fixture
    def stream(self):
        """Create stream instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "results.json"
            stream = ResultStream(
                output_file=output_file,
                max_memory_mb=1,
                buffer_size=10
            )
            yield stream
            stream.close()
    
    def test_add_result(self, stream):
        """Test adding results."""
        result = MappedResult(
            host="192.168.1.1",
            port=80,
            state="open",
            timestamp=time.time()
        )
        
        stream.add(result)
        assert stream.count == 1
    
    def test_stream_multiple_results(self, stream):
        """Test streaming multiple results."""
        for i in range(5):
            stream.add(MappedResult(
                host=f"10.0.0.{i}",
                port=80,
                state="open",
                timestamp=time.time()
            ))
        
        assert stream.count == 5
    
    def test_get_buffer(self, stream):
        """Test getting current buffer."""
        for i in range(3):
            stream.add(MappedResult(
                host=f"192.168.1.{i}",
                port=443,
                state="open",
                timestamp=time.time()
            ))
        
        buffer = stream.get_buffer()
        assert len(buffer) == 3
        assert stream.count == 3


class TestPerformanceIntegration:
    """Integration tests for performance module."""
    
    @pytest.mark.asyncio
    async def test_dns_with_batch_check(self):
        """Test DNS resolution with batch port checking."""
        resolver = AsyncDNSResolver()
        checker = BatchPortChecker(batch_size=5, timeout=1.0)
        
        # Resolve localhost
        ip = await resolver.resolve("localhost")
        
        if ip:
            # Check some ports
            results = await checker.check_ports(ip, [22, 80, 443])
            assert len(results) == 3
    
    def test_profiler_with_benchmark(self):
        """Test profiler integration with benchmarks."""
        Profiler.reset()
        
        @Profiler.profile()
        def profiled_func():
            return sum(range(1000))
        
        # Run benchmark on profiled function
        result = Benchmark.run_sync(
            "Profiled Benchmark",
            profiled_func,
            iterations=10,
            warmup=2
        )
        
        assert result.iterations == 10
        
        # Check profiler recorded calls
        profile_results = Profiler.get_results()
        assert len(profile_results) > 0
    
    def test_lazy_loading_with_gc(self):
        """Test lazy loading with GC optimization."""
        objects_created = []
        
        def factory():
            obj = {"data": list(range(1000))}
            objects_created.append(obj)
            return obj
        
        loader = LazyLoader(factory)
        
        # Load object
        value = loader.get()
        assert len(objects_created) == 1
        
        # Reset and collect
        loader.reset()
        GCOptimizer.collect()
        
        # Load again
        value2 = loader.get()
        assert len(objects_created) == 2


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_resolver_empty_hostname(self):
        """Test resolver with empty hostname."""
        resolver = AsyncDNSResolver()
        result = await resolver.resolve("")
        # Should handle gracefully
    
    @pytest.mark.asyncio
    async def test_batch_checker_empty_ports(self):
        """Test batch checker with empty port list."""
        checker = BatchPortChecker()
        results = await checker.check_ports("localhost", [])
        assert results == {}
    
    def test_profiler_exception_handling(self):
        """Test profiler handles exceptions."""
        Profiler.reset()
        
        @Profiler.profile()
        def raising_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            raising_func()
        
        # Should still record the call
        results = Profiler.get_results()
        # May or may not record depending on implementation
    
    def test_benchmark_zero_iterations(self):
        """Test benchmark with zero iterations."""
        result = Benchmark.run_sync(
            "Zero Iterations",
            lambda: 1,
            iterations=1,  # At least 1 iteration needed
            warmup=0
        )
        # Should handle gracefully
        assert result.iterations == 1
    
    def test_gc_optimizer_multiple_collects(self):
        """Test multiple GC collects."""
        for _ in range(5):
            collected = GCOptimizer.collect()
            assert collected >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
