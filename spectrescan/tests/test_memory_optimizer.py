"""
Tests for memory optimization module.

Author: BitSpectreLabs
License: MIT
"""

import sys
import pytest
import tempfile
from pathlib import Path

# Skip if psutil is not available
psutil = pytest.importorskip("psutil", reason="psutil not installed")

from spectrescan.core.memory_optimizer import (
    MemoryMonitor,
    StreamingResultWriter,
    MemoryOptimizedScanner,
    optimize_memory_settings
)


def test_memory_monitor():
    """Test memory monitor."""
    monitor = MemoryMonitor(max_memory_mb=1024)
    
    stats = monitor.get_memory_usage()
    assert stats.rss_mb > 0
    assert stats.vms_mb > 0
    assert 0 <= stats.percent <= 100
    
    # Check limit (should be within limit initially)
    assert monitor.check_memory_limit() is True
    
    # Get summary
    summary = monitor.get_memory_summary()
    assert "current_mb" in summary
    assert "initial_mb" in summary
    assert "percent" in summary


def test_streaming_result_writer():
    """Test streaming result writer."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "results.json"
        
        writer = StreamingResultWriter(output_path)
        
        # Write some results
        writer.write_result({"host": "127.0.0.1", "port": 80, "state": "open"})
        writer.write_result({"host": "127.0.0.1", "port": 443, "state": "open"})
        writer.write_result({"host": "127.0.0.1", "port": 22, "state": "closed"})
        
        writer.close()
        
        # Verify file was created
        assert output_path.exists()
        
        # Verify content
        import json
        with open(output_path) as f:
            results = json.load(f)
        
        assert len(results) == 3
        assert results[0]["port"] == 80
        assert results[1]["port"] == 443
        assert results[2]["port"] == 22


def test_memory_optimized_scanner():
    """Test memory optimized scanner."""
    scanner = MemoryOptimizedScanner(
        max_memory_mb=2048,
        gc_interval=1000,
        stream_results=True
    )
    
    assert scanner.memory_monitor.max_memory_mb == 2048
    assert scanner.gc_interval == 1000
    assert scanner.stream_results is True
    
    # Get initial stats
    stats = scanner.get_stats()
    assert "results_processed" in stats
    assert "memory" in stats
    assert stats["results_processed"] == 0


def test_optimize_memory_settings():
    """Test memory settings optimization."""
    settings = optimize_memory_settings()
    
    assert "max_memory_mb" in settings
    assert "gc_interval" in settings
    assert "stream_results" in settings
    assert "system_info" in settings
    
    assert settings["max_memory_mb"] > 0
    assert settings["gc_interval"] > 0
    assert isinstance(settings["stream_results"], bool)


def test_streaming_writer_no_file():
    """Test streaming writer without file (in-memory only)."""
    writer = StreamingResultWriter(output_path=None)
    
    # Should not crash when writing
    writer.write_result({"port": 80})
    writer.close()
    
    assert writer.result_count == 0  # Not tracked without file
