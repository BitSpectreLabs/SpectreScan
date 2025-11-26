"""
Tests for error recovery module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from spectrescan.core.error_recovery import (
    RetryStrategy,
    retry_async,
    PartialResultsManager,
    GracefulDegradation,
    ErrorSeverity
)


def test_retry_strategy():
    """Test retry strategy."""
    strategy = RetryStrategy(
        max_retries=3,
        base_delay=1.0,
        max_delay=30.0
    )
    
    # Test delay calculation
    delay_0 = strategy.get_delay(0)
    delay_1 = strategy.get_delay(1)
    delay_2 = strategy.get_delay(2)
    
    assert delay_0 < delay_1 < delay_2
    assert delay_2 <= 30.0  # Max delay
    
    # Test retry decision
    assert strategy.should_retry(0, ConnectionError())
    assert strategy.should_retry(1, TimeoutError())
    assert not strategy.should_retry(3, ConnectionError())  # Max retries
    assert not strategy.should_retry(0, ValueError())  # Non-retryable


@pytest.mark.asyncio
async def test_retry_async_success():
    """Test async retry on success."""
    call_count = 0
    
    async def succeeds():
        nonlocal call_count
        call_count += 1
        return "success"
    
    result = await retry_async(succeeds)
    
    assert result == "success"
    assert call_count == 1  # Only called once


@pytest.mark.asyncio
async def test_retry_async_with_retries():
    """Test async retry with failures then success."""
    call_count = 0
    
    async def fails_twice():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("Connection failed")
        return "success"
    
    strategy = RetryStrategy(max_retries=3, base_delay=0.1)
    result = await retry_async(fails_twice, strategy=strategy)
    
    assert result == "success"
    assert call_count == 3


@pytest.mark.asyncio
async def test_retry_async_max_retries():
    """Test async retry exhausting max retries."""
    async def always_fails():
        raise ConnectionError("Always fails")
    
    strategy = RetryStrategy(max_retries=2, base_delay=0.1)
    
    with pytest.raises(ConnectionError):
        await retry_async(always_fails, strategy=strategy)


def test_partial_results_manager():
    """Test partial results manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = PartialResultsManager(checkpoint_dir=Path(tmpdir))
        
        # Add results
        manager.add_result({"port": 80, "state": "open"})
        manager.add_result({"port": 443, "state": "open"})
        manager.set_metadata("target", "127.0.0.1")
        
        # Save checkpoint
        scan_id = "test_scan"
        checkpoint_path = manager.save_checkpoint(scan_id)
        
        assert checkpoint_path.exists()
        
        # Load checkpoint
        checkpoint = manager.load_checkpoint(scan_id)
        
        assert checkpoint["scan_id"] == scan_id
        assert len(checkpoint["results"]) == 2
        assert checkpoint["metadata"]["target"] == "127.0.0.1"
        
        # List checkpoints
        checkpoints = manager.list_checkpoints()
        assert len(checkpoints) == 1
        assert checkpoints[0]["scan_id"] == scan_id
        
        # Delete checkpoint
        manager.delete_checkpoint(scan_id)
        assert not checkpoint_path.exists()


def test_graceful_degradation():
    """Test graceful degradation."""
    degradation = GracefulDegradation()
    
    # Record errors
    for i in range(9):
        should_degrade = degradation.record_error("feature1", ValueError())
        assert not should_degrade  # Not yet
    
    # 10th error triggers degradation
    should_degrade = degradation.record_error("feature1", ValueError())
    assert should_degrade
    
    # Check if degraded
    assert degradation.is_degraded("feature1")
    assert not degradation.is_degraded("feature2")
    
    # Restore feature
    degradation.restore_feature("feature1")
    assert not degradation.is_degraded("feature1")
    
    # Get status
    status = degradation.get_status()
    assert "degraded_features" in status
    assert "error_counts" in status


def test_error_severity_enum():
    """Test ErrorSeverity enum."""
    assert ErrorSeverity.RECOVERABLE.value == "recoverable"
    assert ErrorSeverity.DEGRADED.value == "degraded"
    assert ErrorSeverity.FATAL.value == "fatal"
