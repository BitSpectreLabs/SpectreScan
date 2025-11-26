"""
Tests for network condition monitoring.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from spectrescan.core.network_monitor import (
    LatencyMonitor,
    PacketLossDetector,
    FirewallDetector,
    RateLimitDetector,
    NetworkConditionMonitor
)


def test_latency_monitor():
    """Test latency monitor."""
    monitor = LatencyMonitor(window_size=100)
    
    # Record latencies
    monitor.record_latency(50.0)
    monitor.record_latency(55.0)
    monitor.record_latency(45.0)
    
    # Get average
    avg = monitor.get_avg_latency()
    assert 45.0 <= avg <= 55.0
    
    # Get jitter
    jitter = monitor.get_jitter()
    assert jitter >= 0
    
    # Get stats
    stats = monitor.get_stats()
    assert "avg_ms" in stats
    assert "min_ms" in stats
    assert "max_ms" in stats
    assert "jitter_ms" in stats


def test_packet_loss_detector():
    """Test packet loss detector."""
    detector = PacketLossDetector(window_size=100)
    
    # Record packets
    detector.record_sent()
    detector.record_success()
    
    detector.record_sent()
    detector.record_timeout()
    
    detector.record_sent()
    detector.record_error()
    
    # Get loss rate
    loss_rate = detector.get_loss_rate()
    assert 0 <= loss_rate <= 100
    assert loss_rate > 0  # We had failures
    
    # Get stats
    stats = detector.get_stats()
    assert stats["sent"] == 3
    assert stats["success"] == 1
    assert stats["timeout"] == 1
    assert stats["error"] == 1


def test_firewall_detector():
    """Test firewall detector."""
    detector = FirewallDetector()
    
    # Record port states
    detector.record_port_state(80, "open")
    detector.record_port_state(443, "open")
    detector.record_port_state(22, "filtered")
    detector.record_port_state(23, "filtered")
    detector.record_port_state(21, "closed")
    
    # Detect firewall type
    fw_type = detector.detect_firewall_type()
    assert fw_type in ["drop", "reject", "stateful", "none", "unknown"]
    
    # Get stats
    stats = detector.get_stats()
    assert stats["open_ports"] == 2
    assert stats["closed_ports"] == 1
    assert stats["filtered_ports"] == 2


def test_rate_limit_detector():
    """Test rate limit detector."""
    detector = RateLimitDetector()
    
    # Record rate limit errors
    for _ in range(10):
        detector.record_rate_limit_error()
    
    # Check if rate limited
    assert detector.is_rate_limited()
    
    # Get suggested delay
    delay = detector.get_suggested_delay()
    assert delay > 0
    
    # Get stats
    stats = detector.get_stats()
    assert stats["rate_limited"] is True
    assert stats["total_rate_limit_errors"] == 10


def test_network_condition_monitor():
    """Test unified network condition monitor."""
    monitor = NetworkConditionMonitor(
        adaptive_timeout=True,
        initial_timeout=2.0
    )
    
    # Record requests
    monitor.record_request(
        port=80,
        state="open",
        latency_ms=50.0,
        success=True
    )
    
    monitor.record_request(
        port=443,
        state="open",
        latency_ms=55.0,
        success=True
    )
    
    # Get metrics
    metrics = monitor.get_network_metrics()
    assert metrics.latency_ms > 0
    assert 0 <= metrics.packet_loss_percent <= 100
    
    # Get recommendations
    recommendations = monitor.get_recommendations()
    assert "timeout" in recommendations
    assert "warnings" in recommendations
    
    # Get summary
    summary = monitor.get_summary()
    assert "latency" in summary
    assert "packet_loss" in summary
    assert "firewall" in summary
    assert "rate_limit" in summary
    assert "timeout" in summary
    assert "recommendations" in summary


def test_adaptive_timeout():
    """Test adaptive timeout adjustment."""
    monitor = NetworkConditionMonitor(
        adaptive_timeout=True,
        initial_timeout=2.0
    )
    
    # Record high latencies
    for _ in range(10):
        monitor.record_request(
            port=80,
            state="open",
            latency_ms=1000.0,
            success=True
        )
    
    # Timeout should adjust (may increase or stay same based on algorithm)
    new_timeout = monitor.adjust_timeout()
    assert new_timeout >= 1.0  # Should be at least 1 second
