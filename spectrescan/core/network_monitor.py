"""
Network Condition Monitor
Packet loss detection, latency adaptation, firewall detection, rate limiting.

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional, List
from collections import deque
from statistics import mean, stdev

logger = logging.getLogger(__name__)


@dataclass
class NetworkMetrics:
    """Network performance metrics."""
    latency_ms: float
    packet_loss_percent: float
    jitter_ms: float
    bandwidth_mbps: Optional[float]
    rtt_avg: float
    rtt_min: float
    rtt_max: float
    timestamp: float


class LatencyMonitor:
    """Monitor and track network latency."""
    
    def __init__(self, window_size: int = 100):
        """
        Initialize latency monitor.
        
        Args:
            window_size: Number of samples to keep in sliding window
        """
        self.window_size = window_size
        self.latencies = deque(maxlen=window_size)
        self.baseline_latency = None
        
        logger.info(f"LatencyMonitor: window size {window_size}")
    
    def record_latency(self, latency_ms: float) -> None:
        """
        Record a latency measurement.
        
        Args:
            latency_ms: Latency in milliseconds
        """
        self.latencies.append(latency_ms)
        
        # Set baseline on first measurement
        if self.baseline_latency is None:
            self.baseline_latency = latency_ms
    
    def get_avg_latency(self) -> float:
        """Get average latency."""
        if not self.latencies:
            return 0.0
        return mean(self.latencies)
    
    def get_jitter(self) -> float:
        """Get jitter (standard deviation of latency)."""
        if len(self.latencies) < 2:
            return 0.0
        return stdev(self.latencies)
    
    def is_high_latency(self, threshold_multiplier: float = 2.0) -> bool:
        """
        Check if current latency is abnormally high.
        
        Args:
            threshold_multiplier: Multiple of baseline to consider high
        
        Returns:
            True if latency is high
        """
        if not self.baseline_latency or not self.latencies:
            return False
        
        current = self.get_avg_latency()
        return current > self.baseline_latency * threshold_multiplier
    
    def get_stats(self) -> dict:
        """Get latency statistics."""
        if not self.latencies:
            return {
                "avg_ms": 0.0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "jitter_ms": 0.0,
                "baseline_ms": self.baseline_latency
            }
        
        return {
            "avg_ms": round(mean(self.latencies), 2),
            "min_ms": round(min(self.latencies), 2),
            "max_ms": round(max(self.latencies), 2),
            "jitter_ms": round(self.get_jitter(), 2),
            "baseline_ms": self.baseline_latency,
            "sample_count": len(self.latencies)
        }


class PacketLossDetector:
    """Detect packet loss and network issues."""
    
    def __init__(self, window_size: int = 100):
        """
        Initialize packet loss detector.
        
        Args:
            window_size: Number of samples in sliding window
        """
        self.window_size = window_size
        self.sent_count = 0
        self.success_count = 0
        self.timeout_count = 0
        self.error_count = 0
        
        self.recent_results = deque(maxlen=window_size)
        
        logger.info(f"PacketLossDetector: window size {window_size}")
    
    def record_sent(self) -> None:
        """Record a packet sent."""
        self.sent_count += 1
    
    def record_success(self) -> None:
        """Record a successful response."""
        self.success_count += 1
        self.recent_results.append(True)
    
    def record_timeout(self) -> None:
        """Record a timeout."""
        self.timeout_count += 1
        self.recent_results.append(False)
    
    def record_error(self) -> None:
        """Record an error."""
        self.error_count += 1
        self.recent_results.append(False)
    
    def get_loss_rate(self) -> float:
        """
        Calculate packet loss rate.
        
        Returns:
            Loss rate as percentage (0-100)
        """
        if self.sent_count == 0:
            return 0.0
        
        failed = self.timeout_count + self.error_count
        return (failed / self.sent_count) * 100
    
    def get_recent_loss_rate(self) -> float:
        """
        Calculate recent packet loss rate.
        
        Returns:
            Recent loss rate as percentage
        """
        if not self.recent_results:
            return 0.0
        
        failures = sum(1 for success in self.recent_results if not success)
        return (failures / len(self.recent_results)) * 100
    
    def is_high_loss(self, threshold: float = 10.0) -> bool:
        """
        Check if packet loss is high.
        
        Args:
            threshold: Loss percentage threshold
        
        Returns:
            True if loss is above threshold
        """
        return self.get_recent_loss_rate() > threshold
    
    def get_stats(self) -> dict:
        """Get packet loss statistics."""
        return {
            "sent": self.sent_count,
            "success": self.success_count,
            "timeout": self.timeout_count,
            "error": self.error_count,
            "loss_rate_percent": round(self.get_loss_rate(), 2),
            "recent_loss_percent": round(self.get_recent_loss_rate(), 2),
            "success_rate_percent": round((self.success_count / max(self.sent_count, 1)) * 100, 2)
        }


class FirewallDetector:
    """Detect firewall and filtering behavior."""
    
    def __init__(self):
        """Initialize firewall detector."""
        self.filtered_ports = set()
        self.open_ports = set()
        self.closed_ports = set()
        
        self.consecutive_filtered = 0
        self.consecutive_closed = 0
        
        logger.info("FirewallDetector initialized")
    
    def record_port_state(self, port: int, state: str) -> None:
        """
        Record port state.
        
        Args:
            port: Port number
            state: Port state (open/closed/filtered)
        """
        if state == "filtered":
            self.filtered_ports.add(port)
            self.consecutive_filtered += 1
            self.consecutive_closed = 0
        elif state == "open":
            self.open_ports.add(port)
            self.consecutive_filtered = 0
            self.consecutive_closed = 0
        elif state == "closed":
            self.closed_ports.add(port)
            self.consecutive_filtered = 0
            self.consecutive_closed += 1
    
    def detect_firewall_type(self) -> str:
        """
        Detect firewall type based on response patterns.
        
        Returns:
            Firewall type (drop/reject/stateful/none)
        """
        total_ports = len(self.filtered_ports) + len(self.open_ports) + len(self.closed_ports)
        
        if total_ports == 0:
            return "unknown"
        
        filtered_ratio = len(self.filtered_ports) / total_ports
        closed_ratio = len(self.closed_ports) / total_ports
        
        # Drop firewall: Most ports filtered
        if filtered_ratio > 0.8:
            return "drop"
        
        # Reject firewall: Most ports closed with RST
        if closed_ratio > 0.8:
            return "reject"
        
        # Stateful firewall: Mix of states
        if filtered_ratio > 0.2 and len(self.open_ports) > 0:
            return "stateful"
        
        return "none"
    
    def is_port_range_blocked(self, threshold: int = 50) -> bool:
        """
        Check if large port range appears blocked.
        
        Args:
            threshold: Number of consecutive filtered ports
        
        Returns:
            True if range appears blocked
        """
        return self.consecutive_filtered >= threshold
    
    def get_stats(self) -> dict:
        """Get firewall detection statistics."""
        total = len(self.filtered_ports) + len(self.open_ports) + len(self.closed_ports)
        
        return {
            "firewall_type": self.detect_firewall_type(),
            "open_ports": len(self.open_ports),
            "closed_ports": len(self.closed_ports),
            "filtered_ports": len(self.filtered_ports),
            "total_scanned": total,
            "filtered_percent": round((len(self.filtered_ports) / max(total, 1)) * 100, 2),
            "consecutive_filtered": self.consecutive_filtered
        }


class RateLimitDetector:
    """Detect rate limiting from target."""
    
    def __init__(self):
        """Initialize rate limit detector."""
        self.error_timestamps = deque(maxlen=100)
        self.rate_limited = False
        self.rate_limit_count = 0
        
        logger.info("RateLimitDetector initialized")
    
    def record_rate_limit_error(self) -> None:
        """Record a rate limit error."""
        self.error_timestamps.append(time.time())
        self.rate_limit_count += 1
        self.rate_limited = True
    
    def is_rate_limited(self, window_seconds: float = 10.0, threshold: int = 5) -> bool:
        """
        Check if currently being rate limited.
        
        Args:
            window_seconds: Time window to check
            threshold: Number of errors in window to consider rate limited
        
        Returns:
            True if rate limited
        """
        if not self.error_timestamps:
            return False
        
        now = time.time()
        recent_errors = sum(1 for ts in self.error_timestamps if now - ts <= window_seconds)
        
        return recent_errors >= threshold
    
    def get_suggested_delay(self) -> float:
        """
        Get suggested delay to avoid rate limiting.
        
        Returns:
            Suggested delay in seconds
        """
        if not self.is_rate_limited():
            return 0.0
        
        # Calculate rate of errors
        if len(self.error_timestamps) < 2:
            return 1.0
        
        recent = list(self.error_timestamps)[-10:]
        if len(recent) < 2:
            return 1.0
        
        time_span = recent[-1] - recent[0]
        rate = len(recent) / max(time_span, 1)
        
        # Suggest delay to reduce rate by 50%
        return max(1.0 / (rate * 0.5), 1.0)
    
    def reset(self) -> None:
        """Reset rate limit detection."""
        self.rate_limited = False
        self.error_timestamps.clear()
    
    def get_stats(self) -> dict:
        """Get rate limit statistics."""
        return {
            "rate_limited": self.rate_limited,
            "total_rate_limit_errors": self.rate_limit_count,
            "recent_errors": len(self.error_timestamps),
            "suggested_delay_seconds": round(self.get_suggested_delay(), 2)
        }


class NetworkConditionMonitor:
    """
    Unified network condition monitor.
    Combines latency, packet loss, firewall, and rate limit detection.
    """
    
    def __init__(
        self,
        adaptive_timeout: bool = True,
        initial_timeout: float = 2.0
    ):
        """
        Initialize network condition monitor.
        
        Args:
            adaptive_timeout: Automatically adjust timeout based on conditions
            initial_timeout: Initial timeout value
        """
        self.latency_monitor = LatencyMonitor()
        self.packet_loss_detector = PacketLossDetector()
        self.firewall_detector = FirewallDetector()
        self.rate_limit_detector = RateLimitDetector()
        
        self.adaptive_timeout = adaptive_timeout
        self.current_timeout = initial_timeout
        self.initial_timeout = initial_timeout
        
        logger.info(f"NetworkConditionMonitor: adaptive={adaptive_timeout}, timeout={initial_timeout}s")
    
    def record_request(
        self,
        port: int,
        state: str,
        latency_ms: Optional[float] = None,
        success: bool = True,
        rate_limited: bool = False
    ) -> None:
        """
        Record a request and its result.
        
        Args:
            port: Port number
            state: Port state (open/closed/filtered)
            latency_ms: Response latency in ms
            success: Whether request succeeded
            rate_limited: Whether rate limited
        """
        # Record packet
        self.packet_loss_detector.record_sent()
        
        if success:
            self.packet_loss_detector.record_success()
        else:
            self.packet_loss_detector.record_timeout()
        
        # Record latency
        if latency_ms is not None:
            self.latency_monitor.record_latency(latency_ms)
        
        # Record port state
        self.firewall_detector.record_port_state(port, state)
        
        # Record rate limiting
        if rate_limited:
            self.rate_limit_detector.record_rate_limit_error()
    
    def adjust_timeout(self) -> float:
        """
        Adjust timeout based on network conditions.
        
        Returns:
            Recommended timeout value
        """
        if not self.adaptive_timeout:
            return self.current_timeout
        
        latency_stats = self.latency_monitor.get_stats()
        
        if latency_stats["avg_ms"] == 0:
            return self.current_timeout
        
        # Base timeout on average + 3 * jitter
        avg_ms = latency_stats["avg_ms"]
        jitter_ms = latency_stats["jitter_ms"]
        
        recommended_timeout = (avg_ms + 3 * jitter_ms) / 1000
        
        # Clamp to reasonable range
        recommended_timeout = max(0.5, min(recommended_timeout, 30.0))
        
        # Apply gradually
        self.current_timeout = (self.current_timeout * 0.7) + (recommended_timeout * 0.3)
        
        return self.current_timeout
    
    def get_network_metrics(self) -> NetworkMetrics:
        """Get comprehensive network metrics."""
        latency_stats = self.latency_monitor.get_stats()
        packet_stats = self.packet_loss_detector.get_stats()
        
        return NetworkMetrics(
            latency_ms=latency_stats["avg_ms"],
            packet_loss_percent=packet_stats["recent_loss_percent"],
            jitter_ms=latency_stats["jitter_ms"],
            bandwidth_mbps=None,
            rtt_avg=latency_stats["avg_ms"],
            rtt_min=latency_stats["min_ms"],
            rtt_max=latency_stats["max_ms"],
            timestamp=time.time()
        )
    
    def get_recommendations(self) -> dict:
        """
        Get recommendations for scan optimization.
        
        Returns:
            Dictionary of recommendations
        """
        recommendations = {
            "timeout": round(self.adjust_timeout(), 2),
            "warnings": []
        }
        
        # Check conditions
        if self.latency_monitor.is_high_latency():
            recommendations["warnings"].append("High latency detected, increase timeout")
        
        if self.packet_loss_detector.is_high_loss():
            recommendations["warnings"].append("High packet loss, reduce concurrency")
        
        if self.firewall_detector.is_port_range_blocked():
            recommendations["warnings"].append("Firewall blocking detected")
        
        if self.rate_limit_detector.is_rate_limited():
            delay = self.rate_limit_detector.get_suggested_delay()
            recommendations["warnings"].append(f"Rate limiting detected, add {delay:.1f}s delay")
            recommendations["suggested_delay"] = delay
        
        return recommendations
    
    def get_summary(self) -> dict:
        """Get comprehensive network condition summary."""
        return {
            "latency": self.latency_monitor.get_stats(),
            "packet_loss": self.packet_loss_detector.get_stats(),
            "firewall": self.firewall_detector.get_stats(),
            "rate_limit": self.rate_limit_detector.get_stats(),
            "timeout": {
                "current": round(self.current_timeout, 2),
                "initial": self.initial_timeout,
                "adaptive": self.adaptive_timeout
            },
            "recommendations": self.get_recommendations()
        }
