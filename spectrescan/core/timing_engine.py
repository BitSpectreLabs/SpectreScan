"""
Adaptive timing engine for SpectreScan
by BitSpectreLabs

Provides Nmap-style timing templates (T0-T5) for controlling scan speed and aggression.
"""

from dataclasses import dataclass
from typing import Optional
from enum import Enum


class TimingLevel(Enum):
    """Timing template levels (like Nmap's -T flag)."""
    PARANOID = "T0"
    SNEAKY = "T1"
    POLITE = "T2"
    NORMAL = "T3"
    AGGRESSIVE = "T4"
    INSANE = "T5"


@dataclass
class TimingTemplate:
    """
    Scan timing configuration template.
    
    Controls concurrency, timeouts, retries, and delays to balance
    speed vs stealth vs accuracy.
    """
    name: str
    level: TimingLevel
    max_concurrent: int          # Maximum concurrent connections
    timeout: float                # Default socket timeout (seconds)
    min_rtt_timeout: float        # Minimum RTT timeout (seconds)
    max_rtt_timeout: float        # Maximum RTT timeout (seconds)
    initial_rtt_timeout: float    # Initial RTT timeout before measurement (seconds)
    max_retries: int              # Maximum retries for failed connections
    scan_delay: float             # Delay between port scans (seconds)
    host_timeout: float           # Host discovery timeout (seconds)
    
    def __post_init__(self):
        """Validate timing parameters."""
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.min_rtt_timeout > self.max_rtt_timeout:
            raise ValueError("min_rtt_timeout must be <= max_rtt_timeout")


# Predefined timing templates (matches Nmap behavior)
TIMING_TEMPLATES = {
    TimingLevel.PARANOID: TimingTemplate(
        name="Paranoid",
        level=TimingLevel.PARANOID,
        max_concurrent=1,           # Serial scanning only
        timeout=300.0,              # 5 minutes
        min_rtt_timeout=100.0,      # 100 seconds
        max_rtt_timeout=300.0,      # 5 minutes
        initial_rtt_timeout=100.0,  # 100 seconds initial
        max_retries=1,              # Minimal retries
        scan_delay=5.0,             # 5 second delay between ports
        host_timeout=300.0          # 5 minutes for host discovery
    ),
    
    TimingLevel.SNEAKY: TimingTemplate(
        name="Sneaky",
        level=TimingLevel.SNEAKY,
        max_concurrent=10,          # Very limited concurrency
        timeout=15.0,               # 15 seconds
        min_rtt_timeout=5.0,        # 5 seconds
        max_rtt_timeout=15.0,       # 15 seconds
        initial_rtt_timeout=10.0,   # 10 seconds initial
        max_retries=2,              # Limited retries
        scan_delay=1.0,             # 1 second delay between ports
        host_timeout=15.0           # 15 seconds for host discovery
    ),
    
    TimingLevel.POLITE: TimingTemplate(
        name="Polite",
        level=TimingLevel.POLITE,
        max_concurrent=50,          # Moderate concurrency
        timeout=10.0,               # 10 seconds
        min_rtt_timeout=2.0,        # 2 seconds
        max_rtt_timeout=10.0,       # 10 seconds
        initial_rtt_timeout=5.0,    # 5 seconds initial
        max_retries=2,              # Moderate retries
        scan_delay=0.4,             # 400ms delay between ports
        host_timeout=10.0           # 10 seconds for host discovery
    ),
    
    TimingLevel.NORMAL: TimingTemplate(
        name="Normal",
        level=TimingLevel.NORMAL,
        max_concurrent=500,         # High concurrency
        timeout=3.0,                # 3 seconds (balanced)
        min_rtt_timeout=0.5,        # 500ms minimum
        max_rtt_timeout=5.0,        # 5 seconds maximum
        initial_rtt_timeout=1.0,    # 1 second initial
        max_retries=3,              # Good retry count
        scan_delay=0.0,             # No delay (fast)
        host_timeout=5.0            # 5 seconds for host discovery
    ),
    
    TimingLevel.AGGRESSIVE: TimingTemplate(
        name="Aggressive",
        level=TimingLevel.AGGRESSIVE,
        max_concurrent=1000,        # Very high concurrency
        timeout=1.5,                # 1.5 seconds
        min_rtt_timeout=0.1,        # 100ms minimum
        max_rtt_timeout=2.0,        # 2 seconds maximum
        initial_rtt_timeout=0.5,    # 500ms initial
        max_retries=3,              # Aggressive retries
        scan_delay=0.0,             # No delay (very fast)
        host_timeout=2.0            # 2 seconds for host discovery
    ),
    
    TimingLevel.INSANE: TimingTemplate(
        name="Insane",
        level=TimingLevel.INSANE,
        max_concurrent=2000,        # Extreme concurrency
        timeout=0.5,                # 500ms (very aggressive)
        min_rtt_timeout=0.05,       # 50ms minimum
        max_rtt_timeout=1.0,        # 1 second maximum
        initial_rtt_timeout=0.3,    # 300ms initial
        max_retries=2,              # Fast-fail approach
        scan_delay=0.0,             # No delay (insane speed)
        host_timeout=1.0            # 1 second for host discovery
    ),
}


def get_timing_template(level: TimingLevel = TimingLevel.NORMAL) -> TimingTemplate:
    """
    Get timing template by level.
    
    Args:
        level: Timing level (T0-T5)
        
    Returns:
        TimingTemplate object
        
    Examples:
        >>> template = get_timing_template(TimingLevel.AGGRESSIVE)
        >>> template.max_concurrent
        1000
    """
    return TIMING_TEMPLATES[level]


def get_timing_template_by_name(name: str) -> Optional[TimingTemplate]:
    """
    Get timing template by name (T0, T1, etc).
    
    Args:
        name: Template name (T0, T1, T2, T3, T4, T5)
        
    Returns:
        TimingTemplate object or None if not found
        
    Examples:
        >>> template = get_timing_template_by_name("T4")
        >>> template.name
        'Aggressive'
    """
    name = name.upper()
    for level, template in TIMING_TEMPLATES.items():
        if level.value == name:
            return template
    return None


def list_timing_templates() -> dict:
    """
    Get all available timing templates.
    
    Returns:
        Dictionary mapping level names to templates
        
    Examples:
        >>> templates = list_timing_templates()
        >>> templates['T3'].name
        'Normal'
    """
    return {level.value: template for level, template in TIMING_TEMPLATES.items()}


class RTTCalculator:
    """
    Calculate and track Round-Trip Time (RTT) for adaptive timeouts.
    
    Measures actual network latency and adjusts timeouts dynamically.
    """
    
    def __init__(self, timing_template: TimingTemplate):
        """
        Initialize RTT calculator.
        
        Args:
            timing_template: Timing template to use
        """
        self.template = timing_template
        self.rtt_samples = []
        self.current_timeout = timing_template.initial_rtt_timeout
        self.max_samples = 20  # Keep last 20 samples
    
    def add_sample(self, rtt: float) -> None:
        """
        Add RTT sample and recalculate timeout.
        
        Args:
            rtt: Round-trip time in seconds
        """
        if rtt <= 0:
            return
        
        self.rtt_samples.append(rtt)
        
        # Keep only recent samples
        if len(self.rtt_samples) > self.max_samples:
            self.rtt_samples.pop(0)
        
        # Calculate new timeout (mean + 2*stddev, clamped to min/max)
        if len(self.rtt_samples) >= 3:
            mean_rtt = sum(self.rtt_samples) / len(self.rtt_samples)
            
            # Calculate standard deviation
            variance = sum((x - mean_rtt) ** 2 for x in self.rtt_samples) / len(self.rtt_samples)
            stddev = variance ** 0.5
            
            # New timeout = mean + 2*stddev (covers ~95% of cases)
            new_timeout = mean_rtt + (2 * stddev)
            
            # Clamp to template limits
            self.current_timeout = max(
                self.template.min_rtt_timeout,
                min(new_timeout, self.template.max_rtt_timeout)
            )
    
    def get_timeout(self) -> float:
        """
        Get current adaptive timeout.
        
        Returns:
            Current timeout in seconds
        """
        return self.current_timeout
    
    def reset(self) -> None:
        """Reset RTT calculator to initial state."""
        self.rtt_samples = []
        self.current_timeout = self.template.initial_rtt_timeout


def create_custom_timing(
    name: str = "Custom",
    max_concurrent: int = 500,
    timeout: float = 3.0,
    scan_delay: float = 0.0
) -> TimingTemplate:
    """
    Create a custom timing template.
    
    Args:
        name: Template name
        max_concurrent: Maximum concurrent connections
        timeout: Socket timeout in seconds
        scan_delay: Delay between scans in seconds
        
    Returns:
        Custom TimingTemplate
        
    Examples:
        >>> template = create_custom_timing("Fast", 1000, 1.0, 0.0)
        >>> template.max_concurrent
        1000
    """
    return TimingTemplate(
        name=name,
        level=TimingLevel.NORMAL,  # Custom templates use NORMAL as base
        max_concurrent=max_concurrent,
        timeout=timeout,
        min_rtt_timeout=timeout * 0.2,
        max_rtt_timeout=timeout * 2.0,
        initial_rtt_timeout=timeout,
        max_retries=3,
        scan_delay=scan_delay,
        host_timeout=timeout * 2.0
    )
