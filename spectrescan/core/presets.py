"""
Scan preset configurations for SpectreScan
by BitSpectreLabs
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional
from spectrescan.core.utils import get_common_ports


class ScanPreset(Enum):
    """Predefined scan configurations."""
    QUICK = "quick"
    TOP_PORTS = "top-ports"
    FULL = "full"
    STEALTH = "stealth"
    SAFE = "safe"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


@dataclass
class ScanConfig:
    """Configuration for a scan operation."""
    name: str
    description: str
    ports: List[int]
    scan_types: List[str]  # ["tcp", "syn", "udp"]
    threads: int
    timeout: float  # seconds
    rate_limit: Optional[int]  # packets per second
    enable_service_detection: bool
    enable_os_detection: bool
    enable_banner_grabbing: bool
    randomize: bool
    timing_template: int  # 0-5 (paranoid to insane)
    
    def __str__(self) -> str:
        return f"{self.name}: {self.description}"


def get_preset_config(preset: ScanPreset) -> ScanConfig:
    """
    Get configuration for a scan preset.
    
    Args:
        preset: Scan preset enum
        
    Returns:
        ScanConfig object
    """
    configs = {
        ScanPreset.QUICK: ScanConfig(
            name="Quick Scan",
            description="Fast scan of top 100 ports",
            ports=get_common_ports(100),
            scan_types=["tcp"],
            threads=100,
            timeout=1.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=False,
            enable_banner_grabbing=True,
            randomize=False,
            timing_template=4  # Aggressive
        ),
        
        ScanPreset.TOP_PORTS: ScanConfig(
            name="Top Ports",
            description="Scan top 1000 most common ports",
            ports=get_common_ports(1000),
            scan_types=["tcp"],
            threads=200,
            timeout=2.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=False,
            timing_template=3  # Normal
        ),
        
        ScanPreset.FULL: ScanConfig(
            name="Full Scan",
            description="Comprehensive scan of all 65535 ports",
            ports=list(range(1, 65536)),
            scan_types=["tcp", "udp"],
            threads=500,
            timeout=3.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=False,
            timing_template=3  # Normal
        ),
        
        ScanPreset.STEALTH: ScanConfig(
            name="Stealth Scan",
            description="Low-profile SYN scan with randomization",
            ports=get_common_ports(100),
            scan_types=["syn"],
            threads=10,
            timeout=5.0,
            rate_limit=50,  # 50 packets per second
            enable_service_detection=False,
            enable_os_detection=False,
            enable_banner_grabbing=False,
            randomize=True,
            timing_template=1  # Sneaky
        ),
        
        ScanPreset.SAFE: ScanConfig(
            name="Safe Scan",
            description="Non-intrusive scan with conservative timing",
            ports=get_common_ports(100),
            scan_types=["tcp"],
            threads=20,
            timeout=5.0,
            rate_limit=20,
            enable_service_detection=True,
            enable_os_detection=False,
            enable_banner_grabbing=True,
            randomize=False,
            timing_template=2  # Polite
        ),
        
        ScanPreset.AGGRESSIVE: ScanConfig(
            name="Aggressive Scan",
            description="Fast, comprehensive scan with all detection enabled",
            ports=list(range(1, 65536)),
            scan_types=["tcp", "syn", "udp"],
            threads=1000,
            timeout=1.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=False,
            timing_template=5  # Insane
        ),
        
        ScanPreset.CUSTOM: ScanConfig(
            name="Custom Scan",
            description="User-defined configuration",
            ports=get_common_ports(100),
            scan_types=["tcp"],
            threads=100,
            timeout=2.0,
            rate_limit=None,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=False,
            timing_template=3  # Normal
        ),
    }
    
    return configs[preset]


def get_timing_parameters(template: int) -> dict:
    """
    Get timing parameters based on template.
    
    Args:
        template: Timing template (0-5)
            0 = Paranoid
            1 = Sneaky
            2 = Polite
            3 = Normal
            4 = Aggressive
            5 = Insane
            
    Returns:
        Dictionary of timing parameters
    """
    templates = {
        0: {  # Paranoid
            "name": "Paranoid",
            "timeout": 10.0,
            "threads": 1,
            "delay_between_probes": 5.0,
            "rate_limit": 1
        },
        1: {  # Sneaky
            "name": "Sneaky",
            "timeout": 8.0,
            "threads": 5,
            "delay_between_probes": 2.0,
            "rate_limit": 10
        },
        2: {  # Polite
            "name": "Polite",
            "timeout": 5.0,
            "threads": 20,
            "delay_between_probes": 1.0,
            "rate_limit": 50
        },
        3: {  # Normal
            "name": "Normal",
            "timeout": 3.0,
            "threads": 100,
            "delay_between_probes": 0.1,
            "rate_limit": None
        },
        4: {  # Aggressive
            "name": "Aggressive",
            "timeout": 1.5,
            "threads": 500,
            "delay_between_probes": 0.01,
            "rate_limit": None
        },
        5: {  # Insane
            "name": "Insane",
            "timeout": 0.5,
            "threads": 2000,
            "delay_between_probes": 0.001,
            "rate_limit": None
        }
    }
    
    return templates.get(template, templates[3])


def describe_preset(preset: ScanPreset) -> str:
    """
    Get detailed description of a preset.
    
    Args:
        preset: Scan preset
        
    Returns:
        Formatted description string
    """
    config = get_preset_config(preset)
    timing = get_timing_parameters(config.timing_template)
    
    description = f"""
Preset: {config.name}
Description: {config.description}

Configuration:
  - Ports: {len(config.ports)} ports
  - Scan Types: {', '.join(config.scan_types).upper()}
  - Threads: {config.threads}
  - Timeout: {config.timeout}s
  - Timing: {timing['name']}
  - Service Detection: {'Yes' if config.enable_service_detection else 'No'}
  - OS Detection: {'Yes' if config.enable_os_detection else 'No'}
  - Banner Grabbing: {'Yes' if config.enable_banner_grabbing else 'No'}
  - Randomized: {'Yes' if config.randomize else 'No'}
"""
    
    if config.rate_limit:
        description += f"  - Rate Limit: {config.rate_limit} packets/sec\n"
    
    return description.strip()


def list_presets() -> str:
    """List all available presets with descriptions."""
    output = "Available Scan Presets:\n\n"
    
    for preset in ScanPreset:
        if preset == ScanPreset.CUSTOM:
            continue
        config = get_preset_config(preset)
        output += f"  --{preset.value}\n"
        output += f"    {config.description}\n"
        output += f"    Ports: {len(config.ports)}, "
        output += f"Threads: {config.threads}, "
        output += f"Timeout: {config.timeout}s\n\n"
    
    return output
