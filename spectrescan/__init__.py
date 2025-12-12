"""
SpectreScan - Professional-grade Port Scanner
by BitSpectreLabs

A high-performance, multi-interface port scanning toolkit.
"""

__version__ = "3.0.0"
__author__ = "BitSpectreLabs"
__license__ = "MIT"

from spectrescan.core.scanner import PortScanner
from spectrescan.core.presets import ScanPreset

__all__ = ["PortScanner", "ScanPreset"]
