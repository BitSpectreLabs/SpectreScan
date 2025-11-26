"""
Dynamic completion data providers for SpectreScan
by BitSpectreLabs

Provides dynamic completion values for profile names, history IDs, and other
context-sensitive completion options.
"""

from typing import List, Optional
from pathlib import Path


def get_profile_names() -> List[str]:
    """
    Get list of available profile names for completion.
    
    Returns:
        List of profile names
    """
    try:
        from spectrescan.core.profiles import ProfileManager
        manager = ProfileManager()
        return manager.list_profiles()
    except Exception:
        return []


def get_history_ids(limit: int = 20) -> List[str]:
    """
    Get list of recent scan history IDs for completion.
    
    Args:
        limit: Maximum number of history IDs to return
        
    Returns:
        List of history IDs (most recent first)
    """
    try:
        from spectrescan.core.history import HistoryManager
        manager = HistoryManager()
        entries = manager.list_entries(limit=limit)
        return [entry.id for entry in entries]
    except Exception:
        return []


def get_preset_names() -> List[str]:
    """
    Get list of available scan preset names for completion.
    
    Returns:
        List of preset names
    """
    return [
        "quick",
        "top-ports",
        "full",
        "stealth",
        "safe",
        "aggressive"
    ]


def get_scan_types() -> List[str]:
    """
    Get list of available scan types for completion.
    
    Returns:
        List of scan type names
    """
    return [
        "tcp",
        "syn",
        "udp",
        "async"
    ]


def get_output_formats() -> List[str]:
    """
    Get list of available output formats for completion.
    
    Returns:
        List of output format names
    """
    return [
        "json",
        "csv",
        "xml",
        "html",
        "pdf",
        "markdown"
    ]


def get_timing_templates() -> List[str]:
    """
    Get list of timing template values for completion.
    
    Returns:
        List of timing template values (T0-T5)
    """
    return ["0", "1", "2", "3", "4", "5"]


def get_commands() -> List[str]:
    """
    Get list of available CLI commands for completion.
    
    Returns:
        List of command names
    """
    return [
        "scan",
        "presets",
        "ssl",
        "cve",
        "dns",
        "version",
        "gui",
        "tui",
        "api",
        "profile",
        "history",
        "compare",
        "resume",
        "checkpoint",
        "config",
        "completion"
    ]


def get_profile_subcommands() -> List[str]:
    """
    Get list of profile subcommands for completion.
    
    Returns:
        List of profile subcommand names
    """
    return [
        "list",
        "load",
        "delete",
        "export",
        "import"
    ]


def get_history_subcommands() -> List[str]:
    """
    Get list of history subcommands for completion.
    
    Returns:
        List of history subcommand names
    """
    return [
        "list",
        "show",
        "search",
        "delete",
        "clear",
        "stats"
    ]


def get_config_subcommands() -> List[str]:
    """
    Get list of config subcommands for completion.
    
    Returns:
        List of config subcommand names
    """
    return [
        "show",
        "create",
        "validate",
        "list-options"
    ]


def get_completion_subcommands() -> List[str]:
    """
    Get list of completion subcommands for completion.
    
    Returns:
        List of completion subcommand names
    """
    return [
        "install",
        "show",
        "bash",
        "zsh",
        "powershell",
        "fish"
    ]


def get_checkpoint_files(directory: Optional[Path] = None) -> List[str]:
    """
    Get list of checkpoint files for completion.
    
    Args:
        directory: Directory to search for checkpoint files
        
    Returns:
        List of checkpoint file paths
    """
    try:
        search_dir = directory or Path.cwd()
        return [str(f) for f in search_dir.glob("*.checkpoint.json")]
    except Exception:
        return []


def get_config_files(directory: Optional[Path] = None) -> List[str]:
    """
    Get list of configuration files for completion.
    
    Args:
        directory: Directory to search for config files
        
    Returns:
        List of config file paths
    """
    try:
        search_dirs = [directory] if directory else [
            Path.cwd(),
            Path.home() / ".spectrescan",
            Path("/etc/spectrescan")
        ]
        
        config_patterns = ["*.yaml", "*.yml", "*.json", "*.toml"]
        files = []
        
        for search_dir in search_dirs:
            if search_dir and search_dir.exists():
                for pattern in config_patterns:
                    files.extend(str(f) for f in search_dir.glob(pattern))
        
        return files
    except Exception:
        return []
