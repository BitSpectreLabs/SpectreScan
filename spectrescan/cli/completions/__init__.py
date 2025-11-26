"""
Shell completion scripts for SpectreScan
by BitSpectreLabs

Provides shell completion support for Bash, Zsh, PowerShell, and Fish shells.
"""

from spectrescan.cli.completions.generator import (
    CompletionGenerator,
    generate_bash_completion,
    generate_zsh_completion,
    generate_powershell_completion,
    generate_fish_completion,
    get_completion_script,
    install_completion,
    get_install_instructions,
    SUPPORTED_SHELLS
)

from spectrescan.cli.completions.dynamic import (
    get_profile_names,
    get_history_ids,
    get_preset_names,
    get_scan_types,
    get_output_formats,
    get_timing_templates
)

__all__ = [
    # Generator
    "CompletionGenerator",
    "generate_bash_completion",
    "generate_zsh_completion",
    "generate_powershell_completion",
    "generate_fish_completion",
    "get_completion_script",
    "install_completion",
    "get_install_instructions",
    "SUPPORTED_SHELLS",
    # Dynamic completions
    "get_profile_names",
    "get_history_ids",
    "get_preset_names",
    "get_scan_types",
    "get_output_formats",
    "get_timing_templates"
]
