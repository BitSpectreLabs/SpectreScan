"""
Shell completion script generator for SpectreScan
by BitSpectreLabs

Generates shell completion scripts for Bash, Zsh, PowerShell, and Fish.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict, List
from enum import Enum


SUPPORTED_SHELLS = ["bash", "zsh", "powershell", "fish"]


class ShellType(Enum):
    """Supported shell types."""
    BASH = "bash"
    ZSH = "zsh"
    POWERSHELL = "powershell"
    FISH = "fish"


# Command and option definitions for completion
SPECTRESCAN_COMMANDS = {
    "scan": "Scan target for open ports and services",
    "presets": "List available scan presets",
    "ssl": "Analyze SSL/TLS configuration",
    "cve": "Check for CVE vulnerabilities",
    "dns": "DNS enumeration and subdomain discovery",
    "version": "Show version information",
    "gui": "Launch graphical interface",
    "tui": "Launch terminal user interface",
    "api": "Start REST API server",
    "profile": "Manage scan profiles",
    "history": "View scan history",
    "compare": "Compare two scans",
    "resume": "Resume scan from checkpoint",
    "checkpoint": "Manage scan checkpoints",
    "config": "Manage configuration",
    "completion": "Shell completion utilities"
}

SCAN_OPTIONS = {
    "--quick": "Quick scan of top 100 ports",
    "--top-ports": "Scan top 1000 ports",
    "--full": "Full scan of all 65535 ports",
    "--stealth": "Stealth SYN scan with rate limiting",
    "--safe": "Safe conservative scan",
    "--aggressive": "Aggressive scan with all features",
    "-p": "Port specification (e.g., 1-1000, 22,80,443)",
    "--ports": "Port specification (e.g., 1-1000, 22,80,443)",
    "--tcp": "TCP connect scan",
    "--syn": "TCP SYN scan (requires privileges)",
    "--udp": "UDP scan",
    "--async": "Async high-speed scan",
    "--threads": "Number of threads",
    "--timeout": "Connection timeout in seconds",
    "--rate-limit": "Packets per second rate limit",
    "--service-detection": "Enable service detection",
    "--no-service-detection": "Disable service detection",
    "--os-detection": "Enable OS detection",
    "--banner-grab": "Enable banner grabbing",
    "--randomize": "Randomize scan order",
    "-T": "Timing template (0-5)",
    "--json": "Save JSON output",
    "--csv": "Save CSV output",
    "--xml": "Save XML output",
    "--html": "Save HTML report",
    "--pdf": "Save PDF report",
    "--markdown": "Save Markdown report",
    "--md": "Save Markdown report",
    "--target-file": "Load targets from file",
    "-iL": "Load targets from file",
    "-q": "Quiet mode",
    "--quiet": "Quiet mode",
    "-v": "Verbose output",
    "--verbose": "Verbose output",
    "--ssl-analysis": "Enable SSL/TLS analysis",
    "--cve-check": "Check for CVE vulnerabilities"
}

PROFILE_SUBCOMMANDS = {
    "list": "List all saved profiles",
    "load": "Load and display a profile",
    "delete": "Delete a profile",
    "export": "Export profile to file",
    "import": "Import profile from file"
}

HISTORY_SUBCOMMANDS = {
    "list": "List recent scans",
    "show": "Show scan details",
    "search": "Search scan history",
    "delete": "Delete a scan entry",
    "clear": "Clear all history",
    "stats": "Show scan statistics"
}

CONFIG_SUBCOMMANDS = {
    "show": "Show current configuration",
    "create": "Create a new config file",
    "validate": "Validate a config file",
    "list-options": "List all configuration options"
}


class CompletionGenerator:
    """Generate shell completion scripts for SpectreScan."""
    
    def __init__(self):
        """Initialize the completion generator."""
        self.commands = SPECTRESCAN_COMMANDS
        self.scan_options = SCAN_OPTIONS
        self.profile_subcommands = PROFILE_SUBCOMMANDS
        self.history_subcommands = HISTORY_SUBCOMMANDS
        self.config_subcommands = CONFIG_SUBCOMMANDS
    
    def generate(self, shell: str) -> str:
        """
        Generate completion script for specified shell.
        
        Args:
            shell: Shell type (bash, zsh, powershell, fish)
            
        Returns:
            Completion script as string
            
        Raises:
            ValueError: If shell type is not supported
        """
        shell = shell.lower()
        
        if shell == "bash":
            return self._generate_bash()
        elif shell == "zsh":
            return self._generate_zsh()
        elif shell in ("powershell", "pwsh"):
            return self._generate_powershell()
        elif shell == "fish":
            return self._generate_fish()
        else:
            raise ValueError(f"Unsupported shell: {shell}. Supported: {SUPPORTED_SHELLS}")
    
    def _generate_bash(self) -> str:
        """Generate Bash completion script."""
        commands_list = " ".join(self.commands.keys())
        scan_opts = " ".join(self.scan_options.keys())
        profile_subs = " ".join(self.profile_subcommands.keys())
        history_subs = " ".join(self.history_subcommands.keys())
        config_subs = " ".join(self.config_subcommands.keys())
        
        return f'''#!/bin/bash
# SpectreScan Bash Completion
# by BitSpectreLabs
#
# Installation:
#   Option 1: Source in .bashrc
#     echo 'source /path/to/spectrescan-completion.bash' >> ~/.bashrc
#
#   Option 2: Install to completions directory
#     sudo cp spectrescan-completion.bash /etc/bash_completion.d/spectrescan
#
#   Option 3: Use spectrescan completion install
#     spectrescan completion install bash

_spectrescan_get_profiles() {{
    spectrescan profile list 2>/dev/null | grep -E "^[a-zA-Z0-9_-]+" | head -20
}}

_spectrescan_get_history_ids() {{
    spectrescan history list --limit 20 2>/dev/null | awk '{{print $1}}' | grep -E "^[a-f0-9]{{12}}" | head -20
}}

_spectrescan_completions() {{
    local cur prev words cword
    _init_completion || return

    local commands="{commands_list}"
    local scan_options="{scan_opts}"
    local profile_subcommands="{profile_subs}"
    local history_subcommands="{history_subs}"
    local config_subcommands="{config_subs}"
    local timing_templates="0 1 2 3 4 5"

    # Get the command (first non-option argument after spectrescan)
    local cmd=""
    for ((i=1; i < cword; i++)); do
        if [[ "${{words[i]}}" != -* ]]; then
            cmd="${{words[i]}}"
            break
        fi
    done

    case "$cmd" in
        scan)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$scan_options" -- "$cur"))
            elif [[ "$prev" == "-T" ]]; then
                COMPREPLY=($(compgen -W "$timing_templates" -- "$cur"))
            elif [[ "$prev" == "--json" || "$prev" == "--csv" || "$prev" == "--xml" || "$prev" == "--html" || "$prev" == "--pdf" || "$prev" == "--markdown" || "$prev" == "--md" ]]; then
                _filedir
            elif [[ "$prev" == "--target-file" || "$prev" == "-iL" ]]; then
                _filedir
            fi
            ;;
        profile)
            if [[ "${{words[2]}}" == "load" || "${{words[2]}}" == "delete" || "${{words[2]}}" == "export" ]]; then
                local profiles=$(_spectrescan_get_profiles)
                COMPREPLY=($(compgen -W "$profiles" -- "$cur"))
            elif [[ "${{words[2]}}" == "import" ]]; then
                _filedir json
            else
                COMPREPLY=($(compgen -W "$profile_subcommands" -- "$cur"))
            fi
            ;;
        history)
            if [[ "${{words[2]}}" == "show" || "${{words[2]}}" == "delete" ]]; then
                local ids=$(_spectrescan_get_history_ids)
                COMPREPLY=($(compgen -W "$ids" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$history_subcommands" -- "$cur"))
            fi
            ;;
        compare)
            local ids=$(_spectrescan_get_history_ids)
            COMPREPLY=($(compgen -W "$ids" -- "$cur"))
            ;;
        config)
            COMPREPLY=($(compgen -W "$config_subcommands" -- "$cur"))
            ;;
        resume)
            _filedir json
            ;;
        completion)
            COMPREPLY=($(compgen -W "install show bash zsh powershell fish" -- "$cur"))
            ;;
        ssl|cve|dns)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--json --help -v --verbose" -- "$cur"))
            fi
            ;;
        *)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--help --version" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            fi
            ;;
    esac

    return 0
}}

complete -F _spectrescan_completions spectrescan
'''
    
    def _generate_zsh(self) -> str:
        """Generate Zsh completion script."""
        # Build command descriptions
        cmd_desc = "\n        ".join(
            f"'{cmd}:{desc}'" for cmd, desc in self.commands.items()
        )
        
        # Build scan option descriptions
        scan_desc = "\n            ".join(
            f"'{opt}[{desc}]'" for opt, desc in self.scan_options.items()
        )
        
        profile_desc = "\n            ".join(
            f"'{sub}:{desc}'" for sub, desc in self.profile_subcommands.items()
        )
        
        history_desc = "\n            ".join(
            f"'{sub}:{desc}'" for sub, desc in self.history_subcommands.items()
        )
        
        return f'''#compdef spectrescan
# SpectreScan Zsh Completion
# by BitSpectreLabs
#
# Installation:
#   Option 1: Add to fpath in .zshrc
#     fpath=(~/.zsh/completions $fpath)
#     cp _spectrescan ~/.zsh/completions/
#     autoload -Uz compinit && compinit
#
#   Option 2: Use spectrescan completion install
#     spectrescan completion install zsh

_spectrescan_profiles() {{
    local profiles
    profiles=(${{(f)"$(spectrescan profile list 2>/dev/null | grep -E '^[a-zA-Z0-9_-]+')"}})
    _describe -t profiles 'profile' profiles
}}

_spectrescan_history_ids() {{
    local ids
    ids=(${{(f)"$(spectrescan history list --limit 20 2>/dev/null | awk '{{print $1}}' | grep -E '^[a-f0-9]{{12}}')"}})
    _describe -t history-ids 'history ID' ids
}}

_spectrescan() {{
    local -a commands
    commands=(
        {cmd_desc}
    )

    local -a scan_options
    scan_options=(
        {scan_desc}
    )

    local -a profile_subcommands
    profile_subcommands=(
        {profile_desc}
    )

    local -a history_subcommands
    history_subcommands=(
        {history_desc}
    )

    _arguments -C \\
        '1: :->command' \\
        '*:: :->args' && return 0

    case $state in
        command)
            _describe -t commands 'spectrescan command' commands
            ;;
        args)
            case $words[1] in
                scan)
                    _arguments -s \\
                        $scan_options \\
                        '*:target:_hosts'
                    ;;
                profile)
                    case $words[2] in
                        load|delete|export)
                            _spectrescan_profiles
                            ;;
                        import)
                            _files -g "*.json"
                            ;;
                        *)
                            _describe -t subcommands 'profile subcommand' profile_subcommands
                            ;;
                    esac
                    ;;
                history)
                    case $words[2] in
                        show|delete)
                            _spectrescan_history_ids
                            ;;
                        *)
                            _describe -t subcommands 'history subcommand' history_subcommands
                            ;;
                    esac
                    ;;
                compare)
                    _spectrescan_history_ids
                    ;;
                resume)
                    _files -g "*.checkpoint.json"
                    ;;
                completion)
                    local -a completion_commands
                    completion_commands=(
                        'install:Install completion for shell'
                        'show:Show completion script'
                        'bash:Generate bash completion'
                        'zsh:Generate zsh completion'
                        'powershell:Generate PowerShell completion'
                        'fish:Generate fish completion'
                    )
                    _describe -t commands 'completion command' completion_commands
                    ;;
                ssl|cve|dns)
                    _arguments \\
                        '--json[Save JSON output]:file:_files -g "*.json"' \\
                        '-v[Verbose output]' \\
                        '--verbose[Verbose output]' \\
                        '*:target:_hosts'
                    ;;
            esac
            ;;
    esac
}}

_spectrescan "$@"
'''
    
    def _generate_powershell(self) -> str:
        """Generate PowerShell completion script."""
        commands_array = ", ".join(f'"{cmd}"' for cmd in self.commands.keys())
        scan_opts_array = ", ".join(f'"{opt}"' for opt in self.scan_options.keys())
        profile_subs_array = ", ".join(f'"{sub}"' for sub in self.profile_subcommands.keys())
        history_subs_array = ", ".join(f'"{sub}"' for sub in self.history_subcommands.keys())
        config_subs_array = ", ".join(f'"{sub}"' for sub in self.config_subcommands.keys())
        
        return f'''# SpectreScan PowerShell Completion
# by BitSpectreLabs
#
# Installation:
#   Option 1: Add to PowerShell profile
#     Add-Content $PROFILE '. /path/to/spectrescan-completion.ps1'
#
#   Option 2: Use spectrescan completion install
#     spectrescan completion install powershell

$script:SpectrescanCommands = @({commands_array})
$script:ScanOptions = @({scan_opts_array})
$script:ProfileSubcommands = @({profile_subs_array})
$script:HistorySubcommands = @({history_subs_array})
$script:ConfigSubcommands = @({config_subs_array})
$script:TimingTemplates = @("0", "1", "2", "3", "4", "5")
$script:CompletionSubcommands = @("install", "show", "bash", "zsh", "powershell", "fish")

function Get-SpectrescanProfiles {{
    try {{
        $output = spectrescan profile list 2>$null
        if ($output) {{
            $output | Where-Object {{ $_ -match '^[a-zA-Z0-9_-]+' }} | Select-Object -First 20
        }}
    }} catch {{
        @()
    }}
}}

function Get-SpectrescanHistoryIds {{
    try {{
        $output = spectrescan history list --limit 20 2>$null
        if ($output) {{
            $output | ForEach-Object {{ ($_ -split '\\s+')[0] }} | Where-Object {{ $_ -match '^[a-f0-9]{{12}}' }} | Select-Object -First 20
        }}
    }} catch {{
        @()
    }}
}}

Register-ArgumentCompleter -Native -CommandName spectrescan -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)

    $words = $commandAst.CommandElements | ForEach-Object {{ $_.Extent.Text }}
    $cmd = if ($words.Count -gt 1) {{ $words[1] }} else {{ "" }}

    # Determine what to complete based on context
    switch ($cmd) {{
        "scan" {{
            if ($wordToComplete.StartsWith("-")) {{
                $script:ScanOptions | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_)
                }}
            }} elseif ($words[-2] -eq "-T") {{
                $script:TimingTemplates | ForEach-Object {{
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', "Timing template $_")
                }}
            }}
        }}
        "profile" {{
            $subCmd = if ($words.Count -gt 2) {{ $words[2] }} else {{ "" }}
            switch ($subCmd) {{
                {{ $_ -in @("load", "delete", "export") }} {{
                    Get-SpectrescanProfiles | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', "Profile: $_")
                    }}
                }}
                "import" {{
                    Get-ChildItem -Filter "*.json" -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like "$wordToComplete*" }} | ForEach-Object {{
                        [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ProviderItem', $_.FullName)
                    }}
                }}
                default {{
                    $script:ProfileSubcommands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'Command', "Profile subcommand: $_")
                    }}
                }}
            }}
        }}
        "history" {{
            $subCmd = if ($words.Count -gt 2) {{ $words[2] }} else {{ "" }}
            switch ($subCmd) {{
                {{ $_ -in @("show", "delete") }} {{
                    Get-SpectrescanHistoryIds | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', "History ID: $_")
                    }}
                }}
                default {{
                    $script:HistorySubcommands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'Command', "History subcommand: $_")
                    }}
                }}
            }}
        }}
        "compare" {{
            Get-SpectrescanHistoryIds | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', "History ID: $_")
            }}
        }}
        "config" {{
            $script:ConfigSubcommands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                [System.Management.Automation.CompletionResult]::new($_, $_, 'Command', "Config subcommand: $_")
            }}
        }}
        "resume" {{
            Get-ChildItem -Filter "*.checkpoint.json" -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like "$wordToComplete*" }} | ForEach-Object {{
                [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ProviderItem', $_.FullName)
            }}
        }}
        "completion" {{
            $script:CompletionSubcommands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                [System.Management.Automation.CompletionResult]::new($_, $_, 'Command', "Completion subcommand: $_")
            }}
        }}
        default {{
            if ($wordToComplete.StartsWith("-")) {{
                @("--help", "--version") | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_)
                }}
            }} else {{
                $script:SpectrescanCommands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'Command', "SpectreScan command: $_")
                }}
            }}
        }}
    }}
}}

Write-Host "SpectreScan PowerShell completion loaded" -ForegroundColor Cyan
'''
    
    def _generate_fish(self) -> str:
        """Generate Fish shell completion script."""
        # Build command completions
        cmd_completions = "\n".join(
            f"complete -c spectrescan -n '__fish_use_subcommand' -a '{cmd}' -d '{desc}'"
            for cmd, desc in self.commands.items()
        )
        
        # Build scan option completions
        scan_completions = []
        for opt, desc in self.scan_options.items():
            if opt.startswith("--"):
                flag = opt[2:]
                scan_completions.append(
                    f"complete -c spectrescan -n '__fish_seen_subcommand_from scan' -l '{flag}' -d '{desc}'"
                )
            elif opt.startswith("-") and len(opt) == 2:
                flag = opt[1:]
                scan_completions.append(
                    f"complete -c spectrescan -n '__fish_seen_subcommand_from scan' -s '{flag}' -d '{desc}'"
                )
        scan_opts_str = "\n".join(scan_completions)
        
        # Build profile subcommand completions
        profile_completions = "\n".join(
            f"complete -c spectrescan -n '__fish_seen_subcommand_from profile' -a '{sub}' -d '{desc}'"
            for sub, desc in self.profile_subcommands.items()
        )
        
        # Build history subcommand completions
        history_completions = "\n".join(
            f"complete -c spectrescan -n '__fish_seen_subcommand_from history' -a '{sub}' -d '{desc}'"
            for sub, desc in self.history_subcommands.items()
        )
        
        return f'''# SpectreScan Fish Completion
# by BitSpectreLabs
#
# Installation:
#   Option 1: Copy to fish completions directory
#     cp spectrescan.fish ~/.config/fish/completions/
#
#   Option 2: Use spectrescan completion install
#     spectrescan completion install fish

# Helper functions
function __fish_spectrescan_profiles
    spectrescan profile list 2>/dev/null | string match -r '^[a-zA-Z0-9_-]+' | head -20
end

function __fish_spectrescan_history_ids
    spectrescan history list --limit 20 2>/dev/null | string split ' ' | string match -r '^[a-f0-9]{{12}}' | head -20
end

function __fish_spectrescan_needs_command
    set -l cmd (commandline -opc)
    test (count $cmd) -eq 1
end

function __fish_spectrescan_using_command
    set -l cmd (commandline -opc)
    test (count $cmd) -gt 1 && test $cmd[2] = $argv[1]
end

# Disable file completion by default
complete -c spectrescan -f

# Main commands
{cmd_completions}

# Scan options
{scan_opts_str}
complete -c spectrescan -n '__fish_seen_subcommand_from scan' -s T -d 'Timing template (0-5)' -a '0 1 2 3 4 5'

# Profile subcommands
{profile_completions}

# Profile dynamic completions
complete -c spectrescan -n '__fish_seen_subcommand_from profile; and __fish_seen_subcommand_from load' -a '(__fish_spectrescan_profiles)' -d 'Profile name'
complete -c spectrescan -n '__fish_seen_subcommand_from profile; and __fish_seen_subcommand_from delete' -a '(__fish_spectrescan_profiles)' -d 'Profile name'
complete -c spectrescan -n '__fish_seen_subcommand_from profile; and __fish_seen_subcommand_from export' -a '(__fish_spectrescan_profiles)' -d 'Profile name'
complete -c spectrescan -n '__fish_seen_subcommand_from profile; and __fish_seen_subcommand_from import' -F -d 'Profile file'

# History subcommands
{history_completions}

# History dynamic completions
complete -c spectrescan -n '__fish_seen_subcommand_from history; and __fish_seen_subcommand_from show' -a '(__fish_spectrescan_history_ids)' -d 'History ID'
complete -c spectrescan -n '__fish_seen_subcommand_from history; and __fish_seen_subcommand_from delete' -a '(__fish_spectrescan_history_ids)' -d 'History ID'

# Compare command
complete -c spectrescan -n '__fish_seen_subcommand_from compare' -a '(__fish_spectrescan_history_ids)' -d 'History ID'

# Resume command
complete -c spectrescan -n '__fish_seen_subcommand_from resume' -F -d 'Checkpoint file'

# Config subcommands
complete -c spectrescan -n '__fish_seen_subcommand_from config' -a 'show' -d 'Show current configuration'
complete -c spectrescan -n '__fish_seen_subcommand_from config' -a 'create' -d 'Create a new config file'
complete -c spectrescan -n '__fish_seen_subcommand_from config' -a 'validate' -d 'Validate a config file'
complete -c spectrescan -n '__fish_seen_subcommand_from config' -a 'list-options' -d 'List all configuration options'

# Completion subcommands
complete -c spectrescan -n '__fish_seen_subcommand_from completion' -a 'install' -d 'Install completion for shell'
complete -c spectrescan -n '__fish_seen_subcommand_from completion' -a 'show' -d 'Show completion script'
complete -c spectrescan -n '__fish_seen_subcommand_from completion' -a 'bash' -d 'Generate bash completion'
complete -c spectrescan -n '__fish_seen_subcommand_from completion' -a 'zsh' -d 'Generate zsh completion'
complete -c spectrescan -n '__fish_seen_subcommand_from completion' -a 'powershell' -d 'Generate PowerShell completion'
complete -c spectrescan -n '__fish_seen_subcommand_from completion' -a 'fish' -d 'Generate fish completion'

# SSL, CVE, DNS commands
complete -c spectrescan -n '__fish_seen_subcommand_from ssl cve dns' -l json -d 'Save JSON output' -F
complete -c spectrescan -n '__fish_seen_subcommand_from ssl cve dns' -s v -l verbose -d 'Verbose output'
'''


def generate_bash_completion() -> str:
    """Generate Bash completion script."""
    return CompletionGenerator().generate("bash")


def generate_zsh_completion() -> str:
    """Generate Zsh completion script."""
    return CompletionGenerator().generate("zsh")


def generate_powershell_completion() -> str:
    """Generate PowerShell completion script."""
    return CompletionGenerator().generate("powershell")


def generate_fish_completion() -> str:
    """Generate Fish completion script."""
    return CompletionGenerator().generate("fish")


def get_completion_script(shell: str) -> str:
    """
    Get completion script for specified shell.
    
    Args:
        shell: Shell type (bash, zsh, powershell, fish)
        
    Returns:
        Completion script as string
    """
    return CompletionGenerator().generate(shell)


def get_install_instructions(shell: str) -> str:
    """
    Get installation instructions for specified shell.
    
    Args:
        shell: Shell type (bash, zsh, powershell, fish)
        
    Returns:
        Installation instructions as string
    """
    shell = shell.lower()
    
    instructions = {
        "bash": """
Bash Completion Installation Instructions:
==========================================

Option 1: Source in ~/.bashrc (recommended for single user)
-----------------------------------------------------------
1. Save the completion script:
   spectrescan completion bash > ~/.spectrescan-completion.bash

2. Add to ~/.bashrc:
   echo 'source ~/.spectrescan-completion.bash' >> ~/.bashrc

3. Reload your shell:
   source ~/.bashrc

Option 2: Install system-wide (requires sudo)
---------------------------------------------
1. Save to completions directory:
   spectrescan completion bash | sudo tee /etc/bash_completion.d/spectrescan > /dev/null

2. Reload your shell or source the file:
   source /etc/bash_completion.d/spectrescan

Option 3: Auto-install (recommended)
------------------------------------
   spectrescan completion install bash
""",
        "zsh": """
Zsh Completion Installation Instructions:
=========================================

Option 1: Add to custom completions directory (recommended)
-----------------------------------------------------------
1. Create completions directory:
   mkdir -p ~/.zsh/completions

2. Add to ~/.zshrc:
   fpath=(~/.zsh/completions $fpath)
   autoload -Uz compinit && compinit

3. Save the completion script:
   spectrescan completion zsh > ~/.zsh/completions/_spectrescan

4. Reload your shell:
   exec zsh

Option 2: Install to system directory (requires sudo)
-----------------------------------------------------
1. Find your completions directory:
   echo $fpath | tr ' ' '\\n' | head -5

2. Save to one of those directories:
   spectrescan completion zsh | sudo tee /usr/share/zsh/site-functions/_spectrescan > /dev/null

3. Reload completions:
   exec zsh

Option 3: Auto-install (recommended)
------------------------------------
   spectrescan completion install zsh
""",
        "powershell": """
PowerShell Completion Installation Instructions:
================================================

Option 1: Add to PowerShell profile (recommended)
-------------------------------------------------
1. Check if profile exists:
   Test-Path $PROFILE

2. Create profile if needed:
   New-Item -Path $PROFILE -Type File -Force

3. Save completion script:
   spectrescan completion powershell > $HOME\\spectrescan-completion.ps1

4. Add to profile:
   Add-Content $PROFILE '. $HOME\\spectrescan-completion.ps1'

5. Reload profile:
   . $PROFILE

Option 2: Direct source (current session only)
----------------------------------------------
   spectrescan completion powershell | Invoke-Expression

Option 3: Auto-install (recommended)
------------------------------------
   spectrescan completion install powershell
""",
        "fish": """
Fish Completion Installation Instructions:
==========================================

Option 1: Install to completions directory (recommended)
--------------------------------------------------------
1. Create completions directory:
   mkdir -p ~/.config/fish/completions

2. Save the completion script:
   spectrescan completion fish > ~/.config/fish/completions/spectrescan.fish

3. Fish will automatically load it on next shell start.
   Or reload with:
   source ~/.config/fish/completions/spectrescan.fish

Option 2: Auto-install (recommended)
------------------------------------
   spectrescan completion install fish
"""
    }
    
    return instructions.get(shell, f"Unsupported shell: {shell}. Supported: {SUPPORTED_SHELLS}")


def install_completion(shell: str) -> tuple[bool, str]:
    """
    Install completion script for specified shell.
    
    Args:
        shell: Shell type (bash, zsh, powershell, fish)
        
    Returns:
        Tuple of (success, message)
    """
    shell = shell.lower()
    
    # Check if shell is supported first
    if shell not in SUPPORTED_SHELLS and shell != "pwsh":
        return False, f"Unsupported shell: {shell}. Supported: {SUPPORTED_SHELLS}"
    
    script = get_completion_script(shell)
    
    try:
        if shell == "bash":
            # Install to ~/.spectrescan-completion.bash
            completion_file = Path.home() / ".spectrescan-completion.bash"
            completion_file.write_text(script, encoding="utf-8")
            
            # Add source line to .bashrc if not present
            bashrc = Path.home() / ".bashrc"
            source_line = f"source {completion_file}"
            
            if bashrc.exists():
                content = bashrc.read_text(encoding="utf-8")
                if source_line not in content:
                    with open(bashrc, "a", encoding="utf-8") as f:
                        f.write(f"\n# SpectreScan completion\n{source_line}\n")
            else:
                bashrc.write_text(f"# SpectreScan completion\n{source_line}\n", encoding="utf-8")
            
            return True, f"Bash completion installed to {completion_file}\nReload with: source ~/.bashrc"
        
        elif shell == "zsh":
            # Install to ~/.zsh/completions/_spectrescan
            completions_dir = Path.home() / ".zsh" / "completions"
            completions_dir.mkdir(parents=True, exist_ok=True)
            completion_file = completions_dir / "_spectrescan"
            completion_file.write_text(script, encoding="utf-8")
            
            # Check/update .zshrc
            zshrc = Path.home() / ".zshrc"
            fpath_line = 'fpath=(~/.zsh/completions $fpath)'
            compinit_line = 'autoload -Uz compinit && compinit'
            
            if zshrc.exists():
                content = zshrc.read_text(encoding="utf-8")
                additions = []
                if fpath_line not in content:
                    additions.append(fpath_line)
                if "compinit" not in content:
                    additions.append(compinit_line)
                
                if additions:
                    with open(zshrc, "a", encoding="utf-8") as f:
                        f.write(f"\n# SpectreScan completion\n")
                        f.write("\n".join(additions) + "\n")
            
            return True, f"Zsh completion installed to {completion_file}\nReload with: exec zsh"
        
        elif shell in ("powershell", "pwsh"):
            # Install to user's PowerShell profile directory
            if sys.platform == "win32":
                ps_dir = Path.home() / "Documents" / "WindowsPowerShell"
            else:
                ps_dir = Path.home() / ".config" / "powershell"
            
            ps_dir.mkdir(parents=True, exist_ok=True)
            completion_file = ps_dir / "spectrescan-completion.ps1"
            completion_file.write_text(script, encoding="utf-8")
            
            # Profile file
            profile_file = ps_dir / "Microsoft.PowerShell_profile.ps1"
            source_line = f". {completion_file}"
            
            if profile_file.exists():
                content = profile_file.read_text(encoding="utf-8")
                if "spectrescan-completion" not in content:
                    with open(profile_file, "a", encoding="utf-8") as f:
                        f.write(f"\n# SpectreScan completion\n{source_line}\n")
            else:
                profile_file.write_text(f"# SpectreScan completion\n{source_line}\n", encoding="utf-8")
            
            return True, f"PowerShell completion installed to {completion_file}\nReload with: . $PROFILE"
        
        elif shell == "fish":
            # Install to ~/.config/fish/completions/spectrescan.fish
            completions_dir = Path.home() / ".config" / "fish" / "completions"
            completions_dir.mkdir(parents=True, exist_ok=True)
            completion_file = completions_dir / "spectrescan.fish"
            completion_file.write_text(script, encoding="utf-8")
            
            return True, f"Fish completion installed to {completion_file}\nReload with: source {completion_file}"
        
        else:
            return False, f"Unsupported shell: {shell}. Supported: {SUPPORTED_SHELLS}"
    
    except Exception as e:
        return False, f"Failed to install completion: {e}"
