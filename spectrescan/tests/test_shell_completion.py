"""
Unit tests for shell completion scripts
by BitSpectreLabs
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from spectrescan.cli.completions.generator import (
    CompletionGenerator,
    generate_bash_completion,
    generate_zsh_completion,
    generate_powershell_completion,
    generate_fish_completion,
    get_completion_script,
    get_install_instructions,
    install_completion,
    SUPPORTED_SHELLS,
    ShellType,
    SPECTRESCAN_COMMANDS,
    SCAN_OPTIONS,
    PROFILE_SUBCOMMANDS,
    HISTORY_SUBCOMMANDS
)

from spectrescan.cli.completions.dynamic import (
    get_profile_names,
    get_history_ids,
    get_preset_names,
    get_scan_types,
    get_output_formats,
    get_timing_templates,
    get_commands,
    get_profile_subcommands,
    get_history_subcommands,
    get_config_subcommands,
    get_completion_subcommands,
    get_checkpoint_files,
    get_config_files
)


class TestSupportedShells:
    """Test supported shell constants."""
    
    def test_supported_shells_list(self):
        """Test SUPPORTED_SHELLS contains expected shells."""
        assert "bash" in SUPPORTED_SHELLS
        assert "zsh" in SUPPORTED_SHELLS
        assert "powershell" in SUPPORTED_SHELLS
        assert "fish" in SUPPORTED_SHELLS
        assert len(SUPPORTED_SHELLS) == 4
    
    def test_shell_type_enum(self):
        """Test ShellType enum values."""
        assert ShellType.BASH.value == "bash"
        assert ShellType.ZSH.value == "zsh"
        assert ShellType.POWERSHELL.value == "powershell"
        assert ShellType.FISH.value == "fish"


class TestCommandDefinitions:
    """Test command and option definitions."""
    
    def test_spectrescan_commands_defined(self):
        """Test that main commands are defined."""
        assert "scan" in SPECTRESCAN_COMMANDS
        assert "profile" in SPECTRESCAN_COMMANDS
        assert "history" in SPECTRESCAN_COMMANDS
        assert "completion" in SPECTRESCAN_COMMANDS
    
    def test_scan_options_defined(self):
        """Test that scan options are defined."""
        assert "--quick" in SCAN_OPTIONS
        assert "--top-ports" in SCAN_OPTIONS
        assert "-p" in SCAN_OPTIONS
        assert "--json" in SCAN_OPTIONS
        assert "--markdown" in SCAN_OPTIONS
    
    def test_profile_subcommands_defined(self):
        """Test that profile subcommands are defined."""
        assert "list" in PROFILE_SUBCOMMANDS
        assert "load" in PROFILE_SUBCOMMANDS
        assert "delete" in PROFILE_SUBCOMMANDS
    
    def test_history_subcommands_defined(self):
        """Test that history subcommands are defined."""
        assert "list" in HISTORY_SUBCOMMANDS
        assert "show" in HISTORY_SUBCOMMANDS
        assert "search" in HISTORY_SUBCOMMANDS


class TestCompletionGenerator:
    """Test CompletionGenerator class."""
    
    def test_init(self):
        """Test generator initialization."""
        gen = CompletionGenerator()
        assert gen.commands == SPECTRESCAN_COMMANDS
        assert gen.scan_options == SCAN_OPTIONS
    
    def test_generate_bash(self):
        """Test bash completion generation."""
        gen = CompletionGenerator()
        script = gen.generate("bash")
        
        assert script is not None
        assert "#!/bin/bash" in script
        assert "_spectrescan_completions" in script
        assert "complete -F" in script
        assert "spectrescan" in script
    
    def test_generate_zsh(self):
        """Test zsh completion generation."""
        gen = CompletionGenerator()
        script = gen.generate("zsh")
        
        assert script is not None
        assert "#compdef spectrescan" in script
        assert "_spectrescan" in script
        assert "_arguments" in script
    
    def test_generate_powershell(self):
        """Test PowerShell completion generation."""
        gen = CompletionGenerator()
        script = gen.generate("powershell")
        
        assert script is not None
        assert "Register-ArgumentCompleter" in script
        assert "CompletionResult" in script
        assert "spectrescan" in script
    
    def test_generate_fish(self):
        """Test fish completion generation."""
        gen = CompletionGenerator()
        script = gen.generate("fish")
        
        assert script is not None
        assert "complete -c spectrescan" in script
        assert "__fish_use_subcommand" in script
    
    def test_generate_unsupported_shell(self):
        """Test error for unsupported shell."""
        gen = CompletionGenerator()
        
        with pytest.raises(ValueError) as excinfo:
            gen.generate("unsupported")
        
        assert "Unsupported shell" in str(excinfo.value)
    
    def test_generate_case_insensitive(self):
        """Test that shell names are case insensitive."""
        gen = CompletionGenerator()
        
        script_lower = gen.generate("bash")
        script_upper = gen.generate("BASH")
        script_mixed = gen.generate("Bash")
        
        assert script_lower == script_upper == script_mixed
    
    def test_pwsh_alias(self):
        """Test that pwsh is accepted as powershell alias."""
        gen = CompletionGenerator()
        
        script_ps = gen.generate("powershell")
        script_pwsh = gen.generate("pwsh")
        
        assert script_ps == script_pwsh


class TestBashCompletion:
    """Test Bash completion script generation."""
    
    def test_generate_bash_completion_function(self):
        """Test generate_bash_completion function."""
        script = generate_bash_completion()
        
        assert "#!/bin/bash" in script
        assert "BitSpectreLabs" in script
    
    def test_bash_has_dynamic_completions(self):
        """Test that bash script has dynamic completion functions."""
        script = generate_bash_completion()
        
        assert "_spectrescan_get_profiles" in script
        assert "_spectrescan_get_history_ids" in script
    
    def test_bash_has_all_commands(self):
        """Test that bash script includes all commands."""
        script = generate_bash_completion()
        
        for cmd in SPECTRESCAN_COMMANDS:
            assert cmd in script
    
    def test_bash_has_scan_options(self):
        """Test that bash script includes scan options."""
        script = generate_bash_completion()
        
        assert "--quick" in script
        assert "--json" in script
        assert "-T" in script
    
    def test_bash_timing_templates(self):
        """Test that bash script includes timing templates."""
        script = generate_bash_completion()
        
        assert "timing_templates" in script
        assert '"0 1 2 3 4 5"' in script


class TestZshCompletion:
    """Test Zsh completion script generation."""
    
    def test_generate_zsh_completion_function(self):
        """Test generate_zsh_completion function."""
        script = generate_zsh_completion()
        
        assert "#compdef spectrescan" in script
        assert "BitSpectreLabs" in script
    
    def test_zsh_has_descriptions(self):
        """Test that zsh script has command descriptions."""
        script = generate_zsh_completion()
        
        assert "_describe" in script
        assert "Scan target" in script
    
    def test_zsh_has_dynamic_completions(self):
        """Test that zsh script has dynamic completion functions."""
        script = generate_zsh_completion()
        
        assert "_spectrescan_profiles" in script
        assert "_spectrescan_history_ids" in script
    
    def test_zsh_has_file_completions(self):
        """Test that zsh script has file completions."""
        script = generate_zsh_completion()
        
        assert "_files" in script
        assert "_hosts" in script


class TestPowerShellCompletion:
    """Test PowerShell completion script generation."""
    
    def test_generate_powershell_completion_function(self):
        """Test generate_powershell_completion function."""
        script = generate_powershell_completion()
        
        assert "Register-ArgumentCompleter" in script
        assert "BitSpectreLabs" in script
    
    def test_powershell_has_arrays(self):
        """Test that PowerShell script has command arrays."""
        script = generate_powershell_completion()
        
        assert "$script:SpectrescanCommands" in script
        assert "$script:ScanOptions" in script
    
    def test_powershell_has_dynamic_functions(self):
        """Test that PowerShell script has dynamic completion functions."""
        script = generate_powershell_completion()
        
        assert "Get-SpectrescanProfiles" in script
        assert "Get-SpectrescanHistoryIds" in script
    
    def test_powershell_completion_result(self):
        """Test that PowerShell uses CompletionResult."""
        script = generate_powershell_completion()
        
        assert "CompletionResult" in script
        assert "ParameterName" in script
        assert "ParameterValue" in script


class TestFishCompletion:
    """Test Fish completion script generation."""
    
    def test_generate_fish_completion_function(self):
        """Test generate_fish_completion function."""
        script = generate_fish_completion()
        
        assert "complete -c spectrescan" in script
        assert "BitSpectreLabs" in script
    
    def test_fish_has_helper_functions(self):
        """Test that fish script has helper functions."""
        script = generate_fish_completion()
        
        assert "__fish_spectrescan_profiles" in script
        assert "__fish_spectrescan_history_ids" in script
        assert "__fish_use_subcommand" in script
    
    def test_fish_has_descriptions(self):
        """Test that fish script has option descriptions."""
        script = generate_fish_completion()
        
        assert "-d '" in script  # Description flag
    
    def test_fish_disables_default_file_completion(self):
        """Test that fish script disables default file completion."""
        script = generate_fish_completion()
        
        assert "complete -c spectrescan -f" in script


class TestGetCompletionScript:
    """Test get_completion_script function."""
    
    def test_get_all_supported_shells(self):
        """Test getting completion for all supported shells."""
        for shell in SUPPORTED_SHELLS:
            script = get_completion_script(shell)
            assert script is not None
            assert len(script) > 100
    
    def test_get_unsupported_shell(self):
        """Test error for unsupported shell."""
        with pytest.raises(ValueError):
            get_completion_script("ksh")


class TestInstallInstructions:
    """Test install instructions generation."""
    
    def test_bash_instructions(self):
        """Test bash installation instructions."""
        instructions = get_install_instructions("bash")
        
        assert "Bash" in instructions
        assert ".bashrc" in instructions
        assert "source" in instructions
    
    def test_zsh_instructions(self):
        """Test zsh installation instructions."""
        instructions = get_install_instructions("zsh")
        
        assert "Zsh" in instructions
        assert ".zshrc" in instructions
        assert "fpath" in instructions
        assert "compinit" in instructions
    
    def test_powershell_instructions(self):
        """Test PowerShell installation instructions."""
        instructions = get_install_instructions("powershell")
        
        assert "PowerShell" in instructions
        assert "$PROFILE" in instructions
    
    def test_fish_instructions(self):
        """Test fish installation instructions."""
        instructions = get_install_instructions("fish")
        
        assert "Fish" in instructions
        assert "completions" in instructions
        assert ".config/fish" in instructions
    
    def test_unsupported_shell_instructions(self):
        """Test unsupported shell returns error message."""
        instructions = get_install_instructions("ksh")
        
        assert "Unsupported shell" in instructions


class TestInstallCompletion:
    """Test install_completion function."""
    
    def test_install_bash(self, tmp_path):
        """Test bash completion installation."""
        with patch.object(Path, "home", return_value=tmp_path):
            success, message = install_completion("bash")
        
        assert success is True
        assert "Success" in message or "installed" in message.lower()
        
        # Check file was created
        completion_file = tmp_path / ".spectrescan-completion.bash"
        assert completion_file.exists()
    
    def test_install_zsh(self, tmp_path):
        """Test zsh completion installation."""
        with patch.object(Path, "home", return_value=tmp_path):
            success, message = install_completion("zsh")
        
        assert success is True
        
        # Check file was created
        completion_file = tmp_path / ".zsh" / "completions" / "_spectrescan"
        assert completion_file.exists()
    
    def test_install_powershell_windows(self, tmp_path):
        """Test PowerShell completion installation on Windows."""
        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(sys, "platform", "win32"):
                success, message = install_completion("powershell")
        
        assert success is True
    
    def test_install_fish(self, tmp_path):
        """Test fish completion installation."""
        with patch.object(Path, "home", return_value=tmp_path):
            success, message = install_completion("fish")
        
        assert success is True
        
        # Check file was created
        completion_file = tmp_path / ".config" / "fish" / "completions" / "spectrescan.fish"
        assert completion_file.exists()
    
    def test_install_unsupported_shell(self):
        """Test error for unsupported shell installation."""
        success, message = install_completion("ksh")
        
        assert success is False
        assert "Unsupported" in message


class TestDynamicCompletions:
    """Test dynamic completion data providers."""
    
    def test_get_preset_names(self):
        """Test get_preset_names returns expected presets."""
        presets = get_preset_names()
        
        assert "quick" in presets
        assert "top-ports" in presets
        assert "full" in presets
        assert "stealth" in presets
    
    def test_get_scan_types(self):
        """Test get_scan_types returns expected types."""
        types = get_scan_types()
        
        assert "tcp" in types
        assert "syn" in types
        assert "udp" in types
        assert "async" in types
    
    def test_get_output_formats(self):
        """Test get_output_formats returns expected formats."""
        formats = get_output_formats()
        
        assert "json" in formats
        assert "csv" in formats
        assert "xml" in formats
        assert "html" in formats
        assert "markdown" in formats
    
    def test_get_timing_templates(self):
        """Test get_timing_templates returns 0-5."""
        templates = get_timing_templates()
        
        assert templates == ["0", "1", "2", "3", "4", "5"]
    
    def test_get_commands(self):
        """Test get_commands returns all CLI commands."""
        commands = get_commands()
        
        assert "scan" in commands
        assert "profile" in commands
        assert "history" in commands
        assert "completion" in commands
    
    def test_get_profile_subcommands(self):
        """Test get_profile_subcommands returns expected subcommands."""
        subs = get_profile_subcommands()
        
        assert "list" in subs
        assert "load" in subs
        assert "delete" in subs
    
    def test_get_history_subcommands(self):
        """Test get_history_subcommands returns expected subcommands."""
        subs = get_history_subcommands()
        
        assert "list" in subs
        assert "show" in subs
        assert "search" in subs
        assert "stats" in subs
    
    def test_get_config_subcommands(self):
        """Test get_config_subcommands returns expected subcommands."""
        subs = get_config_subcommands()
        
        assert "show" in subs
        assert "create" in subs
        assert "validate" in subs
    
    def test_get_completion_subcommands(self):
        """Test get_completion_subcommands returns expected subcommands."""
        subs = get_completion_subcommands()
        
        assert "install" in subs
        assert "show" in subs
        assert "bash" in subs
        assert "zsh" in subs


class TestDynamicProfileCompletion:
    """Test dynamic profile name completion."""
    
    def test_get_profile_names_returns_list(self):
        """Test get_profile_names returns a list."""
        profiles = get_profile_names()
        assert isinstance(profiles, list)
    
    def test_get_profile_names_handles_no_profiles(self):
        """Test get_profile_names handles missing profiles gracefully."""
        # This test verifies the function doesn't crash
        # It will return [] if ProfileManager fails or has no profiles
        profiles = get_profile_names()
        assert isinstance(profiles, list)


class TestDynamicHistoryCompletion:
    """Test dynamic history ID completion."""
    
    def test_get_history_ids_returns_list(self):
        """Test get_history_ids returns a list."""
        ids = get_history_ids()
        assert isinstance(ids, list)
    
    def test_get_history_ids_handles_empty(self):
        """Test get_history_ids handles empty history gracefully."""
        # This test verifies the function doesn't crash
        ids = get_history_ids()
        assert isinstance(ids, list)
    
    def test_get_history_ids_default_limit(self):
        """Test get_history_ids uses default limit."""
        # Just verify it doesn't crash with default limit
        ids = get_history_ids()
        assert isinstance(ids, list)
    
    def test_get_history_ids_custom_limit(self):
        """Test get_history_ids accepts custom limit."""
        # Just verify it doesn't crash with custom limit
        ids = get_history_ids(limit=10)
        assert isinstance(ids, list)


class TestFileCompletions:
    """Test file-based completion functions."""
    
    def test_get_checkpoint_files(self, tmp_path):
        """Test get_checkpoint_files finds checkpoint files."""
        # Create test checkpoint files
        (tmp_path / "scan1.checkpoint.json").touch()
        (tmp_path / "scan2.checkpoint.json").touch()
        (tmp_path / "other.json").touch()
        
        files = get_checkpoint_files(tmp_path)
        
        assert len(files) == 2
        assert any("scan1.checkpoint.json" in f for f in files)
        assert any("scan2.checkpoint.json" in f for f in files)
    
    def test_get_checkpoint_files_empty(self, tmp_path):
        """Test get_checkpoint_files handles empty directory."""
        files = get_checkpoint_files(tmp_path)
        
        assert files == []
    
    def test_get_config_files(self, tmp_path):
        """Test get_config_files finds config files."""
        # Create test config files
        (tmp_path / "config.yaml").touch()
        (tmp_path / "config.json").touch()
        (tmp_path / "other.txt").touch()
        
        files = get_config_files(tmp_path)
        
        assert len(files) >= 2


class TestCompletionScriptContent:
    """Test that generated scripts have proper content."""
    
    def test_bash_has_proper_structure(self):
        """Test bash script has proper function structure."""
        script = generate_bash_completion()
        
        # Should have shebang
        assert script.startswith("#!/bin/bash")
        
        # Should have main completion function
        assert "function" in script or "_spectrescan_completions()" in script
        
        # Should register completion
        assert "complete -F" in script
    
    def test_zsh_has_proper_structure(self):
        """Test zsh script has proper structure."""
        script = generate_zsh_completion()
        
        # Should have compdef
        assert script.startswith("#compdef")
        
        # Should have _arguments
        assert "_arguments" in script
        
        # Should have state handling
        assert "case $state" in script
    
    def test_powershell_has_proper_structure(self):
        """Test PowerShell script has proper structure."""
        script = generate_powershell_completion()
        
        # Should register completer
        assert "Register-ArgumentCompleter" in script
        
        # Should have script block
        assert "ScriptBlock" in script
        
        # Should return CompletionResult
        assert "CompletionResult" in script
    
    def test_fish_has_proper_structure(self):
        """Test fish script has proper structure."""
        script = generate_fish_completion()
        
        # Should have complete commands
        assert "complete -c spectrescan" in script
        
        # Should have condition functions
        assert "function __fish_" in script
        
        # Should have -n conditions
        assert "-n '" in script


class TestCompletionIntegration:
    """Integration tests for completion system."""
    
    def test_all_commands_have_completions(self):
        """Test that all CLI commands are in completion scripts."""
        for shell in SUPPORTED_SHELLS:
            script = get_completion_script(shell)
            
            # Check major commands are present
            assert "scan" in script
            assert "profile" in script
            assert "history" in script
    
    def test_scan_options_in_all_shells(self):
        """Test that scan options appear in all shell completions."""
        key_options = ["--quick", "--json", "--tcp"]
        
        for shell in SUPPORTED_SHELLS:
            script = get_completion_script(shell)
            
            for opt in key_options:
                # Options might be formatted differently
                opt_base = opt.lstrip("-")
                assert opt in script or opt_base in script, \
                    f"Option {opt} not found in {shell} completion"
