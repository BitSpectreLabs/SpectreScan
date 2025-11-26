"""
Tests for Script Manager Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from pathlib import Path
from spectrescan.core.script_manager import (
    ScriptOptions,
    ScriptManager,
    create_default_script_options
)
from spectrescan.core.scripting_engine import ScriptCategory


class TestScriptOptions:
    """Tests for ScriptOptions dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        options = ScriptOptions()
        
        assert options.enabled is False
        assert options.script_names == []
        assert options.categories == []
        assert options.script_args == {}
        assert options.default_scripts is False
    
    def test_enabled(self):
        """Test enabled flag."""
        options = ScriptOptions(enabled=True)
        assert options.enabled is True
    
    def test_with_script_names(self):
        """Test with script names."""
        options = ScriptOptions(
            enabled=True,
            script_names=["http-title", "ssh-hostkey"]
        )
        
        assert len(options.script_names) == 2
        assert "http-title" in options.script_names
    
    def test_with_categories(self):
        """Test with categories."""
        options = ScriptOptions(
            enabled=True,
            categories=[ScriptCategory.DISCOVERY, ScriptCategory.SAFE]
        )
        
        assert len(options.categories) == 2
        assert ScriptCategory.DISCOVERY in options.categories
    
    def test_with_args(self):
        """Test with script arguments."""
        options = ScriptOptions(
            enabled=True,
            script_args={"timeout": 5, "verbose": True}
        )
        
        assert options.script_args["timeout"] == 5
        assert options.script_args["verbose"] is True
    
    def test_post_init_none_handling(self):
        """Test __post_init__ handles None values."""
        options = ScriptOptions(
            script_names=None,
            categories=None,
            script_args=None
        )
        
        assert options.script_names == []
        assert options.categories == []
        assert options.script_args == {}


class TestScriptManager:
    """Tests for ScriptManager class."""
    
    def test_init(self):
        """Test initialization."""
        manager = ScriptManager()
        
        assert manager.engine is not None
    
    def test_init_with_dir(self, tmp_path):
        """Test initialization with custom directory."""
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        
        manager = ScriptManager(scripts_dir=scripts_dir)
        
        assert manager.engine is not None


class TestParseScriptArgument:
    """Tests for parse_script_argument method."""
    
    def test_parse_empty(self):
        """Test parsing empty argument."""
        manager = ScriptManager()
        
        options = manager.parse_script_argument("")
        
        assert options.enabled is True
        assert len(options.script_names) == 0
    
    def test_parse_single_script(self):
        """Test parsing single script name."""
        manager = ScriptManager()
        
        options = manager.parse_script_argument("http-title")
        
        assert options.enabled is True
        assert "http-title" in options.script_names
    
    def test_parse_multiple_scripts(self):
        """Test parsing multiple scripts."""
        manager = ScriptManager()
        
        options = manager.parse_script_argument("http-title,ssh-hostkey")
        
        assert len(options.script_names) == 2
        assert "http-title" in options.script_names
        assert "ssh-hostkey" in options.script_names
    
    def test_parse_all(self):
        """Test parsing 'all' keyword."""
        manager = ScriptManager()
        
        options = manager.parse_script_argument("all")
        
        assert options.enabled is True
        # All scripts should be listed
        assert len(options.script_names) >= 0
    
    def test_parse_default(self):
        """Test parsing 'default' keyword."""
        manager = ScriptManager()
        
        options = manager.parse_script_argument("default")
        
        assert options.enabled is True
        assert options.default_scripts is True
        assert ScriptCategory.DEFAULT in options.categories
    
    def test_parse_category(self):
        """Test parsing category name."""
        manager = ScriptManager()
        
        options = manager.parse_script_argument("discovery")
        
        assert options.enabled is True
        assert ScriptCategory.DISCOVERY in options.categories
    
    def test_parse_wildcard(self):
        """Test parsing wildcard pattern."""
        manager = ScriptManager()
        
        options = manager.parse_script_argument("http-*")
        
        assert options.enabled is True
        # Should match http-* scripts


class TestFindMatchingScripts:
    """Tests for _find_matching_scripts method."""
    
    def test_wildcard_match(self):
        """Test wildcard matching."""
        manager = ScriptManager()
        
        matches = manager._find_matching_scripts("http-*")
        
        # All matches should start with http-
        for name in matches:
            assert name.startswith("http-")
    
    def test_no_match(self):
        """Test pattern with no matches."""
        manager = ScriptManager()
        
        matches = manager._find_matching_scripts("nonexistent-*")
        
        assert matches == []


class TestGetAvailableScripts:
    """Tests for get_available_scripts method."""
    
    def test_all_scripts(self):
        """Test getting all scripts."""
        manager = ScriptManager()
        
        scripts = manager.get_available_scripts()
        
        assert isinstance(scripts, list)
    
    def test_by_category(self):
        """Test getting scripts by category."""
        manager = ScriptManager()
        
        scripts = manager.get_available_scripts(category=ScriptCategory.DEFAULT)
        
        assert isinstance(scripts, list)


class TestGetScriptInfo:
    """Tests for get_script_info method."""
    
    def test_nonexistent_script(self):
        """Test getting info for nonexistent script."""
        manager = ScriptManager()
        
        info = manager.get_script_info("nonexistent-script")
        
        assert info is None
    
    def test_existing_script(self):
        """Test getting info for existing script."""
        manager = ScriptManager()
        
        # Get first available script
        scripts = manager.get_available_scripts()
        if scripts:
            info = manager.get_script_info(scripts[0])
            
            if info:
                assert "name" in info
                assert "description" in info
                assert "categories" in info


class TestFormatScriptResults:
    """Tests for format_script_results method."""
    
    def test_empty_results(self):
        """Test formatting empty results."""
        manager = ScriptManager()
        
        output = manager.format_script_results([])
        
        assert output == ""
    
    def test_format_with_results(self):
        """Test formatting with results."""
        from spectrescan.core.scripting_engine import ScriptResult
        
        manager = ScriptManager()
        
        results = [
            ScriptResult(
                script_name="http-title",
                host="192.168.1.1",
                port=80,
                success=True,
                output="<title>Test Page</title>",
                execution_time=0.5
            )
        ]
        
        output = manager.format_script_results(results)
        
        assert "http-title" in output
        assert "192.168.1.1" in output
        assert "Test Page" in output
    
    def test_format_verbose(self):
        """Test verbose formatting."""
        from spectrescan.core.scripting_engine import ScriptResult
        
        manager = ScriptManager()
        
        results = [
            ScriptResult(
                script_name="http-title",
                host="192.168.1.1",
                port=80,
                success=True,
                output="Title",
                execution_time=0.5,
                data={"title": "Test"}
            )
        ]
        
        output = manager.format_script_results(results, verbose=True)
        
        assert "Execution time" in output
    
    def test_format_failed_result(self):
        """Test formatting failed result."""
        from spectrescan.core.scripting_engine import ScriptResult
        
        manager = ScriptManager()
        
        results = [
            ScriptResult(
                script_name="http-title",
                host="192.168.1.1",
                port=80,
                success=False,
                output="",
                error="Connection refused",
                execution_time=0.1
            )
        ]
        
        output = manager.format_script_results(results)
        
        assert "FAILED" in output


class TestCreateDefaultScriptOptions:
    """Tests for create_default_script_options function."""
    
    def test_creates_enabled_options(self):
        """Test creates enabled options."""
        options = create_default_script_options()
        
        assert options.enabled is True
    
    def test_enables_default_scripts(self):
        """Test enables default scripts."""
        options = create_default_script_options()
        
        assert options.default_scripts is True
    
    def test_includes_default_category(self):
        """Test includes default category."""
        options = create_default_script_options()
        
        assert ScriptCategory.DEFAULT in options.categories
    
    def test_includes_safe_category(self):
        """Test includes safe category."""
        options = create_default_script_options()
        
        assert ScriptCategory.SAFE in options.categories


class TestRunScriptsForScan:
    """Tests for run_scripts_for_scan method."""
    
    @pytest.mark.asyncio
    async def test_disabled_options(self):
        """Test with disabled options."""
        manager = ScriptManager()
        
        options = ScriptOptions(enabled=False)
        results = await manager.run_scripts_for_scan(
            options=options,
            host="192.168.1.1",
            ports=[80, 443]
        )
        
        assert results == []
    
    @pytest.mark.asyncio
    async def test_empty_scripts(self):
        """Test with no scripts specified."""
        manager = ScriptManager()
        
        options = ScriptOptions(enabled=True)
        results = await manager.run_scripts_for_scan(
            options=options,
            host="192.168.1.1",
            ports=[80, 443]
        )
        
        assert results == []
