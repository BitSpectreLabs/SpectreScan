"""
Tests for NSE CLI commands.
by BitSpectreLabs
"""

import pytest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from spectrescan.cli.main import app


runner = CliRunner()


class TestNSECLI:
    """Tests for NSE CLI command."""
    
    def test_script_help(self):
        """Test script command help."""
        result = runner.invoke(app, ["script", "--help"])
        assert result.exit_code == 0
        assert "NSE" in result.output or "nse" in result.output.lower()
        assert "list" in result.output
        assert "info" in result.output
        assert "run" in result.output
        assert "categories" in result.output
    
    def test_script_list(self):
        """Test listing scripts."""
        result = runner.invoke(app, ["script", "list"])
        # Should succeed (may or may not find scripts)
        assert result.exit_code == 0
    
    def test_script_categories(self):
        """Test showing categories."""
        result = runner.invoke(app, ["script", "categories"])
        assert result.exit_code == 0
        # Check for known categories
        assert "auth" in result.output.lower() or "discovery" in result.output.lower()
    
    def test_script_info_not_found(self):
        """Test script info for non-existent script."""
        result = runner.invoke(app, ["script", "info", "nonexistent-script-xyz"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()
    
    def test_script_info_no_name(self):
        """Test script info without name."""
        result = runner.invoke(app, ["script", "info"])
        assert result.exit_code != 0
    
    def test_script_run_no_target(self):
        """Test script run without target."""
        result = runner.invoke(app, ["script", "run", "http-title"])
        assert result.exit_code != 0
        assert "target" in result.output.lower()
    
    def test_script_run_no_name(self):
        """Test script run without script name."""
        result = runner.invoke(app, ["script", "run"])
        assert result.exit_code != 0
    
    def test_script_unknown_action(self):
        """Test unknown action."""
        result = runner.invoke(app, ["script", "unknown"])
        assert result.exit_code != 0
        assert "unknown" in result.output.lower() or "error" in result.output.lower()
    
    def test_script_list_verbose(self):
        """Test list with verbose output."""
        result = runner.invoke(app, ["script", "list", "--verbose"])
        assert result.exit_code == 0
    
    def test_script_list_category_filter(self):
        """Test list with category filter."""
        result = runner.invoke(app, ["script", "list", "--category", "discovery"])
        assert result.exit_code == 0
    
    def test_script_list_invalid_category(self):
        """Test list with invalid category filter."""
        result = runner.invoke(app, ["script", "list", "--category", "invalidcategory123"])
        # Should fail or show error
        assert result.exit_code != 0 or "error" in result.output.lower() or "unknown" in result.output.lower()


class TestNSECLIWithScripts:
    """Tests for NSE CLI with actual scripts."""
    
    def test_script_info_http_title(self):
        """Test getting info for http-title script."""
        result = runner.invoke(app, ["script", "info", "http-title"])
        # Should work since we have this script
        assert result.exit_code == 0
        assert "http-title" in result.output.lower()
        assert "description" in result.output.lower()
    
    def test_script_info_ssl_cert(self):
        """Test getting info for ssl-cert script."""
        result = runner.invoke(app, ["script", "info", "ssl-cert"])
        assert result.exit_code == 0
        assert "ssl" in result.output.lower() or "cert" in result.output.lower()
    
    def test_script_list_shows_bundled(self):
        """Test that bundled scripts are listed."""
        result = runner.invoke(app, ["script", "list"])
        assert result.exit_code == 0
        # Should show at least some of our bundled scripts
        bundled = ["http-title", "ssl-cert", "ssh-hostkey", "ftp-anon"]
        found = sum(1 for s in bundled if s in result.output)
        assert found >= 2, f"Expected at least 2 bundled scripts, found {found}"


class TestNSECLIScriptRun:
    """Tests for NSE script run command."""
    
    def test_script_run_localhost(self):
        """Test running script against localhost (may fail to connect but should attempt)."""
        result = runner.invoke(app, ["script", "run", "http-title", "--target", "127.0.0.1", "--port", "80"])
        # With Lupa installed, will attempt to run but may fail to connect
        # Without Lupa, will fail with Lua not available error
        # Either way, it should produce some output
        assert "script" in result.output.lower() or "http-title" in result.output.lower()
    
    def test_script_run_nonexistent(self):
        """Test running non-existent script."""
        result = runner.invoke(app, ["script", "run", "nonexistent-script", "--target", "127.0.0.1"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()
    
    def test_script_run_with_args(self):
        """Test running script with args (tests argument parsing)."""
        result = runner.invoke(app, ["script", "run", "http-title", 
                                      "--target", "127.0.0.1",
                                      "--port", "80",
                                      "--script-args", "http.useragent=TestAgent"])
        # Should parse arguments correctly
        # With Lupa installed, will attempt to run but may fail to connect
        # Either way, Arguments should be shown in output
        assert "argument" in result.output.lower() or "script" in result.output.lower()


class TestNSEIntegration:
    """Integration tests for NSE system."""
    
    def test_engine_in_core_exports(self):
        """Test that NSE engine is exported from core."""
        from spectrescan import core
        assert hasattr(core, 'NSE_AVAILABLE')
    
    def test_nse_categories_complete(self):
        """Test all expected categories exist."""
        from spectrescan.core.nse_engine import NSECategory
        
        expected = ['auth', 'broadcast', 'brute', 'default', 'discovery', 
                    'dos', 'exploit', 'external', 'fuzzer', 'intrusive',
                    'malware', 'safe', 'version', 'vuln']
        
        for cat in expected:
            assert NSECategory(cat), f"Missing category: {cat}"
    
    def test_script_parser_dataclasses(self):
        """Test NSE dataclasses are properly defined."""
        from spectrescan.core.nse_engine import (
            NSEScriptInfo, NSEScriptResult, NSEHostInfo, NSEPortInfo
        )
        
        # Should be able to create instances
        host = NSEHostInfo(ip="192.168.1.1")
        assert host.ip == "192.168.1.1"
        
        port = NSEPortInfo(number=80, protocol="tcp", state="open")
        assert port.number == 80
        
        result = NSEScriptResult(
            script_name="test",
            host="192.168.1.1",
            port=80,
            protocol="tcp",
            success=True,
            output="test output"
        )
        assert result.success is True
