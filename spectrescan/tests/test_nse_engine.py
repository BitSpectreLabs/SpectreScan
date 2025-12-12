"""
Tests for NSE (Nmap Scripting Engine) Compatibility Layer.

by BitSpectreLabs
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from dataclasses import asdict

from spectrescan.core.nse_engine import (
    NSECategory,
    NSEScriptInfo,
    NSEScriptResult,
    NSEPortInfo,
    NSEHostInfo,
    NSELibrary,
    NSEScriptParser,
    NSEEngine,
    create_nse_engine,
    parse_script_args,
    format_nse_results,
    LUPA_AVAILABLE,
)


class TestNSECategory:
    """Tests for NSECategory enum."""
    
    def test_all_categories_exist(self):
        """Test all expected categories exist."""
        expected = [
            'auth', 'broadcast', 'brute', 'default', 'discovery',
            'dos', 'exploit', 'external', 'fuzzer', 'intrusive',
            'malware', 'safe', 'version', 'vuln'
        ]
        for cat in expected:
            assert hasattr(NSECategory, cat.upper())
    
    def test_category_values(self):
        """Test category values."""
        assert NSECategory.AUTH.value == "auth"
        assert NSECategory.DEFAULT.value == "default"
        assert NSECategory.SAFE.value == "safe"
        assert NSECategory.VULN.value == "vuln"


class TestNSEScriptInfo:
    """Tests for NSEScriptInfo dataclass."""
    
    def test_create_basic_info(self):
        """Test creating basic script info."""
        info = NSEScriptInfo(
            name="test-script",
            description="Test script",
            author="Test Author",
            categories=[NSECategory.SAFE, NSECategory.DEFAULT]
        )
        
        assert info.name == "test-script"
        assert info.description == "Test script"
        assert info.author == "Test Author"
        assert len(info.categories) == 2
    
    def test_default_values(self):
        """Test default values."""
        info = NSEScriptInfo(
            name="test",
            description="Test",
            author="Author",
            categories=[]
        )
        
        assert "Nmap" in info.license
        assert info.dependencies == []
        assert info.portrule is None
        assert info.hostrule is None
    
    def test_with_rules(self):
        """Test script info with rules."""
        info = NSEScriptInfo(
            name="test",
            description="Test",
            author="Author",
            categories=[NSECategory.DISCOVERY],
            portrule="function defined",
            hostrule="function defined"
        )
        
        assert info.portrule is not None
        assert info.hostrule is not None


class TestNSEScriptResult:
    """Tests for NSEScriptResult dataclass."""
    
    def test_create_success_result(self):
        """Test creating successful result."""
        result = NSEScriptResult(
            script_name="http-title",
            host="192.168.1.1",
            port=80,
            protocol="tcp",
            success=True,
            output="Welcome Page"
        )
        
        assert result.success is True
        assert result.output == "Welcome Page"
        assert result.error is None
    
    def test_create_failed_result(self):
        """Test creating failed result."""
        result = NSEScriptResult(
            script_name="ssh-hostkey",
            host="192.168.1.1",
            port=22,
            protocol="tcp",
            success=False,
            output="",
            error="Connection refused"
        )
        
        assert result.success is False
        assert result.error == "Connection refused"
    
    def test_default_values(self):
        """Test default values."""
        result = NSEScriptResult(
            script_name="test",
            host="127.0.0.1",
            port=None,
            protocol="tcp",
            success=True,
            output=""
        )
        
        assert result.structured_output == {}
        assert result.execution_time == 0.0


class TestNSEPortInfo:
    """Tests for NSEPortInfo dataclass."""
    
    def test_create_port_info(self):
        """Test creating port info."""
        port = NSEPortInfo(
            number=80,
            protocol="tcp",
            state="open",
            service="http",
            version="Apache/2.4"
        )
        
        assert port.number == 80
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.service == "http"
    
    def test_minimal_port_info(self):
        """Test minimal port info."""
        port = NSEPortInfo(number=443, protocol="tcp", state="open")
        
        assert port.service is None
        assert port.version is None
        assert port.product is None


class TestNSEHostInfo:
    """Tests for NSEHostInfo dataclass."""
    
    def test_create_host_info(self):
        """Test creating host info."""
        host = NSEHostInfo(
            ip="192.168.1.1",
            hostname="server.local",
            os="Linux"
        )
        
        assert host.ip == "192.168.1.1"
        assert host.hostname == "server.local"
        assert host.os == "Linux"
    
    def test_host_with_ports(self):
        """Test host with ports."""
        ports = [
            NSEPortInfo(number=22, protocol="tcp", state="open", service="ssh"),
            NSEPortInfo(number=80, protocol="tcp", state="open", service="http")
        ]
        
        host = NSEHostInfo(ip="192.168.1.1", ports=ports)
        
        assert len(host.ports) == 2
        assert host.ports[0].service == "ssh"


class TestNSEScriptParser:
    """Tests for NSEScriptParser."""
    
    def test_parse_simple_script(self):
        """Test parsing simple script content."""
        content = '''
description = "A simple test script"
author = "Test Author"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return true
end

action = function(host, port)
    return "Hello"
end
'''
        info = NSEScriptParser.parse_script_content("test-script", content)
        
        assert info.name == "test-script"
        assert info.description == "A simple test script"
        assert info.author == "Test Author"
        assert info.portrule is not None
    
    def test_parse_multiline_description(self):
        """Test parsing multiline description."""
        content = '''
description = [[
This is a longer description
that spans multiple lines
]]
author = "Author"
categories = {"discovery"}
'''
        info = NSEScriptParser.parse_script_content("multi-desc", content)
        
        assert "longer description" in info.description
        assert "multiple lines" in info.description
    
    def test_parse_categories(self):
        """Test parsing categories."""
        content = '''
description = "Test"
author = "Author"
categories = {"auth", "brute", "intrusive"}
'''
        info = NSEScriptParser.parse_script_content("cat-test", content)
        
        assert NSECategory.AUTH in info.categories
        assert NSECategory.BRUTE in info.categories
        assert NSECategory.INTRUSIVE in info.categories
    
    def test_parse_dependencies(self):
        """Test parsing dependencies."""
        content = '''
description = "Test"
author = "Author"
categories = {"default"}
dependencies = {"http", "shortport", "stdnse"}
'''
        info = NSEScriptParser.parse_script_content("dep-test", content)
        
        assert "http" in info.dependencies
        assert "shortport" in info.dependencies
    
    def test_parse_with_hostrule(self):
        """Test parsing script with hostrule."""
        content = '''
description = "Test"
author = "Author"
categories = {"discovery"}

hostrule = function(host)
    return true
end

action = function(host)
    return "Result"
end
'''
        info = NSEScriptParser.parse_script_content("host-test", content)
        
        assert info.hostrule is not None
        assert info.portrule is None
    
    def test_parse_unknown_category(self):
        """Test parsing with unknown category."""
        content = '''
description = "Test"
author = "Author"
categories = {"unknown_category", "safe"}
'''
        info = NSEScriptParser.parse_script_content("unknown-cat", content)
        
        # Should only have SAFE, unknown is ignored
        assert NSECategory.SAFE in info.categories
    
    def test_parse_empty_categories(self):
        """Test parsing with no categories."""
        content = '''
description = "Test"
author = "Author"
'''
        info = NSEScriptParser.parse_script_content("no-cat", content)
        
        # Should default to SAFE
        assert NSECategory.SAFE in info.categories


class TestNSELibrary:
    """Tests for NSELibrary (NSE function stubs)."""
    
    def test_create_library(self):
        """Test creating library."""
        lib = NSELibrary()
        
        assert lib.lua is None
        assert lib._socket_cache == {}
    
    def test_nmap_verbosity(self):
        """Test nmap.verbosity stub."""
        lib = NSELibrary()
        
        assert lib._nmap_verbosity() == 1
    
    def test_nmap_debugging(self):
        """Test nmap.debugging stub."""
        lib = NSELibrary()
        
        assert lib._nmap_debugging() == 0
    
    def test_nmap_clock_ms(self):
        """Test nmap.clock_ms stub."""
        lib = NSELibrary()
        
        ms = lib._nmap_clock_ms()
        assert isinstance(ms, int)
        assert ms > 0
    
    def test_nmap_clock(self):
        """Test nmap.clock stub."""
        lib = NSELibrary()
        
        t = lib._nmap_clock()
        assert isinstance(t, float)
        assert t > 0
    
    def test_stdnse_tohex(self):
        """Test stdnse.tohex stub."""
        lib = NSELibrary()
        
        result = lib._stdnse_tohex(b"ABC")
        assert result == "414243"
    
    def test_stdnse_tohex_string(self):
        """Test stdnse.tohex with string."""
        lib = NSELibrary()
        
        result = lib._stdnse_tohex("ABC")
        assert result == "414243"
    
    def test_stdnse_fromhex(self):
        """Test stdnse.fromhex stub."""
        lib = NSELibrary()
        
        result = lib._stdnse_fromhex("414243")
        assert result == "ABC"
    
    def test_lua_pattern_to_regex(self):
        """Test Lua pattern conversion."""
        lib = NSELibrary()
        
        # Test digit pattern
        result = lib._lua_pattern_to_regex("%d+")
        assert result == r"\d+"
        
        # Test word pattern
        result = lib._lua_pattern_to_regex("%w+")
        assert result == r"\w+"
        
        # Test escape
        result = lib._lua_pattern_to_regex("%%")
        assert result == "%"


class TestNSEEngine:
    """Tests for NSEEngine."""
    
    def test_create_engine(self):
        """Test creating engine."""
        engine = NSEEngine()
        
        assert engine.scripts_dir is not None
        assert engine.scripts == {}
    
    def test_create_engine_custom_dir(self, tmp_path):
        """Test creating engine with custom directory."""
        engine = NSEEngine(scripts_dir=tmp_path)
        
        assert engine.scripts_dir == tmp_path
    
    def test_lua_available_property(self):
        """Test lua_available property."""
        engine = NSEEngine()
        
        # Property should match LUPA_AVAILABLE constant
        assert engine.lua_available == (engine.lua is not None)
    
    def test_load_scripts_empty_dir(self, tmp_path):
        """Test loading scripts from empty directory."""
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        assert len(engine.scripts) == 0
    
    def test_load_scripts_with_pattern(self, tmp_path):
        """Test loading scripts with pattern filter."""
        # Create test scripts
        (tmp_path / "http-title.nse").write_text('''
description = "HTTP Title"
author = "Test"
categories = {"default"}
portrule = function() return true end
action = function() return "Title" end
''')
        (tmp_path / "ssh-hostkey.nse").write_text('''
description = "SSH Hostkey"
author = "Test"
categories = {"default"}
portrule = function() return true end
action = function() return "Key" end
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts(patterns=["http-*"])
        
        assert "http-title" in engine.scripts
        assert "ssh-hostkey" not in engine.scripts
    
    def test_get_script(self, tmp_path):
        """Test getting script by name."""
        (tmp_path / "test-script.nse").write_text('''
description = "Test"
author = "Test"
categories = {"safe"}
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        script = engine.get_script("test-script")
        assert script is not None
        assert script.name == "test-script"
    
    def test_get_nonexistent_script(self):
        """Test getting non-existent script."""
        engine = NSEEngine()
        
        script = engine.get_script("nonexistent")
        assert script is None
    
    def test_get_scripts_by_category(self, tmp_path):
        """Test getting scripts by category."""
        (tmp_path / "auth-test.nse").write_text('''
description = "Auth Test"
author = "Test"
categories = {"auth", "safe"}
''')
        (tmp_path / "vuln-test.nse").write_text('''
description = "Vuln Test"
author = "Test"
categories = {"vuln"}
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        auth_scripts = engine.get_scripts_by_category(NSECategory.AUTH)
        assert len(auth_scripts) == 1
        assert auth_scripts[0].name == "auth-test"
    
    def test_list_scripts(self, tmp_path):
        """Test listing all scripts."""
        (tmp_path / "script1.nse").write_text('description = "1"\nauthor = "A"\ncategories = {"safe"}')
        (tmp_path / "script2.nse").write_text('description = "2"\nauthor = "B"\ncategories = {"safe"}')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        scripts = engine.list_scripts()
        assert len(scripts) == 2
        assert "script1" in scripts
        assert "script2" in scripts
    
    def test_check_portrule_http(self, tmp_path):
        """Test portrule checking for HTTP."""
        (tmp_path / "http-title.nse").write_text('''
description = "HTTP Title"
author = "Test"
categories = {"default"}
portrule = function() return true end
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        host = NSEHostInfo(ip="192.168.1.1")
        port = NSEPortInfo(number=80, protocol="tcp", state="open", service="http")
        
        result = engine.check_portrule("http-title", host, port)
        assert result is True
    
    def test_check_portrule_ssh(self, tmp_path):
        """Test portrule checking for SSH."""
        (tmp_path / "ssh-hostkey.nse").write_text('''
description = "SSH Key"
author = "Test"
categories = {"default"}
portrule = function() return true end
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        host = NSEHostInfo(ip="192.168.1.1")
        port = NSEPortInfo(number=22, protocol="tcp", state="open", service="ssh")
        
        result = engine.check_portrule("ssh-hostkey", host, port)
        assert result is True
    
    def test_check_portrule_no_match(self, tmp_path):
        """Test portrule that doesn't match."""
        (tmp_path / "http-title.nse").write_text('''
description = "HTTP Title"
author = "Test"
categories = {"default"}
portrule = function() return true end
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        host = NSEHostInfo(ip="192.168.1.1")
        port = NSEPortInfo(number=22, protocol="tcp", state="open", service="ssh")
        
        result = engine.check_portrule("http-title", host, port)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_run_script_not_found(self):
        """Test running non-existent script."""
        engine = NSEEngine()
        host = NSEHostInfo(ip="192.168.1.1")
        
        result = await engine.run_script("nonexistent", host)
        
        assert result.success is False
        # Error can be either "not found" or "lua runtime not available"
        assert "not found" in result.error.lower() or "lua" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_run_script_no_lua(self, tmp_path):
        """Test running script without Lua runtime."""
        (tmp_path / "test.nse").write_text('''
description = "Test"
author = "Test"
categories = {"safe"}
action = function() return "Result" end
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.lua = None  # Force no Lua
        engine.load_scripts()
        
        host = NSEHostInfo(ip="192.168.1.1")
        result = await engine.run_script("test", host)
        
        assert result.success is False
        assert "lupa" in result.error.lower()


class TestParseScriptArgs:
    """Tests for parse_script_args function."""
    
    def test_empty_args(self):
        """Test empty argument string."""
        result = parse_script_args("")
        
        assert result == {}
    
    def test_single_arg(self):
        """Test single argument."""
        result = parse_script_args("user=admin")
        
        assert result == {"user": "admin"}
    
    def test_multiple_args(self):
        """Test multiple arguments."""
        result = parse_script_args("user=admin,pass=secret,port=8080")
        
        assert result == {
            "user": "admin",
            "pass": "secret",
            "port": "8080"
        }
    
    def test_flag_arg(self):
        """Test flag without value."""
        result = parse_script_args("verbose,debug")
        
        assert result == {"verbose": True, "debug": True}
    
    def test_mixed_args(self):
        """Test mixed args and flags."""
        result = parse_script_args("user=admin,verbose,timeout=5")
        
        assert result["user"] == "admin"
        assert result["verbose"] is True
        assert result["timeout"] == "5"


class TestFormatNSEResults:
    """Tests for format_nse_results function."""
    
    def test_empty_results(self):
        """Test formatting empty results."""
        result = format_nse_results([])
        
        assert result == ""
    
    def test_single_success_result(self):
        """Test formatting single successful result."""
        results = [
            NSEScriptResult(
                script_name="http-title",
                host="192.168.1.1",
                port=80,
                protocol="tcp",
                success=True,
                output="Welcome Page"
            )
        ]
        
        formatted = format_nse_results(results)
        
        assert "NSE SCRIPT RESULTS" in formatted
        assert "http-title" in formatted
        assert "Welcome Page" in formatted
        assert "192.168.1.1:80" in formatted
    
    def test_multiple_results(self):
        """Test formatting multiple results."""
        results = [
            NSEScriptResult(
                script_name="http-title",
                host="192.168.1.1",
                port=80,
                protocol="tcp",
                success=True,
                output="Title 1"
            ),
            NSEScriptResult(
                script_name="http-headers",
                host="192.168.1.1",
                port=80,
                protocol="tcp",
                success=True,
                output="Server: Apache"
            )
        ]
        
        formatted = format_nse_results(results)
        
        assert "http-title" in formatted
        assert "http-headers" in formatted
        assert "Title 1" in formatted
        assert "Server: Apache" in formatted
    
    def test_failed_result_verbose(self):
        """Test formatting failed result in verbose mode."""
        results = [
            NSEScriptResult(
                script_name="ssh-hostkey",
                host="192.168.1.1",
                port=22,
                protocol="tcp",
                success=False,
                output="",
                error="Connection refused"
            )
        ]
        
        formatted = format_nse_results(results, verbose=True)
        
        assert "FAILED" in formatted
        assert "Connection refused" in formatted
    
    def test_host_only_result(self):
        """Test formatting host-only result (no port)."""
        results = [
            NSEScriptResult(
                script_name="dns-zone-transfer",
                host="192.168.1.1",
                port=None,
                protocol="tcp",
                success=True,
                output="Zone data"
            )
        ]
        
        formatted = format_nse_results(results)
        
        assert "192.168.1.1" in formatted
        assert "dns-zone-transfer" in formatted
    
    def test_verbose_timing(self):
        """Test verbose mode shows timing."""
        results = [
            NSEScriptResult(
                script_name="http-title",
                host="192.168.1.1",
                port=80,
                protocol="tcp",
                success=True,
                output="Title",
                execution_time=1.5
            )
        ]
        
        formatted = format_nse_results(results, verbose=True)
        
        assert "1.5" in formatted or "Execution time" in formatted


class TestCreateNSEEngine:
    """Tests for create_nse_engine factory function."""
    
    def test_create_default_engine(self):
        """Test creating engine with defaults."""
        engine = create_nse_engine()
        
        assert isinstance(engine, NSEEngine)
    
    def test_create_engine_custom_path(self, tmp_path):
        """Test creating engine with custom path."""
        engine = create_nse_engine(scripts_dir=tmp_path)
        
        assert engine.scripts_dir == tmp_path


class TestNSEEngineIntegration:
    """Integration tests for NSE engine with actual scripts."""
    
    def test_load_bundled_scripts(self):
        """Test loading bundled NSE scripts."""
        scripts_dir = Path(__file__).parent.parent / "nse_scripts"
        
        if not scripts_dir.exists():
            pytest.skip("NSE scripts directory not found")
        
        engine = NSEEngine(scripts_dir=scripts_dir)
        engine.load_scripts()
        
        # Check some expected scripts
        expected_scripts = ["http-title", "ssh-hostkey", "ftp-anon"]
        for script in expected_scripts:
            if script in engine.scripts:
                info = engine.get_script(script)
                assert info is not None
                assert len(info.categories) > 0
    
    def test_bundled_scripts_have_categories(self):
        """Test that bundled scripts have proper categories."""
        scripts_dir = Path(__file__).parent.parent / "nse_scripts"
        
        if not scripts_dir.exists():
            pytest.skip("NSE scripts directory not found")
        
        engine = NSEEngine(scripts_dir=scripts_dir)
        engine.load_scripts()
        
        for name, info in engine.scripts.items():
            assert len(info.categories) > 0, f"Script {name} has no categories"
    
    @pytest.mark.asyncio
    async def test_run_multiple_scripts(self, tmp_path):
        """Test running multiple scripts."""
        # Create test scripts
        (tmp_path / "test1.nse").write_text('''
description = "Test 1"
author = "Test"
categories = {"safe"}
portrule = function() return true end
action = function() return "Result 1" end
''')
        (tmp_path / "test2.nse").write_text('''
description = "Test 2"
author = "Test"
categories = {"safe"}
portrule = function() return true end
action = function() return "Result 2" end
''')
        
        engine = NSEEngine(scripts_dir=tmp_path)
        engine.load_scripts()
        
        if not engine.lua_available:
            pytest.skip("Lua runtime not available")
        
        host = NSEHostInfo(ip="127.0.0.1")
        ports = [NSEPortInfo(number=80, protocol="tcp", state="open")]
        
        results = await engine.run_scripts(["test1", "test2"], host, ports)
        
        assert len(results) == 2


class TestShortportFunctions:
    """Tests for shortport library functions."""
    
    def test_port_or_service_port_match(self):
        """Test port_or_service with matching port."""
        lib = NSELibrary()
        matcher = lib._shortport_port_or_service([80, 443], ["http"])
        
        port = {"number": 80, "service": "unknown"}
        assert matcher(None, port) is True
    
    def test_port_or_service_service_match(self):
        """Test port_or_service with matching service."""
        lib = NSELibrary()
        matcher = lib._shortport_port_or_service([80], ["https"])
        
        port = {"number": 8443, "service": "https"}
        assert matcher(None, port) is True
    
    def test_port_or_service_no_match(self):
        """Test port_or_service with no match."""
        lib = NSELibrary()
        matcher = lib._shortport_port_or_service([80], ["http"])
        
        port = {"number": 22, "service": "ssh"}
        assert matcher(None, port) is False
    
    def test_shortport_http(self):
        """Test shortport.http matcher."""
        lib = NSELibrary()
        matcher = lib._shortport_http()
        
        # Should match HTTP ports
        assert matcher(None, {"number": 80, "service": ""}) is True
        assert matcher(None, {"number": 8080, "service": ""}) is True
        assert matcher(None, {"number": 22, "service": ""}) is False
    
    def test_shortport_ssl(self):
        """Test shortport.ssl matcher."""
        lib = NSELibrary()
        matcher = lib._shortport_ssl()
        
        # Should match SSL ports
        assert matcher(None, {"number": 443, "service": ""}) is True
        assert matcher(None, {"number": 993, "service": ""}) is True
        assert matcher(None, {"number": 80, "service": ""}) is False
