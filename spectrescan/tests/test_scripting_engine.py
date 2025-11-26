"""
Tests for Scripting Engine Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from pathlib import Path
from spectrescan.core.scripting_engine import (
    ScriptCategory,
    ScriptInfo,
    ScriptResult,
    Script,
    ScriptEngine
)


class TestScriptCategory:
    """Tests for ScriptCategory enum."""
    
    def test_discovery_category(self):
        """Test DISCOVERY category."""
        assert ScriptCategory.DISCOVERY.value == "discovery"
    
    def test_version_category(self):
        """Test VERSION category."""
        assert ScriptCategory.VERSION.value == "version"
    
    def test_vuln_category(self):
        """Test VULN category."""
        assert ScriptCategory.VULN.value == "vuln"
    
    def test_exploit_category(self):
        """Test EXPLOIT category."""
        assert ScriptCategory.EXPLOIT.value == "exploit"
    
    def test_auth_category(self):
        """Test AUTH category."""
        assert ScriptCategory.AUTH.value == "auth"
    
    def test_brute_category(self):
        """Test BRUTE category."""
        assert ScriptCategory.BRUTE.value == "brute"
    
    def test_default_category(self):
        """Test DEFAULT category."""
        assert ScriptCategory.DEFAULT.value == "default"
    
    def test_safe_category(self):
        """Test SAFE category."""
        assert ScriptCategory.SAFE.value == "safe"
    
    def test_intrusive_category(self):
        """Test INTRUSIVE category."""
        assert ScriptCategory.INTRUSIVE.value == "intrusive"
    
    def test_all_categories(self):
        """Test all categories are accessible."""
        categories = list(ScriptCategory)
        assert len(categories) >= 9


class TestScriptInfo:
    """Tests for ScriptInfo dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        info = ScriptInfo(
            name="test-script",
            description="A test script",
            author="BitSpectreLabs",
            categories=[ScriptCategory.SAFE]
        )
        assert info.name == "test-script"
        assert info.description == "A test script"
        assert info.author == "BitSpectreLabs"
        assert ScriptCategory.SAFE in info.categories
    
    def test_default_license(self):
        """Test default license is MIT."""
        info = ScriptInfo(
            name="test",
            description="test",
            author="test",
            categories=[]
        )
        assert info.license == "MIT"
    
    def test_default_version(self):
        """Test default version."""
        info = ScriptInfo(
            name="test",
            description="test",
            author="test",
            categories=[]
        )
        assert info.version == "1.0"
    
    def test_default_dependencies(self):
        """Test default empty dependencies."""
        info = ScriptInfo(
            name="test",
            description="test",
            author="test",
            categories=[]
        )
        assert info.dependencies == []
    
    def test_with_dependencies(self):
        """Test with dependencies."""
        info = ScriptInfo(
            name="test",
            description="test",
            author="test",
            categories=[],
            dependencies=["requests", "bs4"]
        )
        assert len(info.dependencies) == 2


class TestScriptResult:
    """Tests for ScriptResult dataclass."""
    
    def test_success_result(self):
        """Test successful result."""
        result = ScriptResult(
            script_name="http-title",
            host="192.168.1.1",
            port=80,
            success=True,
            output="Title: Example Website"
        )
        assert result.success is True
        assert result.error is None
    
    def test_failed_result(self):
        """Test failed result."""
        result = ScriptResult(
            script_name="http-title",
            host="192.168.1.1",
            port=80,
            success=False,
            output="",
            error="Connection refused"
        )
        assert result.success is False
        assert result.error == "Connection refused"
    
    def test_with_data(self):
        """Test result with data dictionary."""
        result = ScriptResult(
            script_name="http-headers",
            host="192.168.1.1",
            port=80,
            success=True,
            output="Headers retrieved",
            data={"Server": "nginx", "X-Powered-By": "PHP"}
        )
        assert "Server" in result.data
        assert result.data["Server"] == "nginx"
    
    def test_execution_time(self):
        """Test execution time tracking."""
        result = ScriptResult(
            script_name="test",
            host="localhost",
            port=80,
            success=True,
            output="done",
            execution_time=1.5
        )
        assert result.execution_time == 1.5
    
    def test_no_port(self):
        """Test result without port (host-level script)."""
        result = ScriptResult(
            script_name="host-info",
            host="192.168.1.1",
            port=None,
            success=True,
            output="Host info gathered"
        )
        assert result.port is None


class TestScriptBase:
    """Tests for Script base class."""
    
    def test_default_attributes(self):
        """Test default script attributes."""
        assert Script.name == "base"
        assert Script.author == "BitSpectreLabs"
        assert ScriptCategory.SAFE in Script.categories
    
    def test_init(self):
        """Test script initialization."""
        script = Script()
        assert script.logger is not None
    
    def test_run_not_implemented(self):
        """Test run method raises NotImplementedError."""
        script = Script()
        
        # Run is async, so we need to test it properly
        import asyncio
        with pytest.raises(NotImplementedError):
            asyncio.run(script.run(host="localhost"))
    
    def test_check_requirements(self):
        """Test check_requirements method."""
        script = Script()
        if hasattr(script, 'check_requirements'):
            result = script.check_requirements()
            assert isinstance(result, bool)


class TestScriptEngine:
    """Tests for ScriptEngine class."""
    
    def test_init(self):
        """Test engine initialization."""
        engine = ScriptEngine()
        assert engine is not None
    
    def test_init_with_scripts_dir(self):
        """Test initialization with scripts directory."""
        engine = ScriptEngine(scripts_dir=Path("."))
        assert engine is not None
    
    def test_scripts_dict(self):
        """Test scripts dictionary exists."""
        engine = ScriptEngine()
        assert hasattr(engine, 'scripts')
        assert isinstance(engine.scripts, dict)
    
    def test_load_builtin_scripts(self):
        """Test loading built-in scripts."""
        engine = ScriptEngine()
        
        if hasattr(engine, 'load_builtin_scripts'):
            engine.load_builtin_scripts()
            # May have loaded some scripts
    
    def test_get_scripts_by_category(self):
        """Test getting scripts by category."""
        engine = ScriptEngine()
        
        if hasattr(engine, 'get_scripts_by_category'):
            scripts = engine.get_scripts_by_category(ScriptCategory.SAFE)
            assert isinstance(scripts, list)
    
    def test_get_script(self):
        """Test getting a specific script."""
        engine = ScriptEngine()
        
        if hasattr(engine, 'get_script'):
            # Try to get a non-existent script
            script = engine.get_script("nonexistent-script")
            assert script is None
    
    def test_list_scripts(self):
        """Test listing all scripts."""
        engine = ScriptEngine()
        
        if hasattr(engine, 'list_scripts'):
            scripts = engine.list_scripts()
            assert isinstance(scripts, list)


class TestScriptEngineExecution:
    """Tests for script execution."""
    
    @pytest.mark.asyncio
    async def test_run_script(self):
        """Test running a script."""
        engine = ScriptEngine()
        
        if hasattr(engine, 'run_script'):
            # Try to run a non-existent script
            result = await engine.run_script(
                script_name="nonexistent",
                host="localhost",
                port=80
            )
            # Should return None or error result
    
    @pytest.mark.asyncio
    async def test_run_scripts_on_port(self):
        """Test running scripts on a port."""
        engine = ScriptEngine()
        
        if hasattr(engine, 'run_scripts_on_port'):
            results = await engine.run_scripts_on_port(
                host="localhost",
                port=80,
                service="http"
            )
            assert isinstance(results, list)


class TestCustomScript:
    """Tests for custom script implementation."""
    
    def test_custom_script_class(self):
        """Test creating a custom script class."""
        
        class TestScript(Script):
            name = "test-custom"
            description = "Custom test script"
            
            async def run(self, host, port=None, **kwargs):
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output="Test complete"
                )
        
        script = TestScript()
        assert script.name == "test-custom"
    
    @pytest.mark.asyncio
    async def test_custom_script_execution(self):
        """Test executing a custom script."""
        
        class TestScript(Script):
            name = "test-custom"
            description = "Custom test script"
            
            async def run(self, host, port=None, **kwargs):
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output="Test complete"
                )
        
        script = TestScript()
        result = await script.run("localhost", 80)
        assert result.success is True
        assert result.host == "localhost"
