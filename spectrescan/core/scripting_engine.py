"""
Python Scripting Engine
NSE (Nmap Scripting Engine) alternative using Python.

Author: BitSpectreLabs
License: MIT
"""

import os
import sys
import logging
import importlib.util
import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class ScriptCategory(Enum):
    """Script categories (like NSE)."""
    DISCOVERY = "discovery"
    VERSION = "version"
    VULN = "vuln"
    EXPLOIT = "exploit"
    AUTH = "auth"
    BRUTE = "brute"
    DEFAULT = "default"
    SAFE = "safe"
    INTRUSIVE = "intrusive"
    MALWARE = "malware"


@dataclass
class ScriptInfo:
    """Script metadata."""
    name: str
    description: str
    author: str
    categories: List[ScriptCategory]
    license: str = "MIT"
    version: str = "1.0"
    dependencies: List[str] = field(default_factory=list)


@dataclass
class ScriptResult:
    """Result from script execution."""
    script_name: str
    host: str
    port: Optional[int]
    success: bool
    output: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0


class Script:
    """
    Base class for SpectreScan scripts.
    All scripts should inherit from this class.
    """
    
    # Script metadata (override in subclasses)
    name: str = "base"
    description: str = "Base script class"
    author: str = "BitSpectreLabs"
    categories: List[ScriptCategory] = [ScriptCategory.SAFE]
    
    def __init__(self):
        """Initialize script."""
        self.logger = logging.getLogger(f"script.{self.name}")
    
    async def run(
        self,
        host: str,
        port: Optional[int] = None,
        service: Optional[str] = None,
        banner: Optional[str] = None,
        **kwargs
    ) -> ScriptResult:
        """
        Run the script.
        
        Args:
            host: Target host
            port: Target port (if applicable)
            service: Detected service name
            banner: Service banner (if available)
            **kwargs: Additional arguments
        
        Returns:
            ScriptResult with execution results
        """
        raise NotImplementedError("Scripts must implement run() method")
    
    def check_requirements(self) -> bool:
        """
        Check if script requirements are met.
        
        Returns:
            True if requirements satisfied
        """
        return True
    
    def get_info(self) -> ScriptInfo:
        """Get script metadata."""
        return ScriptInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            categories=self.categories
        )


class ScriptEngine:
    """
    Script execution engine.
    Loads, manages, and executes Python scripts.
    """
    
    def __init__(self, scripts_dir: Optional[Path] = None):
        """
        Initialize script engine.
        
        Args:
            scripts_dir: Directory containing scripts (default: spectrescan/scripts)
        """
        if scripts_dir is None:
            # Default to spectrescan/scripts directory
            self.scripts_dir = Path(__file__).parent.parent / "scripts"
        else:
            self.scripts_dir = Path(scripts_dir)
        
        self.scripts: Dict[str, Script] = {}
        self.script_categories: Dict[ScriptCategory, List[str]] = {}
        
        logger.info(f"ScriptEngine initialized with scripts_dir: {self.scripts_dir}")
    
    def load_scripts(self, patterns: Optional[List[str]] = None):
        """
        Load scripts from scripts directory.
        
        Args:
            patterns: Optional list of script name patterns to load (e.g., ["http-*", "ssh-*"])
                     If None, loads all scripts
        """
        if not self.scripts_dir.exists():
            logger.warning(f"Scripts directory not found: {self.scripts_dir}")
            return
        
        # Find all Python files
        script_files = list(self.scripts_dir.glob("*.py"))
        
        for script_file in script_files:
            if script_file.name.startswith("__"):
                continue
            
            # Check if matches patterns
            if patterns:
                if not any(self._matches_pattern(script_file.stem, pattern) for pattern in patterns):
                    continue
            
            try:
                self._load_script_file(script_file)
            except Exception as e:
                logger.error(f"Failed to load script {script_file.name}: {e}")
    
    def _matches_pattern(self, script_name: str, pattern: str) -> bool:
        """Check if script name matches pattern (supports wildcards)."""
        import fnmatch
        return fnmatch.fnmatch(script_name, pattern)
    
    def _load_script_file(self, script_path: Path):
        """Load a single script file."""
        module_name = f"spectrescan.scripts.{script_path.stem}"
        
        # Load module dynamically
        spec = importlib.util.spec_from_file_location(module_name, script_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load script: {script_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # Find Script subclass in module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, Script) and attr != Script:
                # Instantiate script
                script_instance = attr()
                script_name = script_instance.name
                
                # Check requirements
                if not script_instance.check_requirements():
                    logger.warning(f"Script {script_name} requirements not met, skipping")
                    continue
                
                self.scripts[script_name] = script_instance
                
                # Index by categories
                for category in script_instance.categories:
                    if category not in self.script_categories:
                        self.script_categories[category] = []
                    self.script_categories[category].append(script_name)
                
                logger.info(f"Loaded script: {script_name}")
                break
    
    def get_script(self, name: str) -> Optional[Script]:
        """Get script by name."""
        return self.scripts.get(name)
    
    def get_scripts_by_category(self, category: ScriptCategory) -> List[Script]:
        """Get all scripts in a category."""
        script_names = self.script_categories.get(category, [])
        return [self.scripts[name] for name in script_names]
    
    def list_scripts(
        self,
        category: Optional[ScriptCategory] = None
    ) -> List[ScriptInfo]:
        """
        List available scripts.
        
        Args:
            category: Filter by category (optional)
        
        Returns:
            List of script metadata
        """
        if category:
            scripts = self.get_scripts_by_category(category)
        else:
            scripts = list(self.scripts.values())
        
        return [script.get_info() for script in scripts]
    
    async def run_script(
        self,
        script_name: str,
        host: str,
        port: Optional[int] = None,
        service: Optional[str] = None,
        banner: Optional[str] = None,
        **kwargs
    ) -> ScriptResult:
        """
        Run a single script.
        
        Args:
            script_name: Name of script to run
            host: Target host
            port: Target port
            service: Service name
            banner: Service banner
            **kwargs: Additional arguments
        
        Returns:
            ScriptResult
        """
        script = self.get_script(script_name)
        if not script:
            return ScriptResult(
                script_name=script_name,
                host=host,
                port=port,
                success=False,
                output="",
                error=f"Script not found: {script_name}"
            )
        
        import time
        start_time = time.time()
        
        try:
            result = await script.run(
                host=host,
                port=port,
                service=service,
                banner=banner,
                **kwargs
            )
            result.execution_time = time.time() - start_time
            return result
        
        except Exception as e:
            logger.error(f"Script {script_name} failed: {e}")
            return ScriptResult(
                script_name=script_name,
                host=host,
                port=port,
                success=False,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    async def run_scripts(
        self,
        script_names: List[str],
        host: str,
        ports: Optional[List[int]] = None,
        services: Optional[Dict[int, str]] = None,
        banners: Optional[Dict[int, str]] = None,
        **kwargs
    ) -> List[ScriptResult]:
        """
        Run multiple scripts.
        
        Args:
            script_names: List of script names
            host: Target host
            ports: Target ports (if applicable)
            services: Dict of port->service mappings
            banners: Dict of port->banner mappings
            **kwargs: Additional arguments
        
        Returns:
            List of ScriptResult objects
        """
        results = []
        
        for script_name in script_names:
            if ports:
                # Run script for each port
                for port in ports:
                    service = services.get(port) if services else None
                    banner = banners.get(port) if banners else None
                    
                    result = await self.run_script(
                        script_name=script_name,
                        host=host,
                        port=port,
                        service=service,
                        banner=banner,
                        **kwargs
                    )
                    results.append(result)
            else:
                # Run script without port
                result = await self.run_script(
                    script_name=script_name,
                    host=host,
                    **kwargs
                )
                results.append(result)
        
        return results
    
    async def run_category(
        self,
        category: ScriptCategory,
        host: str,
        ports: Optional[List[int]] = None,
        **kwargs
    ) -> List[ScriptResult]:
        """
        Run all scripts in a category.
        
        Args:
            category: Script category
            host: Target host
            ports: Target ports
            **kwargs: Additional arguments
        
        Returns:
            List of ScriptResult objects
        """
        scripts = self.get_scripts_by_category(category)
        script_names = [s.name for s in scripts]
        
        return await self.run_scripts(script_names, host, ports, **kwargs)


def create_script_template(
    name: str,
    description: str,
    categories: List[ScriptCategory],
    output_path: Path
):
    """
    Create a script template file.
    
    Args:
        name: Script name
        description: Script description
        categories: Script categories
        output_path: Output file path
    """
    template = f'''"""
{name}.py
{description}

Author: Your Name
License: MIT
"""

from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class {name.replace("-", "_").title().replace("_", "")}(Script):
    """
    {description}
    """
    
    name = "{name}"
    description = "{description}"
    author = "Your Name"
    categories = {[f"ScriptCategory.{cat.name}" for cat in categories]}
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        output_lines = []
        data = {{}}
        
        try:
            # Script logic here
            output_lines.append(f"Running {{self.name}} on {{host}}{{f':{{port}}' if port else ''}}")
            
            # Example: Check if specific service
            if service:
                output_lines.append(f"Service detected: {{service}}")
            
            # Add your detection/enumeration/exploitation logic here
            
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=True,
                output="\\n".join(output_lines),
                data=data
            )
        
        except Exception as e:
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="\\n".join(output_lines),
                error=str(e)
            )
'''
    
    output_path.write_text(template)
    logger.info(f"Created script template: {output_path}")
