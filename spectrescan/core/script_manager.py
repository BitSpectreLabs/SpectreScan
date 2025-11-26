"""
Script Management System
Implements -sC and --script flags for script execution.

Author: BitSpectreLabs
License: MIT
"""

import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path

from .scripting_engine import ScriptEngine, ScriptCategory, ScriptResult

logger = logging.getLogger(__name__)


@dataclass
class ScriptOptions:
    """Options for script execution."""
    enabled: bool = False
    script_names: List[str] = None
    categories: List[ScriptCategory] = None
    script_args: Dict[str, Any] = None
    default_scripts: bool = False
    
    def __post_init__(self):
        if self.script_names is None:
            self.script_names = []
        if self.categories is None:
            self.categories = []
        if self.script_args is None:
            self.script_args = {}


class ScriptManager:
    """
    Manage script execution for scans.
    Implements Nmap-style script options.
    """
    
    def __init__(self, scripts_dir: Optional[Path] = None):
        """
        Initialize script manager.
        
        Args:
            scripts_dir: Directory containing scripts
        """
        self.engine = ScriptEngine(scripts_dir)
        self.engine.load_scripts()
        
        logger.info(f"ScriptManager initialized with {len(self.engine.scripts)} scripts")
    
    def parse_script_argument(self, script_arg: str) -> ScriptOptions:
        """
        Parse --script argument.
        
        Supports:
        - Single script: --script http-title
        - Multiple scripts: --script http-title,ssh-hostkey
        - Wildcards: --script "http-*"
        - Categories: --script discovery
        - Combinations: --script "http-*,ssh-*"
        - All: --script all
        - Default: --script default
        
        Args:
            script_arg: Script argument string
        
        Returns:
            ScriptOptions object
        """
        options = ScriptOptions(enabled=True)
        
        if not script_arg:
            return options
        
        # Handle special keywords
        if script_arg.lower() == "all":
            options.script_names = list(self.engine.scripts.keys())
            return options
        
        if script_arg.lower() == "default":
            options.default_scripts = True
            options.categories.append(ScriptCategory.DEFAULT)
            return options
        
        # Split by comma
        parts = [p.strip() for p in script_arg.split(',')]
        
        for part in parts:
            # Check if it's a category
            try:
                category = ScriptCategory(part.lower())
                options.categories.append(category)
                continue
            except ValueError:
                pass
            
            # Check if it's a wildcard pattern
            if '*' in part or '?' in part:
                # Load matching scripts
                matching = self._find_matching_scripts(part)
                options.script_names.extend(matching)
            else:
                # Direct script name
                options.script_names.append(part)
        
        return options
    
    def _find_matching_scripts(self, pattern: str) -> List[str]:
        """Find scripts matching wildcard pattern."""
        import fnmatch
        return [
            name for name in self.engine.scripts.keys()
            if fnmatch.fnmatch(name, pattern)
        ]
    
    async def run_scripts_for_scan(
        self,
        options: ScriptOptions,
        host: str,
        ports: List[int],
        services: Optional[Dict[int, str]] = None,
        banners: Optional[Dict[int, str]] = None
    ) -> List[ScriptResult]:
        """
        Run scripts for a scan based on options.
        
        Args:
            options: Script options
            host: Target host
            ports: List of open ports
            services: Dict of port->service mappings
            banners: Dict of port->banner mappings
        
        Returns:
            List of script results
        """
        if not options.enabled:
            return []
        
        script_names = set()
        
        # Add scripts by category
        for category in options.categories:
            scripts = self.engine.get_scripts_by_category(category)
            script_names.update(s.name for s in scripts)
        
        # Add explicit script names
        script_names.update(options.script_names)
        
        if not script_names:
            logger.warning("No scripts to run")
            return []
        
        logger.info(f"Running {len(script_names)} scripts on {host}")
        
        # Run scripts
        results = await self.engine.run_scripts(
            script_names=list(script_names),
            host=host,
            ports=ports,
            services=services,
            banners=banners,
            **options.script_args
        )
        
        return results
    
    def format_script_results(
        self,
        results: List[ScriptResult],
        verbose: bool = False
    ) -> str:
        """
        Format script results for display.
        
        Args:
            results: List of script results
            verbose: Show detailed output
        
        Returns:
            Formatted string
        """
        if not results:
            return ""
        
        output_lines = []
        output_lines.append("\n" + "=" * 60)
        output_lines.append("SCRIPT RESULTS")
        output_lines.append("=" * 60)
        
        # Group by host:port
        grouped = {}
        for result in results:
            key = f"{result.host}:{result.port}" if result.port else result.host
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(result)
        
        for key, port_results in grouped.items():
            output_lines.append(f"\n{key}:")
            
            for result in port_results:
                if result.success:
                    output_lines.append(f"  [{result.script_name}]")
                    
                    # Indent output
                    for line in result.output.split('\n'):
                        output_lines.append(f"    {line}")
                    
                    if verbose and result.data:
                        output_lines.append(f"    Data: {result.data}")
                    
                    if verbose:
                        output_lines.append(f"    Execution time: {result.execution_time:.2f}s")
                else:
                    output_lines.append(f"  [{result.script_name}] FAILED")
                    if verbose and result.error:
                        output_lines.append(f"    Error: {result.error}")
        
        return "\n".join(output_lines)
    
    def get_available_scripts(
        self,
        category: Optional[ScriptCategory] = None
    ) -> List[str]:
        """
        Get list of available script names.
        
        Args:
            category: Filter by category (optional)
        
        Returns:
            List of script names
        """
        if category:
            scripts = self.engine.get_scripts_by_category(category)
            return [s.name for s in scripts]
        else:
            return list(self.engine.scripts.keys())
    
    def get_script_info(self, script_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a script.
        
        Args:
            script_name: Name of script
        
        Returns:
            Dictionary with script info
        """
        script = self.engine.get_script(script_name)
        if not script:
            return None
        
        info = script.get_info()
        return {
            "name": info.name,
            "description": info.description,
            "author": info.author,
            "categories": [c.value for c in info.categories],
            "version": info.version,
            "dependencies": info.dependencies
        }


def create_default_script_options() -> ScriptOptions:
    """Create default script options (for -sC flag)."""
    return ScriptOptions(
        enabled=True,
        default_scripts=True,
        categories=[ScriptCategory.DEFAULT, ScriptCategory.SAFE]
    )
