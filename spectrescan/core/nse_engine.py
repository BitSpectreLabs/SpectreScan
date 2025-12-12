"""
NSE (Nmap Scripting Engine) Compatibility Layer
Provides Lua script execution for Nmap .nse script compatibility.

Author: BitSpectreLabs
License: MIT
"""

import os
import re
import logging
import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set, Tuple, Callable
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)

# Try to import lupa for Lua support
try:
    import lupa
    from lupa import LuaRuntime
    LUPA_AVAILABLE = True
except ImportError:
    LUPA_AVAILABLE = False
    LuaRuntime = None
    logger.warning("lupa not installed - NSE Lua scripts will not be available")


class NSECategory(Enum):
    """NSE script categories."""
    AUTH = "auth"
    BROADCAST = "broadcast"
    BRUTE = "brute"
    DEFAULT = "default"
    DISCOVERY = "discovery"
    DOS = "dos"
    EXPLOIT = "exploit"
    EXTERNAL = "external"
    FUZZER = "fuzzer"
    INTRUSIVE = "intrusive"
    MALWARE = "malware"
    SAFE = "safe"
    VERSION = "version"
    VULN = "vuln"


@dataclass
class NSEScriptInfo:
    """NSE script metadata."""
    name: str
    description: str
    author: str
    categories: List[NSECategory]
    license: str = "Same as Nmap--See https://nmap.org/book/man-legal.html"
    dependencies: List[str] = field(default_factory=list)
    portrule: Optional[str] = None
    hostrule: Optional[str] = None
    prerule: Optional[str] = None
    postrule: Optional[str] = None
    path: Optional[Path] = None


@dataclass
class NSEScriptResult:
    """Result from NSE script execution."""
    script_name: str
    host: str
    port: Optional[int]
    protocol: str
    success: bool
    output: str
    structured_output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class NSEPortInfo:
    """Port information for NSE scripts."""
    number: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None


@dataclass
class NSEHostInfo:
    """Host information for NSE scripts."""
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    ports: List[NSEPortInfo] = field(default_factory=list)


class NSELibrary:
    """
    Provides NSE library functions accessible from Lua scripts.
    Emulates nmap, stdnse, shortport, etc.
    """
    
    def __init__(self, lua_runtime: Optional['LuaRuntime'] = None):
        self.lua = lua_runtime
        self._socket_cache: Dict[str, socket.socket] = {}
    
    def setup_globals(self, lua: 'LuaRuntime'):
        """Set up global NSE functions in Lua environment."""
        self.lua = lua
        g = lua.globals()
        
        # nmap library
        nmap_table = lua.table()
        nmap_table['socket'] = self._create_socket_class()
        nmap_table['new_socket'] = self._nmap_new_socket
        nmap_table['new_try'] = self._nmap_new_try
        nmap_table['verbosity'] = self._nmap_verbosity
        nmap_table['debugging'] = self._nmap_debugging
        nmap_table['log_write'] = self._nmap_log_write
        nmap_table['get_port_state'] = self._nmap_get_port_state
        nmap_table['clock_ms'] = self._nmap_clock_ms
        nmap_table['clock'] = self._nmap_clock
        nmap_table['registry'] = lua.table()
        g['nmap'] = nmap_table
        
        # stdnse library
        stdnse_table = lua.table()
        stdnse_table['sleep'] = self._stdnse_sleep
        stdnse_table['format_output'] = self._stdnse_format_output
        stdnse_table['output_table'] = self._stdnse_output_table
        stdnse_table['debug'] = self._stdnse_debug
        stdnse_table['verbose'] = self._stdnse_verbose
        stdnse_table['print_debug'] = self._stdnse_debug
        stdnse_table['print_verbose'] = self._stdnse_verbose
        stdnse_table['tohex'] = self._stdnse_tohex
        stdnse_table['fromhex'] = self._stdnse_fromhex
        stdnse_table['strsplit'] = self._stdnse_strsplit
        g['stdnse'] = stdnse_table
        
        # shortport library
        shortport_table = lua.table()
        shortport_table['port_or_service'] = self._shortport_port_or_service
        shortport_table['http'] = self._shortport_http
        shortport_table['ssl'] = self._shortport_ssl
        shortport_table['port_range'] = self._shortport_port_range
        shortport_table['service'] = self._shortport_service
        g['shortport'] = shortport_table
        
        # string extensions
        string_table = g['string']
        if string_table:
            string_table['match'] = self._string_match
        
        # table extensions  
        table_table = g['table']
        if table_table:
            table_table['concat'] = self._table_concat
        
        # Utility require function
        g['require'] = self._require_module
    
    def _nmap_new_socket(self):
        """Create new nmap socket as a Lua-friendly table."""
        sock_state = {
            'socket': None,
            'host': None,
            'port': None,
            'timeout': 5.0
        }
        
        # Methods need to accept 'self' as first arg when called with : syntax
        def connect(self_table, host, port, protocol="tcp"):
            try:
                if protocol.lower() == "tcp":
                    sock_state['socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    sock_state['socket'] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                sock_state['socket'].settimeout(sock_state['timeout'])
                sock_state['socket'].connect((host, int(port)))
                sock_state['host'] = host
                sock_state['port'] = port
                return True, None
            except Exception as e:
                return False, str(e)
        
        def send(self_table, data):
            try:
                if isinstance(data, str):
                    data = data.encode()
                sock_state['socket'].send(data)
                return True, None
            except Exception as e:
                return False, str(e)
        
        def receive(self_table):
            try:
                data = sock_state['socket'].recv(8192)
                return True, data.decode('utf-8', errors='replace')
            except Exception as e:
                return False, str(e)
        
        def receive_lines(self_table):
            try:
                data = sock_state['socket'].recv(8192)
                lines = data.decode('utf-8', errors='replace').split('\n')
                return True, self.lua.table_from(lines)
            except Exception as e:
                return False, str(e)
        
        def receive_bytes(self_table, count):
            try:
                data = sock_state['socket'].recv(count)
                return True, data
            except Exception as e:
                return False, str(e)
        
        def close(self_table):
            if sock_state['socket']:
                try:
                    sock_state['socket'].close()
                except:
                    pass
                sock_state['socket'] = None
        
        def set_timeout(self_table, timeout):
            sock_state['timeout'] = timeout
            if sock_state['socket']:
                sock_state['socket'].settimeout(timeout)
        
        def get_info(self_table):
            return self.lua.table_from({
                'host': sock_state['host'],
                'port': sock_state['port']
            })
        
        # Return as Lua table with functions
        sock_table = self.lua.table()
        sock_table['connect'] = connect
        sock_table['send'] = send
        sock_table['receive'] = receive
        sock_table['receive_lines'] = receive_lines
        sock_table['receive_bytes'] = receive_bytes
        sock_table['close'] = close
        sock_table['set_timeout'] = set_timeout
        sock_table['get_info'] = get_info
        
        return sock_table
    
    def _create_socket_class(self):
        """Create nmap socket class (legacy)."""
        return self._nmap_new_socket
    
    def _nmap_new_try(self, func):
        """Create try wrapper for error handling."""
        def try_wrapper(*args):
            try:
                return func(*args)
            except Exception as e:
                return None, str(e)
        return try_wrapper
    
    def _nmap_verbosity(self):
        """Get verbosity level."""
        return 1
    
    def _nmap_debugging(self):
        """Get debugging level."""
        return 0
    
    def _nmap_log_write(self, level, message):
        """Write to log."""
        logger.info(f"[NSE] {message}")
    
    def _nmap_get_port_state(self, host, port):
        """Get port state."""
        return self.lua.table_from({'state': 'open'})
    
    def _nmap_clock_ms(self):
        """Get current time in milliseconds."""
        return int(time.time() * 1000)
    
    def _nmap_clock(self):
        """Get current time in seconds."""
        return time.time()
    
    def _stdnse_sleep(self, seconds):
        """Sleep for seconds."""
        time.sleep(seconds)
    
    def _stdnse_format_output(self, success, output):
        """Format output."""
        if success:
            return output
        return None
    
    def _stdnse_output_table(self):
        """Create output table."""
        return self.lua.table()
    
    def _stdnse_debug(self, level, *args):
        """Debug output."""
        if level <= 1:
            logger.debug(f"[NSE DEBUG] {' '.join(str(a) for a in args)}")
    
    def _stdnse_verbose(self, level, *args):
        """Verbose output."""
        if level <= 1:
            logger.info(f"[NSE VERBOSE] {' '.join(str(a) for a in args)}")
    
    def _stdnse_tohex(self, data):
        """Convert to hex string."""
        if isinstance(data, str):
            data = data.encode()
        return data.hex()
    
    def _stdnse_fromhex(self, hex_str):
        """Convert from hex string."""
        return bytes.fromhex(hex_str).decode('utf-8', errors='replace')
    
    def _stdnse_strsplit(self, pattern, text):
        """Split string by pattern."""
        return self.lua.table_from(re.split(pattern, text))
    
    def _shortport_port_or_service(self, ports, services, protocols=None, states=None):
        """Create port/service matcher."""
        if protocols is None:
            protocols = ["tcp"]
        if states is None:
            states = ["open"]
        
        def matcher(host, port):
            if port['number'] in ports:
                return True
            if port.get('service') in services:
                return True
            return False
        
        return matcher
    
    def _shortport_http(self):
        """HTTP port matcher."""
        return self._shortport_port_or_service(
            [80, 443, 8080, 8443, 8000],
            ["http", "https", "http-alt", "https-alt"]
        )
    
    def _shortport_ssl(self):
        """SSL port matcher."""
        return self._shortport_port_or_service(
            [443, 465, 993, 995, 8443],
            ["https", "ssl", "smtps", "imaps", "pop3s"]
        )
    
    def _shortport_port_range(self, start, end, protocols=None, states=None):
        """Port range matcher."""
        ports = list(range(start, end + 1))
        return self._shortport_port_or_service(ports, [], protocols, states)
    
    def _shortport_service(self, services, protocols=None, states=None):
        """Service matcher."""
        return self._shortport_port_or_service([], services, protocols, states)
    
    def _string_match(self, s, pattern):
        """Lua string.match implementation."""
        # Convert Lua pattern to Python regex
        py_pattern = self._lua_pattern_to_regex(pattern)
        match = re.search(py_pattern, s)
        if match:
            return match.group(0)
        return None
    
    def _lua_pattern_to_regex(self, pattern):
        """Convert Lua pattern to Python regex."""
        # Basic conversion - Lua patterns are similar to regex but not identical
        # %d -> \d, %s -> \s, %w -> \w, etc.
        conversions = {
            '%d': r'\d',
            '%s': r'\s',
            '%w': r'\w',
            '%a': r'[a-zA-Z]',
            '%l': r'[a-z]',
            '%u': r'[A-Z]',
            '%p': r'[^\w\s]',
            '%c': r'[\x00-\x1f]',
            '%.': r'\.',
            '%[': r'\[',
            '%]': r'\]',
            '%(': r'\(',
            '%)': r'\)',
            '%+': r'\+',
            '%-': r'-',
            '%*': r'\*',
            '%?': r'\?',
            '%%': r'%',
        }
        
        result = pattern
        for lua_pat, py_pat in conversions.items():
            result = result.replace(lua_pat, py_pat)
        
        return result
    
    def _table_concat(self, t, sep=""):
        """Lua table.concat implementation."""
        items = []
        if hasattr(t, 'values'):
            items = list(t.values())
        elif hasattr(t, '__iter__'):
            items = list(t)
        return sep.join(str(item) for item in items if item is not None)
    
    def _require_module(self, module_name):
        """Handle require() for NSE libraries."""
        # Return empty table for unsupported modules
        logger.debug(f"NSE require: {module_name} (stub)")
        return self.lua.table()


class NSEScriptParser:
    """Parse NSE (.nse) script files."""
    
    @staticmethod
    def parse_script_file(script_path: Path) -> Optional[NSEScriptInfo]:
        """
        Parse NSE script metadata from file.
        
        Args:
            script_path: Path to .nse file
            
        Returns:
            NSEScriptInfo or None if parsing fails
        """
        try:
            content = script_path.read_text(encoding='utf-8', errors='replace')
            return NSEScriptParser.parse_script_content(script_path.stem, content)
        except Exception as e:
            logger.error(f"Failed to parse NSE script {script_path}: {e}")
            return None
    
    @staticmethod
    def parse_script_content(name: str, content: str) -> NSEScriptInfo:
        """Parse NSE script metadata from content."""
        # Extract description
        desc_match = re.search(r'description\s*=\s*\[\[([^\]]+)\]\]', content, re.DOTALL)
        if not desc_match:
            desc_match = re.search(r'description\s*=\s*"([^"]+)"', content)
        description = desc_match.group(1).strip() if desc_match else ""
        
        # Extract author
        author_match = re.search(r'author\s*=\s*"([^"]+)"', content)
        if not author_match:
            author_match = re.search(r'author\s*=\s*\{([^}]+)\}', content)
        author = author_match.group(1).strip() if author_match else "Unknown"
        
        # Extract license
        license_match = re.search(r'license\s*=\s*"([^"]+)"', content)
        license_str = license_match.group(1) if license_match else "Same as Nmap"
        
        # Extract categories
        categories = []
        cat_match = re.search(r'categories\s*=\s*\{([^}]+)\}', content)
        if cat_match:
            cat_str = cat_match.group(1)
            cat_names = re.findall(r'"(\w+)"', cat_str)
            for cat_name in cat_names:
                try:
                    categories.append(NSECategory(cat_name.lower()))
                except ValueError:
                    pass
        
        # Extract dependencies
        dependencies = []
        dep_match = re.search(r'dependencies\s*=\s*\{([^}]+)\}', content)
        if dep_match:
            dep_str = dep_match.group(1)
            dependencies = re.findall(r'"([^"]+)"', dep_str)
        
        # Check for rule types
        portrule = "portrule" in content
        hostrule = "hostrule" in content
        prerule = "prerule" in content
        postrule = "postrule" in content
        
        return NSEScriptInfo(
            name=name,
            description=description,
            author=author,
            categories=categories if categories else [NSECategory.SAFE],
            license=license_str,
            dependencies=dependencies,
            portrule="portrule function" if portrule else None,
            hostrule="hostrule function" if hostrule else None,
            prerule="prerule function" if prerule else None,
            postrule="postrule function" if postrule else None
        )


class NSEEngine:
    """
    NSE (Nmap Scripting Engine) Compatibility Engine.
    Executes Lua-based .nse scripts.
    """
    
    def __init__(self, scripts_dir: Optional[Path] = None):
        """
        Initialize NSE engine.
        
        Args:
            scripts_dir: Directory containing .nse scripts
        """
        self.scripts_dir = scripts_dir or Path(__file__).parent.parent / "nse_scripts"
        self.scripts: Dict[str, NSEScriptInfo] = {}
        self.script_contents: Dict[str, str] = {}
        self.lua: Optional['LuaRuntime'] = None
        self.nse_lib: Optional[NSELibrary] = None
        
        if LUPA_AVAILABLE:
            self._init_lua()
        
        logger.info(f"NSEEngine initialized with scripts_dir: {self.scripts_dir}")
    
    def _init_lua(self):
        """Initialize Lua runtime."""
        try:
            self.lua = LuaRuntime(unpack_returned_tuples=True)
            self.nse_lib = NSELibrary(self.lua)
            self.nse_lib.setup_globals(self.lua)
            logger.info("Lua runtime initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Lua runtime: {e}")
            self.lua = None
    
    @property
    def lua_available(self) -> bool:
        """Check if Lua runtime is available."""
        return self.lua is not None
    
    def load_scripts(self, patterns: Optional[List[str]] = None):
        """
        Load NSE scripts from scripts directory.
        
        Args:
            patterns: Optional list of script name patterns to load
        """
        if not self.scripts_dir.exists():
            logger.warning(f"NSE scripts directory not found: {self.scripts_dir}")
            return
        
        # Find all .nse files
        script_files = list(self.scripts_dir.glob("*.nse"))
        
        for script_file in script_files:
            # Check if matches patterns
            if patterns:
                import fnmatch
                if not any(fnmatch.fnmatch(script_file.stem, p) for p in patterns):
                    continue
            
            try:
                info = NSEScriptParser.parse_script_file(script_file)
                if info:
                    info.path = script_file  # Set the path
                    self.scripts[info.name] = info
                    self.script_contents[info.name] = script_file.read_text(
                        encoding='utf-8', errors='replace'
                    )
                    logger.debug(f"Loaded NSE script: {info.name}")
            except Exception as e:
                logger.error(f"Failed to load NSE script {script_file}: {e}")
        
        logger.info(f"Loaded {len(self.scripts)} NSE scripts")
    
    def get_script(self, name: str) -> Optional[NSEScriptInfo]:
        """Get script info by name."""
        return self.scripts.get(name)
    
    def get_scripts_by_category(self, category: NSECategory) -> List[NSEScriptInfo]:
        """Get all scripts in a category."""
        return [s for s in self.scripts.values() if category in s.categories]
    
    def list_scripts(self) -> List[str]:
        """List all available script names."""
        return list(self.scripts.keys())
    
    async def run_script(
        self,
        script_name: str,
        host: NSEHostInfo,
        port: Optional[NSEPortInfo] = None,
        args: Optional[Dict[str, Any]] = None
    ) -> NSEScriptResult:
        """
        Run a single NSE script.
        
        Args:
            script_name: Name of the script
            host: Host information
            port: Port information (for portrule scripts)
            args: Script arguments
            
        Returns:
            NSEScriptResult
        """
        start_time = time.time()
        
        if not self.lua_available:
            return NSEScriptResult(
                script_name=script_name,
                host=host.ip,
                port=port.number if port else None,
                protocol=port.protocol if port else "tcp",
                success=False,
                output="",
                error="Lua runtime not available (install lupa: pip install lupa)"
            )
        
        if script_name not in self.scripts:
            return NSEScriptResult(
                script_name=script_name,
                host=host.ip,
                port=port.number if port else None,
                protocol=port.protocol if port else "tcp",
                success=False,
                output="",
                error=f"Script not found: {script_name}"
            )
        
        script_content = self.script_contents.get(script_name, "")
        
        try:
            # Create execution context
            result = await self._execute_lua_script(
                script_name, script_content, host, port, args or {}
            )
            
            execution_time = time.time() - start_time
            result.execution_time = execution_time
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Error executing NSE script {script_name}: {e}")
            return NSEScriptResult(
                script_name=script_name,
                host=host.ip,
                port=port.number if port else None,
                protocol=port.protocol if port else "tcp",
                success=False,
                output="",
                error=str(e),
                execution_time=execution_time
            )
    
    async def _execute_lua_script(
        self,
        script_name: str,
        script_content: str,
        host: NSEHostInfo,
        port: Optional[NSEPortInfo],
        args: Dict[str, Any]
    ) -> NSEScriptResult:
        """Execute Lua script content."""
        # Set up host and port tables
        g = self.lua.globals()
        
        # Create host table
        host_table = self.lua.table_from({
            'ip': host.ip,
            'name': host.hostname or host.ip,
            'os': host.os or ''
        })
        g['host'] = host_table
        
        # Create port table if available
        if port:
            port_table = self.lua.table_from({
                'number': port.number,
                'protocol': port.protocol,
                'state': port.state,
                'service': port.service or '',
                'version': port.version or '',
                'product': port.product or ''
            })
        else:
            port_table = self.lua.table()
        g['port'] = port_table
        
        # Set script args
        args_table = self.lua.table_from(args)
        g['SCRIPT_ARGS'] = args_table
        
        # Execute script
        try:
            self.lua.execute(script_content)
            
            # Call action function
            action_func = g['action']
            if action_func is not None:
                try:
                    output = action_func(host_table, port_table)
                except TypeError as te:
                    # Try calling with just host
                    output = action_func(host_table)
                
                # Format output
                if output is None:
                    return NSEScriptResult(
                        script_name=script_name,
                        host=host.ip,
                        port=port.number if port else None,
                        protocol=port.protocol if port else "tcp",
                        success=False,
                        output=""
                    )
                
                output_str = str(output) if output else ""
                
                return NSEScriptResult(
                    script_name=script_name,
                    host=host.ip,
                    port=port.number if port else None,
                    protocol=port.protocol if port else "tcp",
                    success=True,
                    output=output_str
                )
            else:
                return NSEScriptResult(
                    script_name=script_name,
                    host=host.ip,
                    port=port.number if port else None,
                    protocol=port.protocol if port else "tcp",
                    success=False,
                    output="",
                    error="No action function found in script"
                )
                
        except Exception as e:
            raise RuntimeError(f"Lua execution error: {e}")
    
    async def run_scripts(
        self,
        script_names: List[str],
        host: NSEHostInfo,
        ports: Optional[List[NSEPortInfo]] = None,
        args: Optional[Dict[str, Any]] = None
    ) -> List[NSEScriptResult]:
        """
        Run multiple scripts.
        
        Args:
            script_names: List of script names to run
            host: Host information
            ports: List of ports (optional)
            args: Script arguments
            
        Returns:
            List of results
        """
        results = []
        
        for script_name in script_names:
            script_info = self.scripts.get(script_name)
            if not script_info:
                continue
            
            # Determine if script is port-based or host-based
            if script_info.portrule and ports:
                # Run for each port
                for port in ports:
                    result = await self.run_script(script_name, host, port, args)
                    results.append(result)
            elif script_info.hostrule or not script_info.portrule:
                # Run once for host
                result = await self.run_script(script_name, host, None, args)
                results.append(result)
        
        return results
    
    def check_portrule(
        self,
        script_name: str,
        host: NSEHostInfo,
        port: NSEPortInfo
    ) -> bool:
        """
        Check if a script's portrule matches.
        
        Args:
            script_name: Name of the script
            host: Host information
            port: Port information
            
        Returns:
            True if script should run on this port
        """
        script_info = self.scripts.get(script_name)
        if not script_info or not script_info.portrule:
            return False
        
        # For now, use heuristics based on script name and port
        script_lower = script_name.lower()
        
        # HTTP scripts
        if 'http' in script_lower:
            return port.service in ['http', 'https'] or port.number in [80, 443, 8080, 8443]
        
        # SSH scripts
        if 'ssh' in script_lower:
            return port.service == 'ssh' or port.number == 22
        
        # SSL/TLS scripts
        if 'ssl' in script_lower or 'tls' in script_lower:
            return port.service in ['https', 'ssl', 'imaps', 'pop3s', 'smtps'] or port.number in [443, 465, 993, 995]
        
        # FTP scripts
        if 'ftp' in script_lower:
            return port.service == 'ftp' or port.number in [21, 20]
        
        # SMTP scripts
        if 'smtp' in script_lower:
            return port.service == 'smtp' or port.number in [25, 465, 587]
        
        # SMB scripts
        if 'smb' in script_lower:
            return port.service == 'smb' or port.number in [139, 445]
        
        # MySQL scripts
        if 'mysql' in script_lower:
            return port.service == 'mysql' or port.number == 3306
        
        # Default: run on open ports
        return port.state == 'open'


def create_nse_engine(scripts_dir: Optional[Path] = None) -> NSEEngine:
    """
    Factory function to create NSE engine.
    
    Args:
        scripts_dir: Optional path to NSE scripts directory
        
    Returns:
        Configured NSEEngine instance
    """
    engine = NSEEngine(scripts_dir)
    engine.load_scripts()
    return engine


# Convenience functions for script argument parsing
def parse_script_args(args_str: str) -> Dict[str, Any]:
    """
    Parse NSE script arguments string.
    
    Format: key1=value1,key2=value2
    
    Args:
        args_str: Argument string
        
    Returns:
        Dictionary of arguments
    """
    if not args_str:
        return {}
    
    result = {}
    parts = args_str.split(',')
    
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            result[key.strip()] = value.strip()
        else:
            result[part.strip()] = True
    
    return result


def format_nse_results(results: List[NSEScriptResult], verbose: bool = False) -> str:
    """
    Format NSE results for display.
    
    Args:
        results: List of NSE results
        verbose: Include detailed output
        
    Returns:
        Formatted string
    """
    if not results:
        return ""
    
    lines = []
    lines.append("\n" + "=" * 60)
    lines.append("NSE SCRIPT RESULTS")
    lines.append("=" * 60)
    
    # Group by host:port
    grouped: Dict[str, List[NSEScriptResult]] = {}
    for result in results:
        key = f"{result.host}:{result.port}" if result.port else result.host
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(result)
    
    for key, port_results in grouped.items():
        lines.append(f"\n{key}:")
        
        for result in port_results:
            if result.success:
                lines.append(f"  |_{result.script_name}:")
                for line in result.output.split('\n'):
                    if line.strip():
                        lines.append(f"    {line}")
                
                if verbose:
                    lines.append(f"    [Execution time: {result.execution_time:.2f}s]")
            else:
                if verbose:
                    lines.append(f"  |_{result.script_name}: FAILED")
                    if result.error:
                        lines.append(f"    Error: {result.error}")
    
    return "\n".join(lines)
