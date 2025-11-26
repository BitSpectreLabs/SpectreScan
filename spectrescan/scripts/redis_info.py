"""
redis-info.py
Retrieve Redis server information

Author: BitSpectreLabs
License: MIT
"""

import asyncio
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class RedisInfo(Script):
    """Retrieve Redis server information."""
    
    name = "redis-info"
    description = "Enumerate Redis server configuration"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.DISCOVERY, ScriptCategory.SAFE, ScriptCategory.VERSION]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        if service and service.lower() != "redis":
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="Not a Redis service"
            )
        
        try:
            port = port or 6379
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            # Send INFO command
            writer.write(b"INFO\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(8192), timeout=5.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # Parse INFO response
            output_lines = []
            data = {}
            
            for line in response_text.split('\r\n'):
                if ':' in line and not line.startswith('#'):
                    key, value = line.split(':', 1)
                    data[key] = value
                    
                    # Show important fields
                    if key in ['redis_version', 'redis_mode', 'os', 'tcp_port', 'uptime_in_days']:
                        output_lines.append(f"{key}: {value}")
            
            output = "Redis Server Info:\n" + "\n".join(output_lines)
            
            # Check for security issues
            warnings = []
            if data.get('requirepass') == '':
                warnings.append("No authentication required (security risk!)")
            
            if warnings:
                output += "\n\nSecurity Warnings:\n" + "\n".join(f"  - {w}" for w in warnings)
            
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=True,
                output=output,
                data={"info": data, "warnings": warnings}
            )
        
        except Exception as e:
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="",
                error=str(e)
            )
