"""
http-methods.py
Check allowed HTTP methods

Author: BitSpectreLabs
License: MIT
"""

import asyncio
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class HttpMethods(Script):
    """Check HTTP methods allowed by server."""
    
    name = "http-methods"
    description = "Enumerate allowed HTTP methods (OPTIONS)"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.DISCOVERY, ScriptCategory.SAFE]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        try:
            port = port or 80
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            request = f"OPTIONS / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # Find Allow header
            lines = response_text.split('\r\n')
            allowed_methods = None
            
            for line in lines:
                if line.lower().startswith('allow:'):
                    allowed_methods = line.split(':', 1)[1].strip()
                    break
            
            if allowed_methods:
                methods = [m.strip() for m in allowed_methods.split(',')]
                dangerous = [m for m in methods if m in ['PUT', 'DELETE', 'TRACE', 'CONNECT']]
                
                output = f"Allowed methods: {', '.join(methods)}"
                if dangerous:
                    output += f"\nPotentially dangerous methods: {', '.join(dangerous)}"
                
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output=output,
                    data={"methods": methods, "dangerous": dangerous}
                )
            else:
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output="No Allow header found",
                    data={"methods": []}
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
