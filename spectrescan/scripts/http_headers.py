"""
http-headers.py
Display HTTP response headers

Author: BitSpectreLabs
License: MIT
"""

import asyncio
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class HttpHeaders(Script):
    """Display HTTP response headers."""
    
    name = "http-headers"
    description = "Enumerate HTTP response headers"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.DISCOVERY, ScriptCategory.SAFE, ScriptCategory.DEFAULT]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        if service and service.lower() not in ["http", "https"]:
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="Not an HTTP service"
            )
        
        try:
            port = port or 80
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # Parse headers
            lines = response_text.split('\r\n')
            headers = {}
            output_lines = []
            
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                    output_lines.append(f"{key.strip()}: {value.strip()}")
            
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=True,
                output="\n".join(output_lines),
                data={"headers": headers}
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
